#!/usr/bin/env python3
"""Verify a signed Appine release APK and save structural evidence; never install it."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "appine"
OUTPUT = ROOT / "target/apk-verification"
SDK = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
BUILD_TOOLS = Path(SDK) / "build-tools/36.0.0" if SDK else None
NDK = os.environ.get("ANDROID_NDK_HOME") or os.environ.get("ANDROID_NDK_ROOT")
AAPT2 = os.environ.get("AAPT2") or str(BUILD_TOOLS / "aapt2" if BUILD_TOOLS else "aapt2")
READELF = os.environ.get("LLVM_READELF") or str(
    Path(NDK) / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf" if NDK else "llvm-readelf"
)
PAGE_SIZE = 16384
PUBLIC_LIBRARIES = {"libc.so", "libdl.so", "libm.so", "liblog.so", "libandroid.so", "libjnigraphics.so", "libz.so"}
NATIVE_CLASS = "Lio/github/mthli/appine/Native;"
SHARED_START_DESCRIPTOR = "(Ljava/lang/String;ILjava/lang/String;)J"
EXPECTED_SIGNER_SHA256 = "223f2f0b741fe49c53d0ff392f860d4430f6f23484e4e3014212abfc4f21faf7"


def require(condition, description):
    if not condition:
        raise ValueError(description)


def command(args, output_name):
    completed = subprocess.run(args, capture_output=True, text=True)
    combined = completed.stdout + completed.stderr
    (OUTPUT / output_name).write_text(combined)
    require(completed.returncode == 0, f"Command failed: {args[0]} (see {output_name})")
    return combined


def apksigner_command():
    jar = os.environ.get("APKSIGNER_JAR")
    if jar:
        return ["java", "-jar", jar]
    executable = os.environ.get("APKSIGNER") or str(BUILD_TOOLS / "apksigner" if BUILD_TOOLS else "apksigner")
    return [executable]


def verify_signature(signature):
    # Build-tools versions label certificate lines either "Signer #1" or "V2 Signer:".
    signer_label = r"(?:Signer #\d+:?|V[\d.]+ Signer:)"
    names = re.findall(rf"^{signer_label}\s+certificate DN:\s*(.+)$", signature, re.M)
    digests = re.findall(rf"^{signer_label}\s+certificate SHA-256 digest:\s*([0-9a-fA-F]{{64}})\s*$", signature, re.M)
    require(names and all("CN=Appine" in name for name in names), "Expected Appine release signer")
    require({digest.lower() for digest in digests} == {EXPECTED_SIGNER_SHA256}, "Appine signing certificate SHA-256 mismatch")
    schemes = re.findall(r"^Verified using (v[\d.]+).*: true$", signature, re.M)
    require(any(scheme.startswith(("v2", "v3", "v4")) for scheme in schemes), "Expected modern APK signature verification")
    require(re.search(r"^Number of signers: 1\s*$", signature, re.M) is not None, "Expected one APK signer")
    return {"dn": names[0], "sha256": EXPECTED_SIGNER_SHA256, "verified_schemes": schemes}


def elf_headers(data):
    require(data[:6] == b"\x7fELF\x02\x01", "Expected ELF64 little endian")
    fields = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, _, _, phoff, _, _, _, phsize, phcount, *_ = fields
    require(machine == 183, f"Expected AArch64 ELF, found e_machine={machine}")
    require(phsize >= 56, "Unexpected ELF program header size")
    require(phoff + phsize * phcount <= len(data), "ELF program headers exceed file")
    headers = [struct.unpack_from("<IIQQQQQQ", data, phoff + phsize * i) for i in range(phcount)]
    return kind, headers


def read_uleb(data, offset):
    value = 0
    for shift in range(0, 35, 7):
        require(offset < len(data), "DEX ULEB128 exceeds file")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7f) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("DEX ULEB128 is too long")


def dex_start_methods(data):
    require(len(data) >= 112 and data[:4] == b"dex\n" and data[7] == 0, "Expected standard DEX file")
    require(data[4:7] in (b"035", b"037", b"038", b"039", b"040"), "Unsupported DEX version")
    require(struct.unpack_from("<I", data, 40)[0] == 0x12345678, "Expected little-endian DEX")
    string_count, strings_off, type_count, types_off, proto_count, protos_off = struct.unpack_from("<6I", data, 56)
    method_count, methods_off, class_count, classes_off = struct.unpack_from("<4I", data, 88)
    for count, offset, width in ((string_count, strings_off, 4), (type_count, types_off, 4),
                                 (proto_count, protos_off, 12), (method_count, methods_off, 8),
                                 (class_count, classes_off, 32)):
        require(offset + count * width <= len(data), "DEX table exceeds file")

    def string(index):
        require(index < string_count, "Invalid DEX string index")
        offset = struct.unpack_from("<I", data, strings_off + index * 4)[0]
        _, offset = read_uleb(data, offset)
        end = data.find(b"\0", offset)
        require(end >= offset, "Unterminated DEX string")
        return data[offset:end].decode("utf-8", errors="replace")

    def type_name(index):
        require(index < type_count, "Invalid DEX type index")
        return string(struct.unpack_from("<I", data, types_off + index * 4)[0])

    def descriptor(index):
        require(index < proto_count, "Invalid DEX prototype index")
        _, return_type, parameters_off = struct.unpack_from("<III", data, protos_off + index * 12)
        parameters = []
        if parameters_off:
            count = struct.unpack_from("<I", data, parameters_off)[0]
            require(parameters_off + 4 + count * 2 <= len(data), "DEX parameter list exceeds file")
            parameters = [type_name(struct.unpack_from("<H", data, parameters_off + 4 + i * 2)[0]) for i in range(count)]
        return "(" + "".join(parameters) + ")" + type_name(return_type)

    result = []
    for i in range(class_count):
        definition = struct.unpack_from("<8I", data, classes_off + i * 32)
        if type_name(definition[0]) != NATIVE_CLASS or not definition[6]:
            continue
        offset = definition[6]
        counts = []
        for _ in range(4):
            count, offset = read_uleb(data, offset)
            counts.append(count)
        for _ in range(counts[0] + counts[1]):
            _, offset = read_uleb(data, offset)
            _, offset = read_uleb(data, offset)
        for count in counts[2:]:
            method_index = 0
            for _ in range(count):
                delta, offset = read_uleb(data, offset)
                flags, offset = read_uleb(data, offset)
                code_off, offset = read_uleb(data, offset)
                method_index += delta
                require(method_index < method_count, "Invalid DEX method index")
                class_index, proto_index, name_index = struct.unpack_from("<HHI", data, methods_off + method_index * 8)
                require(class_index == definition[0], "DEX class-data method belongs to another class")
                if string(name_index) == "start":
                    result.append({"descriptor": descriptor(proto_index), "access_flags": flags, "code_offset": code_off})
    return result


def verify_native(path):
    data = path.read_bytes()
    kind, headers = elf_headers(data)
    require(kind == 3, "Native library must be an ELF shared object")
    loads = []
    for header in headers:
        ptype, flags, offset, vaddr, _, filesz, memsz, alignment = header
        if ptype != 1:
            continue
        require(alignment >= PAGE_SIZE, f"PT_LOAD alignment {alignment} is below 16 KB")
        require(alignment & (alignment - 1) == 0, "PT_LOAD alignment must be a power of two")
        require(offset % alignment == vaddr % alignment, "PT_LOAD offset/address alignment mismatch")
        require(filesz <= memsz and offset + filesz <= len(data), "Invalid PT_LOAD file extent")
        loads.append({"offset": offset, "virtual_address": vaddr, "alignment": alignment, "flags": flags})
    require(loads, "Native library has no PT_LOAD segments")
    dynamic = command([READELF, "--dynamic", str(path)], "native-dynamic.txt")
    dependencies = re.findall(r"\(NEEDED\).*?\[([^\]]+)\]", dynamic)
    require(set(dependencies) <= PUBLIC_LIBRARIES, f"Unexpected native dependencies: {dependencies}")
    require(not re.search(r"\((?:RUNPATH|RPATH)\)", dynamic), "Native library contains RUNPATH/RPATH")
    require("com.termux" not in dynamic, "Native dynamic section references Termux")
    symbols = command([READELF, "--dyn-syms", "--wide", str(path)], "native-symbols.txt")
    exported = {}
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[0].endswith(":") and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and fields[6] != "UND":
            exported[fields[7]] = fields[6]
    required_symbols = set()
    for class_name in ("Native", "VtNative"):
        kotlin = (SOURCE / f"android/app/src/main/java/io/github/mthli/appine/{class_name}.kt").read_text()
        methods = re.findall(r"\bexternal\s+fun\s+(\w+)\s*\(", kotlin)
        require(methods, f"No JNI declarations found in {class_name}.kt")
        if class_name == "Native":
            require("start" in methods, "Shared-storage Native.start declaration missing from source")
        required_symbols.update(f"Java_io_github_mthli_appine_{class_name}_{name}" for name in methods)
    required_symbols = sorted(required_symbols)
    missing = sorted(set(required_symbols) - exported.keys())
    require(not missing, f"Native JNI exports missing or hidden: {missing}")
    return {"path": str(path), "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
            "load_segments": loads, "needed": dependencies, "runpath": None, "jni_exports_checked": required_symbols}


def verify_apk(path):
    badging = command([AAPT2, "dump", "badging", str(path)], "badging.txt")
    manifest = command([AAPT2, "dump", "xmltree", str(path), "--file", "AndroidManifest.xml"], "manifest.txt")
    package = re.search(r"^package: name='([^']+)' versionCode='([^']+)' versionName='([^']+)'", badging, re.M)
    require(package is not None, "Package metadata missing")
    require(package.groups() == ("io.github.mthli.appine", "2", "1.0.1"), f"Unexpected package metadata: {package.groups()}")
    require(re.search(r"^(?:minSdkVersion|sdkVersion):'30'$", badging, re.M) is not None, "Expected minSdk 30")
    require("targetSdkVersion:'37'" in badging, "Expected targetSdk 37")
    require("application-debuggable" not in badging, "Release APK must not be debuggable")
    permission = "android.permission.MANAGE_EXTERNAL_STORAGE"
    require(f"uses-permission: name='{permission}'" in badging, "All-files permission missing")
    require(permission in manifest, "All-files permission missing from binary manifest")
    signature = command([*apksigner_command(), "verify", "--verbose", "--print-certs", str(path)], "signature.txt")
    signer = verify_signature(signature)

    with zipfile.ZipFile(path) as archive, path.open("rb") as raw:
        require(archive.testzip() is None, "APK entry CRC verification failed")
        entries = archive.namelist()
        require(len(entries) == len(set(entries)), "APK contains duplicate entry names")
        source_assets = SOURCE / "android/app/src/main/assets"
        require(source_assets.is_dir(), "Appine source assets directory missing")
        checked_assets = []
        for asset in sorted(source_assets.rglob("*")):
            if not asset.is_file():
                continue
            name = "assets/" + asset.relative_to(source_assets).as_posix()
            require(name in entries, f"Source asset missing from APK: {name}")
            require(archive.read(name) == asset.read_bytes(), f"APK asset differs from source: {name}")
            checked_assets.append(name)
        dex_methods = []
        for name in entries:
            if re.fullmatch(r"classes(?:\d+)?\.dex", name):
                dex_methods.extend(dex_start_methods(archive.read(name)))
        shared_start = [method for method in dex_methods if method["descriptor"] == SHARED_START_DESCRIPTOR]
        require(len(shared_start) == 1, "Expected one shared-storage Native.start DEX method")
        require(shared_start[0]["access_flags"] & 0x108 == 0x108 and shared_start[0]["code_offset"] == 0,
                "Shared-storage Native.start must be static and native in DEX")
        required = ["assets/rootfs.tgz", "assets/appine-open-url", "assets/doas.apk", "lib/arm64-v8a/libappine.so"]
        for name in required:
            require(name in entries and archive.getinfo(name).file_size > 0, f"Missing or empty APK entry: {name}")
        package_counts = {}
        for prefix, expected in (("bash", 4), ("procps", 7), ("bubblewrap", 2), ("openrc", 4)):
            count = sum(name.startswith(f"assets/{prefix}/") and name.endswith(".apk") for name in entries)
            require(count == expected, f"Expected {expected} bundled {prefix} packages, found {count}")
            package_counts[prefix] = count
        require(archive.read("assets/rootfs.tgz")[:2] == b"\x1f\x8b", "Bundled rootfs is not gzip")
        browser = OUTPUT / "appine-open-url"
        browser.write_bytes(archive.read("assets/appine-open-url"))
        browser_kind, browser_headers = elf_headers(browser.read_bytes())
        require(browser_kind == 2, "Browser launcher must be an executable ELF")
        require(not any(header[0] == 3 for header in browser_headers), "Browser launcher has a dynamic interpreter")
        browser_dynamic = command([READELF, "--dynamic", str(browser)], "browser-dynamic.txt")
        require("(NEEDED)" not in browser_dynamic, "Browser launcher is not static")
        native_entries = []
        for info in archive.infolist():
            if not info.filename.startswith("lib/") or not info.filename.endswith(".so"):
                continue
            require(info.filename == "lib/arm64-v8a/libappine.so", f"Unexpected native entry: {info.filename}")
            require(info.compress_type == zipfile.ZIP_STORED, f"Native entry is compressed: {info.filename}")
            raw.seek(info.header_offset)
            local = raw.read(30)
            require(len(local) == 30 and local[:4] == b"PK\x03\x04", "Invalid ZIP local file header")
            name_len, extra_len = struct.unpack_from("<HH", local, 26)
            data_offset = info.header_offset + 30 + name_len + extra_len
            require(data_offset % PAGE_SIZE == 0, f"Native ZIP data offset is not 16 KB aligned: {data_offset}")
            native_entries.append({"entry": info.filename, "size": info.file_size, "compression": "stored", "data_offset": data_offset})
        native = OUTPUT / "libappine.so"
        native.write_bytes(archive.read("lib/arm64-v8a/libappine.so"))
        native_result = verify_native(native)

    return {"apk": str(path), "size": path.stat().st_size, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "package": package[1], "version_code": package[2], "version_name": package[3], "min_sdk": 30,
            "target_sdk": 37, "debuggable": False, "all_files_permission": True,
            "signer": signer["dn"], "signer_sha256": signer["sha256"], "verified_signature_schemes": signer["verified_schemes"],
            "native_zip_entries": native_entries, "native": native_result, "bundled_packages": package_counts,
            "source_assets_checked": checked_assets,
            "shared_storage_jni_descriptor": SHARED_START_DESCRIPTOR,
            "browser_static": True, "rootfs_present": True,
            "limitations": ["Structural checks do not verify installation or execution on a 16 KB-page device.",
                            "No APK was installed; Android all-files Settings grant was not exercised."]}


def main():
    global SOURCE, OUTPUT
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--source-root", type=Path, default=SOURCE)
    parser.add_argument("--output-dir", type=Path, default=OUTPUT)
    parser.add_argument("--expected-source-sha", default=os.environ.get("APPINE_SOURCE_SHA"))
    args = parser.parse_args()
    SOURCE = args.source_root.resolve()
    OUTPUT = args.output_dir.resolve()
    OUTPUT.mkdir(parents=True, exist_ok=True)
    try:
        artifact = args.artifact.resolve(strict=True)
        source_sha = command(["git", "-C", str(SOURCE), "rev-parse", "HEAD"], "source-sha.txt").strip()
        require(re.fullmatch(r"[0-9a-f]{40}", source_sha) is not None, "Expected full Appine source SHA")
        if args.expected_source_sha:
            require(source_sha == args.expected_source_sha, "Appine checkout does not match expected source SHA")
        source_status = command(["git", "-C", str(SOURCE), "status", "--porcelain", "--untracked-files=no"], "source-status.txt")
        require(not source_status.strip(), "Appine checkout has tracked modifications")
        result = verify_apk(artifact)
        result["source_sha"] = source_sha
        result["source_root"] = str(SOURCE)
    except (ValueError, OSError, struct.error, zipfile.BadZipFile) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        (OUTPUT / "failure.txt").write_text(str(error) + "\n")
        return 1
    (OUTPUT / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
