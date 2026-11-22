//! Builds libghostty-vt (static, with Zig) and vt.c, the terminal emulator of the app's tabs
//! (src/vt.rs), which also uses the Wuffs that libghostty-vt links. For a host other than Android
//! (where the crate is empty) it does nothing.
//!
//! The libghostty-vt source comes from scripts/fetch-ghostty
//! (target/ghostty/libghostty-vt-<version>, or APPINE_GHOSTTY_SRC), with the release's Zig
//! packages beside it (the same path with `-deps`), which `zig build --system` takes, so this build
//! needs no network. The Zig binary is `zig` on PATH or ZIG; the build finds the NDK through
//! ANDROID_NDK_HOME, which the Gradle task sets.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const GHOSTTY: &str = "libghostty-vt-1.0.0";

fn main() {
    println!("cargo:rerun-if-changed=src/vt.c");
    println!("cargo:rerun-if-env-changed=APPINE_GHOSTTY_SRC");
    println!("cargo:rerun-if-env-changed=ZIG");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("android") {
        return;
    }

    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    build_venus(&manifest);
    let src = env::var_os("APPINE_GHOSTTY_SRC").map_or_else(
        || manifest.join("../../target/ghostty").join(GHOSTTY),
        PathBuf::from,
    );
    assert!(
        src.join("build.zig").is_file(),
        "no libghostty-vt source at {}: run scripts/fetch-ghostty",
        src.display()
    );
    let mut deps = src.clone().into_os_string();
    deps.push("-deps");
    let deps = PathBuf::from(deps);
    assert!(
        deps.is_dir(),
        "no libghostty-vt packages at {}: run scripts/fetch-ghostty",
        deps.display()
    );
    // The release's version and its packages' hashes
    println!(
        "cargo:rerun-if-changed={}",
        src.join("LIB_VERSION").display()
    );
    println!(
        "cargo:rerun-if-changed={}",
        src.join("build.zig.zon").display()
    );

    let target = match env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("aarch64") => "aarch64-linux-android",
        other => panic!("libghostty-vt: unsupported Android architecture {other:?}"),
    };
    let prefix = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("ghostty");
    let zig = env::var_os("ZIG").unwrap_or_else(|| "zig".into());
    // --system takes the packages from the release's dependency tarball and never fetches. The
    // global cache is the source's own, beside Zig's local cache in it (.zig-cache), so the
    // builds of every profile share it: one that holds a package's archive, as the user's
    // ~/.cache/zig may, crashes Zig 0.17's build with "reached unreachable code"
    // (PACKAGING-LIBGHOSTTY.md)
    let mut cmd = Command::new(&zig);
    cmd.current_dir(&src)
        .args([
            "build",
            "-Demit-lib-vt",
            "-Dcpu=baseline",
            "-Doptimize=ReleaseFast",
        ])
        .arg(format!("-Dtarget={target}"))
        .arg("--system")
        .arg(&deps)
        .arg("--prefix")
        .arg(&prefix)
        .env("ZIG_GLOBAL_CACHE_DIR", src.join(".zig-global-cache"))
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE");
    // libghostty-vt's build.zig runs git to detect Ghostty's app version even under -Demit-lib-vt.
    // When unpacked under target/ghostty/ inside Appine's repository, git walks up to Appine's
    // .git and panics on Appine release tags (e.g. v1.1.0-3) that do not match Ghostty's vX.Y.Z.
    if let Some(ceiling) = fs::canonicalize(&src)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
    {
        cmd.env("GIT_CEILING_DIRECTORIES", ceiling);
    }
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("cannot run {}: {e}", zig.to_string_lossy()));
    assert!(
        status.success(),
        "zig build of libghostty-vt failed: {status}"
    );

    cc::Build::new()
        .file("src/vt.c")
        .include(prefix.join("include"))
        .include(wuffs(&src, &deps))
        .std("c11")
        .warnings(true)
        .extra_warnings(true)
        .compile("appine_vt");
    // After vt.c, which uses it
    println!(
        "cargo:rustc-link-search=native={}",
        prefix.join("lib").display()
    );
    println!("cargo:rustc-link-lib=static=ghostty-vt");
}

/// The directory of Wuffs's single-file C library among the release's Zig packages. libghostty-vt
/// links Wuffs for Kitty graphics, and vt.c decodes PNG images with it, so it compiles against
/// those declarations; the package is the one the source's `pkg/wuffs/build.zig.zon` names by hash.
fn wuffs(src: &Path, deps: &Path) -> PathBuf {
    let zon = src.join("pkg/wuffs/build.zig.zon");
    let text =
        fs::read_to_string(&zon).unwrap_or_else(|e| panic!("cannot read {}: {e}", zon.display()));
    let hash = text
        .split_once(".wuffs = .{")
        .and_then(|(_, dependency)| dependency.split_once(".hash = \""))
        .and_then(|(_, rest)| rest.split_once('"'))
        .map(|(hash, _)| hash)
        .unwrap_or_else(|| panic!("no Wuffs package hash in {}", zon.display()));
    let dir = deps.join(hash).join("release/c");
    assert!(
        dir.join("wuffs-v0.4.c").is_file(),
        "no Wuffs at {}: run scripts/fetch-ghostty",
        dir.display()
    );
    dir
}

fn build_venus(manifest: &Path) {
    let ndk = PathBuf::from(env::var_os("ANDROID_NDK_HOME").expect("Android NDK directory"));
    let bin = ndk.join("../../cmake/3.22.1/bin");
    let build = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("venus");
    let cmake = bin.join("cmake");
    let status = Command::new(&cmake)
        .arg("-S")
        .arg(manifest.join("gpu"))
        .arg("-B")
        .arg(&build)
        .args([
            "-G",
            "Ninja",
            "-DANDROID_ABI=arm64-v8a",
            "-DANDROID_PLATFORM=30",
            "-DCMAKE_BUILD_TYPE=Release",
        ])
        .arg(format!(
            "-DCMAKE_TOOLCHAIN_FILE={}",
            ndk.join("build/cmake/android.toolchain.cmake").display()
        ))
        .arg(format!(
            "-DCMAKE_MAKE_PROGRAM={}",
            bin.join("ninja").display()
        ))
        .status()
        .expect("install the Android SDK cmake;3.22.1 package");
    assert!(status.success(), "configuring the Venus decoder failed");
    assert!(
        Command::new(cmake)
            .arg("--build")
            .arg(&build)
            .arg("--parallel")
            .arg(env::var("NUM_JOBS").unwrap_or_else(|_| "4".into()))
            .status()
            .unwrap()
            .success(),
        "building the Venus decoder failed"
    );
    println!("cargo:rerun-if-changed=gpu");
    println!("cargo:rustc-link-search=native={}", build.display());
    for lib in ["static=appine_venus", "vulkan", "android", "log", "dl", "m"] {
        println!("cargo:rustc-link-lib={lib}");
    }
}
