//! A live host directory at Android's shared-storage paths, exercised by Alpine BusyBox.

#![cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]

use appine_kernel::{ExitStatus, Machine, MachineOptions, Stdio, Tier};
use std::fs;
use std::os::unix::fs::{FileExt, symlink};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const TIMEOUT: Duration = Duration::from_secs(30);
const STRESS_TIMEOUT: Duration = Duration::from_secs(60);

#[test]
fn both_shared_storage_paths_read_and_write_the_host_directory() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("read-write") else {
            return;
        };
        fs::create_dir_all(root.shared.join("目录 空间")).unwrap();
        fs::write(root.shared.join("目录 空间/来自手机.txt"), b"host data\n").unwrap();
        let binary: Vec<u8> = (0..131_073).map(|n| n as u8).collect();
        fs::write(root.shared.join("payload.bin"), &binary).unwrap();
        fs::write(root.shared.join("empty.txt"), b"").unwrap();
        fs::write(root.shared.join("truncate.txt"), b"a longer old value").unwrap();
        install_inode_checker(&root);
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();

        assert_eq!(
            run(
                &machine,
                tier,
                r#"
cd /sdcard
[ "$(pwd)" = /sdcard ]
[ "$(cat '目录 空间/来自手机.txt')" = 'host data' ]
[ ! -s empty.txt ]
printf 'guest data\n' > '目录 空间/由终端.txt'
cd /storage/emulated/0
[ "$(pwd)" = /storage/emulated/0 ]
[ "$(cat '目录 空间/由终端.txt')" = 'guest data' ]
printf 'append\n' >> '目录 空间/由终端.txt'
cp payload.bin 'binary copy.bin'
cmp /sdcard/payload.bin '/storage/emulated/0/binary copy.bin'
: > 'empty from guest'
printf x > /sdcard/truncate.txt
mkdir 'created dir'
printf 'renamed\n' > 'created dir/original.txt'
mv 'created dir/original.txt' 'created dir/renamed.txt'
[ "$(cat '/sdcard/created dir/renamed.txt')" = renamed ]
rm '/sdcard/created dir/renamed.txt'
rmdir '/sdcard/created dir'
ls -1 /sdcard | grep -F 'binary copy.bin' >/dev/null
/tmp/check-storage-inodes
su -s /bin/sh nobody -c '
    set -eu
    [ "$(id -u)" = 65534 ]
    cd /sdcard
    [ "$(cat "目录 空间/来自手机.txt")" = "host data" ]
    printf "ordinary user\n" > "ordinary user.txt"
    cd /storage/emulated/0
    [ "$(cat "ordinary user.txt")" = "ordinary user" ]
    printf "second path\n" > "ordinary canonical.txt"
    /tmp/check-storage-inodes
'
printf 'ok\n'
"#,
            ),
            "ok\n",
            "{tier:?}"
        );
        assert_eq!(
            fs::read(root.shared.join("目录 空间/由终端.txt")).unwrap(),
            b"guest data\nappend\n",
            "{tier:?}"
        );
        assert_eq!(
            fs::read(root.shared.join("binary copy.bin")).unwrap(),
            binary,
            "{tier:?}"
        );
        assert_eq!(fs::read(root.shared.join("empty from guest")).unwrap(), b"");
        assert_eq!(fs::read(root.shared.join("truncate.txt")).unwrap(), b"x");
        assert_eq!(
            fs::read(root.shared.join("ordinary user.txt")).unwrap(),
            b"ordinary user\n",
            "{tier:?}"
        );
        assert_eq!(
            fs::read(root.shared.join("ordinary canonical.txt")).unwrap(),
            b"second path\n",
            "{tier:?}"
        );
        assert!(!root.shared.join("created dir").exists(), "{tier:?}");
    }
}

#[test]
fn shared_storage_refreshes_names_and_attributes_after_host_changes() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("host-changes") else {
            return;
        };
        fs::create_dir_all(root.shared.join("old dir")).unwrap();
        fs::write(root.shared.join("changing.txt"), b"first").unwrap();
        fs::write(root.shared.join("removed.txt"), b"old").unwrap();
        fs::write(root.shared.join("old dir/child.txt"), b"child").unwrap();
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();
        assert_eq!(
            run(
                &machine,
                tier,
                r#"
cd /sdcard
[ "$(cat changing.txt)" = first ]
[ "$(stat -c %s changing.txt)" = 5 ]
[ -f removed.txt ]
[ "$(cat 'old dir/child.txt')" = child ]
[ ! -e future.txt ]
[ ! -d 'future dir' ]
printf 'before\n'
"#,
            ),
            "before\n",
            "{tier:?}"
        );

        fs::write(root.shared.join("changing.txt"), b"other").unwrap();
        assert_eq!(
            run(&machine, tier, "cat /storage/emulated/0/changing.txt"),
            "other",
            "{tier:?}"
        );
        fs::write(root.shared.join("changing.txt"), b"a longer replacement\n").unwrap();
        fs::remove_file(root.shared.join("removed.txt")).unwrap();
        fs::write(root.shared.join("future.txt"), b"new").unwrap();
        fs::create_dir(root.shared.join("future dir")).unwrap();
        fs::rename(root.shared.join("old dir"), root.shared.join("renamed dir")).unwrap();
        assert_eq!(
            run(
                &machine,
                tier,
                r#"
cd /storage/emulated/0
[ "$(cat changing.txt)" = 'a longer replacement' ]
[ "$(stat -c %s changing.txt)" = 21 ]
[ ! -e removed.txt ]
[ "$(cat future.txt)" = new ]
[ -d 'future dir' ]
[ ! -e 'old dir' ]
[ "$(cat 'renamed dir/child.txt')" = child ]
printf 'after\n'
"#,
            ),
            "after\n",
            "{tier:?}"
        );
    }
}

#[test]
fn shared_storage_resolves_deep_paths_from_concurrent_guest_workers() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("concurrent-paths") else {
            return;
        };
        let directory = root.shared.join("a/b/c/d/e/f/g/h");
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("data.txt"), b"content\n").unwrap();
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();
        let started = Instant::now();
        assert_eq!(
            Guest::spawn(
                &machine,
                tier,
                r#"
pids=
for prefix in /sdcard /storage/emulated/0 /sdcard /storage/emulated/0; do
    (
        set -eu
        file="$prefix/a/b/c/d/e/f/g/h/data.txt"
        i=0
        while [ "$i" -lt 128 ]; do
            [ "$(stat -c %s "$file")" = 8 ]
            [ "$(cat "$file")" = content ]
            i=$((i + 1))
        done
    ) &
    pids="$pids $!"
done
for pid in $pids; do wait "$pid"; done
printf 'concurrent ok\n'
"#,
            )
            .with_timeout(STRESS_TIMEOUT)
            .finish(),
            "concurrent ok\n",
            "{tier:?}"
        );
        eprintln!(
            "Concurrent shared storage paths ({tier:?}): {:.3} s",
            started.elapsed().as_secs_f64()
        );
    }
}

#[test]
fn shared_storage_open_files_survive_host_rename_and_unlink() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("open-files") else {
            return;
        };
        fs::create_dir(&root.shared).unwrap();
        fs::write(root.shared.join("held.txt"), b"held contents\n").unwrap();
        fs::write(root.shared.join("write-held.txt"), b"old").unwrap();
        let writer = fs::File::open(root.shared.join("write-held.txt")).unwrap();
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();
        let mut guest = Guest::spawn(
            &machine,
            tier,
            r#"
stty -echo
cd /sdcard
exec 3<held.txt
exec 4>write-held.txt
printf 'ready\n'
read go
[ ! -e held.txt ]
[ ! -e moved.txt ]
[ ! -e write-held.txt ]
cat <&3
printf 'through the open file\n' >&4
exec 4>&-
printf 'done\n'
"#,
        );
        guest.expect("ready\n");
        fs::rename(root.shared.join("held.txt"), root.shared.join("moved.txt")).unwrap();
        fs::remove_file(root.shared.join("moved.txt")).unwrap();
        fs::remove_file(root.shared.join("write-held.txt")).unwrap();
        guest.send(b"go\n");
        assert_eq!(guest.finish(), "ready\nheld contents\ndone\n", "{tier:?}");
        let mut written = [0; 64];
        let n = writer.read_at(&mut written, 0).unwrap();
        assert_eq!(&written[..n], b"through the open file\n", "{tier:?}");
    }
}

#[test]
fn shared_storage_symlinks_resolve_in_the_guest_namespace() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("symlinks") else {
            return;
        };
        fs::create_dir(&root.shared).unwrap();
        fs::write(
            root.top.join("host-secret"),
            b"outside the shared directory",
        )
        .unwrap();
        symlink("../host-secret", root.shared.join("relative escape")).unwrap();
        symlink(
            root.top.join("host-secret"),
            root.shared.join("absolute escape"),
        )
        .unwrap();
        symlink("..", root.shared.join("directory escape")).unwrap();
        symlink("/etc/os-release", root.shared.join("guest file")).unwrap();
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();
        assert_eq!(
            run(
                &machine,
                tier,
                r#"
for shared in /sdcard /storage/emulated/0; do
    if cat "$shared/relative escape" >/dev/null 2>&1; then exit 1; fi
    if cat "$shared/absolute escape" >/dev/null 2>&1; then exit 1; fi
    if cat "$shared/directory escape/host-secret" >/dev/null 2>&1; then exit 1; fi
    cmp "$shared/guest file" /etc/os-release
done
cd /sdcard/..
[ "$(pwd)" = / ]
printf 'confined\n'
"#,
            ),
            "confined\n",
            "{tier:?}"
        );
    }
}

#[test]
fn shared_storage_can_appear_later_and_preserves_an_existing_sdcard_directory() {
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let Some(root) = TestRoot::new("late-root") else {
            return;
        };
        appine_kernel::write_file(
            &root.store,
            "/sdcard/local.txt",
            b"preserved",
            0o644,
            false,
            0,
            0,
        )
        .unwrap();
        let machine = root.start(tier);
        machine.mount_shared_storage(&root.shared).unwrap();
        assert_eq!(
            run(
                &machine,
                tier,
                r#"
if ls /sdcard >/dev/null 2>&1; then exit 1; fi
if ls /storage/emulated/0 >/dev/null 2>&1; then exit 1; fi
printf 'unavailable\n'
"#,
            ),
            "unavailable\n",
            "{tier:?}"
        );
        fs::create_dir(&root.shared).unwrap();
        fs::write(root.shared.join("later.txt"), b"later\n").unwrap();
        assert_eq!(
            run(
                &machine,
                tier,
                r#"
cd /sdcard
cat later.txt
cd /storage/emulated/0
printf 'available\n' > written.txt
[ ! -e /sdcard/local.txt ]
"#,
            ),
            "later\n",
            "{tier:?}"
        );
        assert_eq!(
            fs::read(root.shared.join("written.txt")).unwrap(),
            b"available\n"
        );
        assert_eq!(
            appine_kernel::read_file(&root.store, "/sdcard/local.txt").unwrap(),
            b"preserved",
            "{tier:?}"
        );
        drop(machine);
        let machine = root.start(tier);
        assert_eq!(
            run(&machine, tier, "cat /sdcard/local.txt"),
            "preserved",
            "{tier:?}"
        );
    }
}

struct TestRoot {
    top: PathBuf,
    store: PathBuf,
    shared: PathBuf,
}

impl TestRoot {
    fn new(name: &str) -> Option<TestRoot> {
        let tarball = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/rootfs/alpine-minirootfs-3.24.3-aarch64.tar.gz");
        if !tarball.is_file() {
            assert!(
                std::env::var_os("APPINE_REQUIRE_ROOTFS").is_none_or(|v| v != "1"),
                "the pinned Alpine 3.24.3 rootfs is missing; run scripts/fetch-rootfs"
            );
            eprintln!("skipping shared-storage tests: the pinned Alpine 3.24.3 rootfs is missing");
            return None;
        }
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let top = std::env::temp_dir().join(format!(
            "appine-shared-storage-{name}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&top).unwrap();
        let root = TestRoot {
            store: top.join("store"),
            shared: top.join("shared"),
            top,
        };
        appine_kernel::import_rootfs(&root.store, &tarball).unwrap();
        Some(root)
    }

    fn start(&self, tier: Tier) -> Arc<Machine> {
        Arc::new(
            Machine::start(&MachineOptions {
                rootfs: Some(self.store.clone()),
                tier,
                ..MachineOptions::default()
            })
            .unwrap(),
        )
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.top);
    }
}

fn run(machine: &Arc<Machine>, tier: Tier, script: &str) -> String {
    Guest::spawn(machine, tier, script).finish()
}

/// Reads directory inodes directly, so an ls implementation that stats entries cannot hide a
/// mismatch between getdents64 and newfstatat.
fn install_inode_checker(root: &TestRoot) {
    let source = root.top.join("check-storage-inodes.c");
    let binary = root.top.join("check-storage-inodes");
    fs::write(
        &source,
        r#"
#include <fcntl.h>
#include <sys/syscall.h>

static long call4(long number, long a, long b, long c, long d) {
    register long x0 __asm__("x0") = a;
    register long x1 __asm__("x1") = b;
    register long x2 __asm__("x2") = c;
    register long x3 __asm__("x3") = d;
    register long x8 __asm__("x8") = number;
    __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3), "r"(x8) : "memory", "cc");
    return x0;
}

static int equal(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}

static unsigned long integer(const unsigned char *bytes, unsigned count) {
    unsigned long value = 0;
    for (unsigned i = 0; i < count; ++i) value |= (unsigned long)bytes[i] << (i * 8);
    return value;
}

static int check(const char *path) {
    const char *names[] = { "payload.bin", "empty.txt", "binary copy.bin" };
    long fd = call4(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0);
    if (fd < 0) return 10;
    unsigned seen = 0;
    unsigned char entries[4096];
    for (;;) {
        long count = call4(SYS_getdents64, fd, (long)entries, sizeof entries, 0);
        if (count < 0) return 11;
        if (count == 0) break;
        unsigned long offset = 0;
        while (offset < (unsigned long)count) {
            if ((unsigned long)count - offset < 20) return 12;
            unsigned long length = integer(entries + offset + 16, 2);
            if (length < 20 || length > (unsigned long)count - offset) return 12;
            unsigned long end = 19;
            while (end < length && entries[offset + end]) ++end;
            if (end == length) return 12;
            for (unsigned i = 0; i < 3; ++i) {
                if (!equal((const char *)entries + offset + 19, names[i])) continue;
                unsigned char stat[128];
                if (call4(SYS_newfstatat, fd, (long)names[i], (long)stat, 0) < 0) return 13;
                if (integer(entries + offset, 8) != integer(stat + 8, 8)) return 14;
                seen |= 1u << i;
            }
            offset += length;
        }
    }
    call4(SYS_close, fd, 0, 0, 0);
    return seen == 7 ? 0 : 15;
}

__attribute__((noreturn)) void _start(void) {
    int status = check("/sdcard");
    if (!status) status = check("/storage/emulated/0");
    if (status) {
        static const char message[] = "Shared storage directory/stat inode check failed.\n";
        call4(SYS_write, 2, (long)message, sizeof message - 1, 0);
    }
    call4(SYS_exit_group, status, 0, 0, 0);
    for (;;) {}
}
"#,
    )
    .unwrap();
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    let output = std::process::Command::new(compiler)
        .args([
            "-D_GNU_SOURCE",
            "-nostdlib",
            "-static",
            "-fno-builtin",
            "-fno-stack-protector",
            "-O2",
            "-Wall",
            "-Wextra",
            "-Werror",
        ])
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "could not build the shared storage inode checker: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    appine_kernel::write_file(
        &root.store,
        "/tmp/check-storage-inodes",
        &fs::read(binary).unwrap(),
        0o755,
        false,
        0,
        0,
    )
    .unwrap();
}

struct Guest {
    machine: Arc<Machine>,
    console: u32,
    pid: u32,
    tier: Tier,
    deadline: Instant,
    output: String,
    events: mpsc::Receiver<Result<Vec<u8>, appine_kernel::errno::Errno>>,
    reader: Option<JoinHandle<()>>,
    ended: bool,
}

impl Guest {
    fn spawn(machine: &Arc<Machine>, tier: Tier, script: &str) -> Guest {
        let console = machine.open_console(24, 200).unwrap();
        let script = format!("set -eu\n{script}");
        let argv = [b"sh".to_vec(), b"-c".to_vec(), script.into_bytes()];
        let env = [b"PATH=/usr/sbin:/usr/bin:/sbin:/bin".to_vec()];
        let pid = machine
            .spawn(b"/bin/sh", &argv, &env, Stdio::Console(console))
            .unwrap();
        let (sender, events) = mpsc::channel();
        let machine_read = Arc::clone(machine);
        let reader = thread::spawn(move || {
            let mut buf = [0; 4096];
            loop {
                let out = machine_read
                    .read_console(console, &mut buf)
                    .map(|n| buf[..n].to_vec());
                let ended = !matches!(&out, Ok(chunk) if !chunk.is_empty());
                if sender.send(out).is_err() || ended {
                    break;
                }
            }
        });
        Guest {
            machine: Arc::clone(machine),
            console,
            pid,
            tier,
            deadline: Instant::now() + TIMEOUT,
            output: String::new(),
            events,
            reader: Some(reader),
            ended: false,
        }
    }

    fn with_timeout(mut self, timeout: Duration) -> Guest {
        self.deadline = Instant::now() + timeout;
        self
    }

    fn receive(&mut self) {
        let chunk = self
            .events
            .recv_timeout(self.deadline.saturating_duration_since(Instant::now()))
            .unwrap_or_else(|e| {
                panic!(
                    "{:?}: guest output timed out: {e}: {}",
                    self.tier, self.output
                )
            })
            .unwrap_or_else(|e| {
                panic!("{:?}: console read failed: {e}: {}", self.tier, self.output)
            });
        self.ended = chunk.is_empty();
        self.output
            .push_str(&String::from_utf8_lossy(&chunk).replace('\r', ""));
    }

    fn expect(&mut self, text: &str) {
        while !self.output.contains(text) && !self.ended {
            self.receive();
        }
        assert!(
            self.output.contains(text),
            "{:?}: missing {text:?}: {}",
            self.tier,
            self.output
        );
    }

    fn send(&self, bytes: &[u8]) {
        assert_eq!(
            self.machine.write_console(self.console, bytes).unwrap(),
            bytes.len()
        );
    }

    fn finish(mut self) -> String {
        while !self.ended {
            self.receive();
        }
        let status = loop {
            if let Some(status) = self.machine.try_wait(self.pid) {
                break status;
            }
            assert!(
                Instant::now() < self.deadline,
                "{:?}: guest exit timed out",
                self.tier
            );
            thread::sleep(Duration::from_millis(10));
        };
        assert_eq!(
            status,
            ExitStatus::Exited(0),
            "{:?}: {}",
            self.tier,
            self.output
        );
        std::mem::take(&mut self.output)
    }
}

impl Drop for Guest {
    fn drop(&mut self) {
        if self.machine.try_wait(self.pid).is_none() {
            let _ = self.machine.signal(self.pid, 9);
        }
        let _ = self.machine.close_console(self.console);
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}
