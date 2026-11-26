//! End-to-end tests: tests/guest/*.S are assembled into static ELFs with the host `cc`, and
//! tests/guest/*.c are compiled into programs statically linked with musl by `musl-gcc`, then they
//! are run by appine-run. Each test case runs under Tier 0 and under Tier 1 separately, and the
//! results must be the same.
//!
//! Without musl-gcc (Debian/Ubuntu's musl-tools) the C programs are skipped; with
//! `APPINE_REQUIRE_MUSL=1` (as CI sets) that becomes a failure.
//!
//! Producing Linux aarch64 ELFs needs a Linux arm64 host (design doc §13.3); on other hosts the
//! whole file is not compiled.
#![cfg(all(target_os = "linux", target_arch = "aarch64"))]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const TIERS: [&str; 2] = ["0", "1"];

#[test]
fn hello_world() {
    for (tier, out) in run("hello", &[]) {
        assert_eq!(stdout(&out), "Hello from appine!\n", "tier {tier}");
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn options_without_a_value_refuse_one() {
    // `--pty=0` used to turn the PTY on: an inline value on a flag is a usage error (2), while an
    // option with a value still takes it inline (a missing program is 127)
    let appine_run = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(args)
            .output()
            .unwrap()
            .status
            .code()
    };
    for flag in [
        "--pty=0",
        "--no-pty=1",
        "--stats=no",
        "--init=0",
        "--always-map-low-ports=0",
        "--help=1",
        "--version=1",
    ] {
        assert_eq!(appine_run(&[flag, "/nonexistent"]), Some(2), "{flag}");
    }
    assert_eq!(appine_run(&["--tier=7", "/nonexistent"]), Some(2));
    assert_eq!(appine_run(&["--tier=0", "/nonexistent"]), Some(127));
}

#[test]
fn exit_code_is_propagated() {
    for (tier, out) in run("exit42", &[]) {
        assert_eq!(out.status.code(), Some(42), "tier {tier}");
    }
}

#[test]
fn fib_uses_stack_and_calls() {
    for (tier, out) in run("fib", &[]) {
        assert_eq!(stdout(&out), "fib(50) = 12586269025\n", "tier {tier}");
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn argv_reaches_guest() {
    for (tier, out) in run("echo", &["hello", "appine", "world"]) {
        assert_eq!(stdout(&out), "hello appine world\n", "tier {tier}");
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn unknown_syscall_returns_enosys() {
    for (tier, out) in run("enosys", &[]) {
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn segfault_kills_guest() {
    for (tier, out) in run("segv", &[]) {
        assert_eq!(out.status.code(), Some(128 + 11), "tier {tier}");
        assert!(
            stderr(&out).contains("SIGSEGV"),
            "tier {tier}: {}",
            stderr(&out)
        );
        assert!(
            stderr(&out).contains("addr=0x1000"),
            "tier {tier}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn undefined_instruction_kills_guest() {
    for (tier, out) in run("undef", &[]) {
        assert_eq!(out.status.code(), Some(128 + 4), "tier {tier}");
        assert!(
            stderr(&out).contains("SIGILL"),
            "tier {tier}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn threads_signals_and_fork() {
    // Mutexes, condition variables, atomics, thread-local storage, signals sent to a given thread,
    // the alternate signal stack, returning after fixing up a memory access fault, SA_RESTART, fork
    // in a multithreaded process, detached threads
    run_c_guest("threads");
}

#[test]
fn thread_churn_keeps_the_host_heap_intact() {
    // 4 processes, each with 4 threads that keep creating and joining short-lived threads for 5
    // seconds: an exiting thread dropping an Rc weak reference outside the BKL corrupts the host
    // heap, and Appine exits with SIGABRT (tests/guest/churn.c)
    let Some(program) = build_c_guest("churn") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .arg("5")
            .output()
            .expect("failed to run appine-run");
        assert!(
            out.status.success() && stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {:?} {}{}",
            out.status,
            stdout(&out),
            stderr(&out)
        );
    }
}

#[test]
fn sockets_polling_and_timers() {
    // AF_UNIX (socketpair, SCM_RIGHTS, SO_PEERCRED, abstract addresses), TCP/UDP loopback, netlink,
    // epoll/eventfd/select, setitimer; none of them needs outside network
    run_c_guest("net");
}

#[test]
fn net_regressions() {
    // Targeted regressions for kernel/net, kernel/netns, kernel/netlink, kernel/rawicmp and
    // kernel/nft fixes
    run_c_guest("net_regressions");
}

#[test]
fn bugs_kill_only_the_guest_process() {
    // A kernel-layer panic (on entering the kernel, while the BKL is released, in a no-BKL system
    // call, when a thread starts and exits, on the timer thread) or the engine making the host
    // fault (simulated with the test hooks of debug builds) ends only the guest process that hits
    // it, and everything else in the app keeps running
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("bugs") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .env("APPINE_TEST_HOOKS", "1")
            .env("APPINE_ON_BUG", "kill")
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
        // 0xa991 is the test hook's syscall number
        for report in [
            "kernel panic in syscall 43409",
            "kernel panic in syscall 113 without the BKL",
            "host signal 11",
            "kernel panic while the thread was exiting",
            "kernel panic while starting the thread",
            "kernel panic in its timers",
        ] {
            assert!(
                stderr(&out).contains(report),
                "tier {tier}: {}",
                stderr(&out)
            );
        }
    }
}

#[test]
fn tcp_filters_refused_by_the_host() {
    if cfg!(debug_assertions) {
        run_c_guest_with("sockfilter", &[], true);
        run_c_guest_with("net_regressions", &["filtered-dnat"], true);
    }
}

#[test]
fn clock_jumps_wake_wall_clock_waiters() {
    // A jump of the host's wall clock (simulated with a test hook of debug builds): timerfds with
    // TFD_TIMER_CANCEL_ON_SET read ECANCELED, and waits on wall-clock deadlines look at them again
    // and still end on time
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("clockjump") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .env("APPINE_TEST_HOOKS", "1")
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn host_calls_survive_kernel_bugs() {
    // A kernel-layer panic while the host calls a Machine method (simulated by a test hook): only
    // that call fails, a call on a console also hangs up that console, and the Machine stays usable
    // afterwards. A spawn whose thread cannot start fails without leaving its process or the
    // console's session behind
    use appine_kernel::errno::Errno;
    use appine_kernel::{ExitStatus, KillReason, Machine, MachineOptions, RunError, Stdio, Tier};
    use std::os::unix::ffi::OsStrExt;
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("bugs") else {
        return;
    };
    // The kernel layer reads APPINE_ON_BUG only when it first hits a bug: rerun this test case in
    // a child process that has it and APPINE_TEST_HOOKS set
    if std::env::var_os("APPINE_TEST_HOOKS").is_none() {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "host_calls_survive_kernel_bugs", "--nocapture"])
            .env("APPINE_TEST_HOOKS", "1")
            .env("APPINE_ON_BUG", "kill")
            .output()
            .expect("failed to rerun the test");
        assert!(
            out.status.success() && stdout(&out).contains("1 passed"),
            "{}{}",
            stdout(&out),
            stderr(&out)
        );
        return;
    }
    let hello = build_guest("hello");
    let path = |p: &Path| p.as_os_str().as_bytes().to_vec();
    let argv = |mode: &str| [b"bugs".to_vec(), mode.as_bytes().to_vec()];
    let read_all = |machine: &Machine, id: u32| {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        let end = loop {
            match machine.read_console(id, &mut buf) {
                Ok(0) => break Ok(()),
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) => break Err(e),
            }
        };
        (String::from_utf8(out).unwrap(), end)
    };
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let machine = Machine::start(&MachineOptions {
            tier,
            rootfs: None,
            memory_limit: None,
            low_port_offset: None,
            always_map_low_ports: false,
            exception_trace: false,
        })
        .unwrap();
        // An error in spawn: spawn fails
        let pid = machine
            .spawn(
                &path(&program),
                &argv("host-call-then-exit"),
                &[],
                Stdio::Host,
            )
            .unwrap();
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");
        let r = machine.spawn(&path(&hello), &[b"hello".to_vec()], &[], Stdio::Host);
        assert!(matches!(r, Err(RunError::Internal)), "{tier:?}: {r:?}");
        // An error while reading the console: the console is hung up, and the session leader
        // receives SIGHUP
        let id = machine.open_console(24, 80).unwrap();
        let pid = machine
            .spawn(
                &path(&program),
                &argv("host-call-then-read"),
                &[],
                Stdio::Console(id),
            )
            .unwrap();
        assert_eq!(read_all(&machine, id).1, Err(Errno::EIO), "{tier:?}");
        assert!(
            matches!(machine.wait(pid), ExitStatus::Signaled { signal, .. } if signal.number() == 1),
            "{tier:?}"
        );
        assert_eq!(read_all(&machine, id).1, Err(Errno::ENOENT), "{tier:?}");
        // Usable as usual afterwards
        let id = machine.open_console(24, 80).unwrap();
        let pid = machine
            .spawn(&path(&hello), &[b"hello".to_vec()], &[], Stdio::Console(id))
            .unwrap();
        let (out, end) = read_all(&machine, id);
        assert_eq!(
            (out.as_str(), end),
            ("Hello from appine!\r\n", Ok(())),
            "{tier:?}"
        );
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");
        // A spawn whose host thread cannot be created fails with EAGAIN, and the console is free
        // for the next spawn (it used to stay EBUSY, held by a process that never ran)
        let pid = machine
            .spawn(
                &path(&program),
                &argv("thread-start-fails-then-exit"),
                &[],
                Stdio::Host,
            )
            .unwrap();
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");
        let id = machine.open_console(24, 80).unwrap();
        let hello_on =
            |id| machine.spawn(&path(&hello), &[b"hello".to_vec()], &[], Stdio::Console(id));
        let r = hello_on(id);
        assert!(
            matches!(&r, Err(RunError::Io(e)) if e.raw_os_error() == Some(Errno::EAGAIN.0)),
            "{tier:?}: {r:?}"
        );
        let pid = hello_on(id).unwrap();
        let (out, end) = read_all(&machine, id);
        assert_eq!(
            (out.as_str(), end),
            ("Hello from appine!\r\n", Ok(())),
            "{tier:?}"
        );
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");
        // A process killed for hitting a bug leaves a report for the app (take_kills): it carries
        // the console's number, and once taken it is gone
        assert!(machine.take_kills().is_empty(), "{tier:?}");
        let id = machine.open_console(24, 80).unwrap();
        let pid = machine
            .spawn(
                &path(&program),
                &[b"bugs".to_vec()],
                &[],
                Stdio::Console(id),
            )
            .unwrap();
        let (out, _) = read_all(&machine, id);
        assert!(out.ends_with("all ok\r\n"), "{tier:?}: {out}");
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");
        let kills = machine.take_kills();
        assert!(kills.len() >= 6, "{tier:?}: {kills:?}");
        for k in &kills {
            assert_eq!(
                (k.comm.as_str(), k.console),
                ("guest-bugs", Some(id)),
                "{tier:?}: {k:?}"
            );
            assert!(
                matches!(&k.reason, KillReason::Bug { report, .. } if report.contains(&format!("pid {}", k.pid))),
                "{tier:?}: {k:?}"
            );
        }
        // The report holds the panic's message and location (bug::install_panic_hook), not just
        // "panic in a syscall"
        assert!(
            kills.iter().any(|k| matches!(&k.reason, KillReason::Bug { report, .. } if report.contains(
                "kernel panic in syscall 43409: panic injected by the test hook at core/kernel/src/bug.rs:"
            ))),
            "{tier:?}: {kills:?}"
        );
        // The report carries the kernel log, as `dmesg` writes it: the report itself last, older
        // records before it (here the report of the previous bug); and the unimplemented paths
        // the guest reached (crate::stub), here the unknown prctl option it asked for twice
        let reports: Vec<(&str, &[String])> = kills
            .iter()
            .map(|k| match &k.reason {
                KillReason::Bug { report, log, stubs } => {
                    assert!(
                        stubs.contains(
                            &"prctl option 0x7fff0000: 2 calls, first by guest-bugs".into()
                        ),
                        "{tier:?}: {stubs:?}"
                    );
                    (report.as_str(), log.as_slice())
                }
                other => panic!("{tier:?}: {other:?}"),
            })
            .collect();
        for (i, (report, log)) in reports.iter().enumerate() {
            assert!(
                log.iter().all(|l| l.starts_with('[') && l.contains("] ")),
                "{tier:?}: {log:?}"
            );
            assert!(
                log.last()
                    .is_some_and(|l| l.ends_with(report.lines().last().unwrap())),
                "{tier:?}: {report} {log:?}"
            );
            if i > 0 {
                let before = reports[i - 1].0.lines().next().unwrap();
                assert!(
                    log.iter().any(|l| l.ends_with(before)),
                    "{tier:?}: {before} {log:?}"
                );
            }
        }
        assert!(machine.take_kills().is_empty(), "{tier:?}");
    }
}

#[test]
fn bkl_watchdog_reports_long_holds() {
    // A hold of the BKL longer than the watchdog's threshold (a test hook holds it for 2.5 s, the
    // threshold is 1 s) is reported on stderr while it lasts, naming the process, the syscall
    // (0xa991, the test hook's) and the host thread, and in the kernel log once it has ended. The
    // watchdog does not depend on the tier
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("stall") else {
        return;
    };
    let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
        .env("APPINE_TEST_HOOKS", "1")
        .env("APPINE_BKL_WATCHDOG", "1")
        .arg(&program)
        .output()
        .expect("failed to run appine-run");
    let (out, err) = (stdout(&out), stderr(&out));
    assert!(out.ends_with("all ok\n"), "{out}{err}");
    let report = err
        .lines()
        .find(|l| l.contains(" has held the BKL for "))
        .unwrap_or_else(|| panic!("no report on stderr: {err}"));
    assert!(
        report.starts_with("appine: pid ")
            && report.contains(" (guest-stall), thread ")
            && report.contains(" in syscall 43409 at guest pc 0x")
            && report.contains("(host thread guest-"),
        "{report}"
    );
    // As dmesg would show it: "<3>[    1.234567] appine: pid 2 (guest-stall), thread 2 held the
    // BKL for 2 s in syscall 43409 at guest pc 0x..."
    let record = out.lines().next().unwrap();
    assert!(
        record.starts_with("<3>[")
            && record.contains("] appine: pid ")
            && record.contains(" (guest-stall), thread ")
            && record.contains(" s in syscall 43409 at guest pc 0x"),
        "{record}"
    );
    // The same record on stderr
    let logged = record.split_once("] ").unwrap().1;
    assert!(err.lines().any(|l| l == logged), "{logged}\n{err}");
}

#[test]
fn bkl_watchdog_reports_a_hold_right_after_another() {
    // A second hold starts as soon as the first one ends, while the watchdog's record of the first
    // waits for the BKL: the watchdog goes on looking and reports the second hold too, and both
    // records reach the kernel log, in order
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("stall") else {
        return;
    };
    let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
        .env("APPINE_TEST_HOOKS", "1")
        .env("APPINE_BKL_WATCHDOG", "1")
        .arg(&program)
        .arg("twice")
        .output()
        .expect("failed to run appine-run");
    let (out, err) = (stdout(&out), stderr(&out));
    assert!(out.ends_with("all ok\n"), "{out}{err}");
    let reports: Vec<&str> = err
        .lines()
        .filter(|l| l.contains(" has held the BKL for "))
        .collect();
    assert_eq!(reports.len(), 2, "{err}");
    let thread = |l: &str| {
        l.split_once(", thread ")
            .unwrap()
            .1
            .split(' ')
            .next()
            .unwrap()
            .to_owned()
    };
    assert_ne!(thread(reports[0]), thread(reports[1]), "{err}");
    let records: Vec<&str> = out
        .lines()
        .filter(|l| l.contains(" held the BKL for "))
        .collect();
    assert_eq!(records.len(), 2, "{out}");
    assert_eq!(thread(records[0]), thread(reports[0]), "{out}{err}");
}

#[test]
fn bkl_stall_reaches_the_host() {
    // Machine::stall answers without the BKL while a hold goes on, then carries its kernel log
    // record once it ended
    use appine_kernel::{ExitStatus, Machine, MachineOptions, Stdio};
    use std::os::unix::ffi::OsStrExt;
    use std::time::{Duration, Instant};
    if !cfg!(debug_assertions) {
        return;
    }
    let Some(program) = build_c_guest("stall") else {
        return;
    };
    // The kernel reads APPINE_BKL_WATCHDOG when it starts: rerun this test case in a child process
    // that has it and APPINE_TEST_HOOKS set
    if std::env::var_os("APPINE_TEST_HOOKS").is_none() {
        let out = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "bkl_stall_reaches_the_host", "--nocapture"])
            .env("APPINE_TEST_HOOKS", "1")
            .env("APPINE_BKL_WATCHDOG", "1")
            .output()
            .expect("failed to rerun the test");
        assert!(
            out.status.success() && stdout(&out).contains("1 passed"),
            "{}{}",
            stdout(&out),
            stderr(&out)
        );
        return;
    }
    let machine = Machine::start(&MachineOptions::default()).unwrap();
    assert_eq!(machine.stall(), None);
    let pid = machine
        .spawn(
            program.as_os_str().as_bytes(),
            &[b"stall".to_vec(), b"hold".to_vec()],
            &[],
            Stdio::Host,
        )
        .unwrap();
    let wait_for = |what: &str, done: &dyn Fn(&appine_kernel::Stall) -> bool| {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(s) = machine.stall().filter(|s| done(s)) {
                return s;
            }
            assert!(
                Instant::now() < deadline,
                "no {what}: {:?}",
                machine.stall()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    };
    let stall = wait_for("report", &|_| true);
    assert_eq!((stall.id, stall.ended.as_ref()), (1, None), "{stall:?}");
    assert!(
        stall.secs >= 1
            && stall
                .report
                .contains(&format!("pid {pid} (guest-stall), thread {pid} "))
            && stall.report.contains(" in syscall 43409 at guest pc 0x"),
        "{stall:?}"
    );
    assert_eq!(machine.wait(pid), ExitStatus::Exited(0));
    let stall = wait_for("end", &|s| s.ended.is_some());
    assert!(
        stall.id == 1
            && stall.secs >= 1
            && stall.ended.as_ref().unwrap().contains(&format!(
                "pid {pid} (guest-stall), thread {pid} held the BKL for {} s in syscall 43409",
                stall.secs
            )),
        "{stall:?}"
    );
}

#[test]
fn memory_limit_and_thread_limits() {
    // RLIMIT_NPROC's default value and checks (root is not limited by it), and over the app's
    // memory limit the guest process using the most is killed
    let Some(program) = build_c_guest("limits") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier, "--memory-limit", "256M"])
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
        assert!(
            stderr(&out).contains("out of memory: killed process"),
            "tier {tier}: {}",
            stderr(&out)
        );
    }
}

#[test]
fn main_stack_grows_up_to_rlimit_stack() {
    // Page faults, syscall buffers and signal frames all make the main thread's stack grow, its
    // size limited by the current value of RLIMIT_STACK; beyond that a page fault gets SIGSEGV and
    // a kernel access gets EFAULT
    let Some(program) = build_c_guest("stack") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn shootdowns_wait_only_for_threads_they_kicked() {
    // tests/guest/cowspin.c: a parent taking back pages it lent its child shoots down the child's
    // address space while the child's threads spin in guest code or wait for the BKL. Waiting for
    // a spinner that was not kicked deadlocked the kernel, so a run is given 60 s
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let Some(program) = build_c_guest("cowspin") else {
        return;
    };
    for tier in TIERS {
        let mut child = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to run appine-run");
        let deadline = Instant::now() + Duration::from_secs(60);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                let _ = child.kill();
                let out = child.wait_with_output().unwrap();
                panic!("tier {tier}: still running after 60 s\n{}", stderr(&out));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let out = child.wait_with_output().unwrap();
        assert_eq!(stdout(&out), "done\n", "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn mprotect_never_makes_copy_on_write_pages_writable() {
    // tests/guest/cowprot.c: after fork one process keeps giving the pages it lent or borrowed
    // read-write permission while its other thread wakes from short sleeps (so no shootdown kicks
    // it) and writes them; the other process must never see those writes
    let Some(program) = build_c_guest("cowprot") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(stdout(&out), "done\n", "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn ipc_timers_credentials_and_scheduling() {
    // System V message queues, semaphores (SEM_UNDO) and shared memory across fork, POSIX timers
    // (overrun counts, SIGEV_THREAD, CPU clocks), clocks (no-BKL and locked ones agree), mremap,
    // credential rules after dropping privileges, affinity and real-time policies, RLIMIT_NOFILE,
    // ptrace single-stepping, syscall stops and process_vm_readv
    let Some(program) = build_c_guest("posix") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn self_modifying_code() {
    // Rewriting code as a JIT does: the same page rewritten again and again, W^X mprotect, a dual
    // memfd mapping, rewriting while another thread is running it, and cache maintenance on
    // unmapped addresses
    let Some(program) = build_c_guest("jit") else {
        return;
    };
    for tier in TIERS {
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier])
            .arg(&program)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
    }
}

#[test]
fn readv_on_host_stdin_returns_what_has_arrived() {
    // tests/guest/stdinreadv.c: with stdin a host pipe, a readv whose first iovec the input just
    // fills returns those bytes instead of waiting to fill the second, so a program can answer
    // before the host sends more (it used to wait for more input, and here the host waits for the
    // answer first, so it never came); input spread over both iovecs comes in one readv. A run
    // is given 20 s per answer
    use std::io::{BufRead, BufReader, Write};
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;
    let Some(program) = build_c_guest("stdinreadv") else {
        return;
    };
    for tier in TIERS {
        let mut child = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier, "--no-pty"])
            .arg(&program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to run appine-run");
        let (lines, answers) = mpsc::channel();
        let stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let _ = lines.send(line.unwrap());
            }
        });
        let mut stdin = child.stdin.take().unwrap();
        let mut answer = |what: &str| match answers.recv_timeout(Duration::from_secs(20)) {
            Ok(line) => line,
            Err(_) => {
                let _ = child.kill();
                panic!("tier {tier}: no answer after {what} within 20 s");
            }
        };
        stdin.write_all(b"12345678").unwrap();
        assert_eq!(answer("8 bytes"), "got 8: 12345678|", "tier {tier}");
        stdin.write_all(b"ABCDEFGHIJ").unwrap();
        assert_eq!(answer("10 bytes"), "got 10: ABCDEFGH|IJ", "tier {tier}");
        drop(stdin);
        assert_eq!(answer("the end of input"), "got 0: |", "tier {tier}");
        let out = child.wait_with_output().unwrap();
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn host_stdio_positional_io_and_interruptible_writes() {
    use std::fs::OpenOptions;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    let Some(program) = build_c_guest("hoststdio") else {
        return;
    };
    for tier in TIERS {
        // 1. Regular host files on stdin and stdout support pread/pwrite/preadv/pwritev.
        let (_, in_path) = output(&format!("hoststdio-in-t{tier}"));
        let (_, out_path) = output(&format!("hoststdio-out-t{tier}"));
        std::fs::write(&in_path, b"hello world!").unwrap();
        std::fs::write(&out_path, b"____________").unwrap();
        let stdin_file = OpenOptions::new().read(true).open(&in_path).unwrap();
        let stdout_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&out_path)
            .unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier, "--no-pty"])
            .arg(&program)
            .arg("regular")
            .stdin(Stdio::from(stdin_file))
            .stdout(Stdio::from(stdout_file))
            .output()
            .expect("failed to run appine-run");
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
        assert_eq!(
            std::fs::read(&out_path).unwrap(),
            b"HELLO WORLD_",
            "tier {tier}: host regular stdout pwrite/pwritev contents"
        );
        let _ = std::fs::remove_file(&in_path);
        let _ = std::fs::remove_file(&out_path);

        // 2. Host pipes reject pread/pwrite with ESPIPE, honour O_NONBLOCK, and allow SIGALRM to
        // interrupt a blocked write when the host pipe is full.
        let mut child = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--tier", tier, "--no-pty"])
            .arg(&program)
            .arg("pipe-intr")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn appine-run");
        // Keep the pipe read end open without reading so stdout fills and blocks the guest write.
        let _stdout_keepalive = child.stdout.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(15);
        let status = loop {
            if let Some(st) = child.try_wait().unwrap() {
                break st;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("tier {tier}: blocked host pipe write was not interrupted by SIGALRM");
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        drop(_stdout_keepalive);
        let out = child.wait_with_output().unwrap();
        assert_eq!(status.code(), Some(0), "tier {tier}: {}", stderr(&out));
    }
}

#[test]
fn deleted_held_file_releases_share_on_close() {
    let Some(program) = build_c_guest("hoststdio") else {
        return;
    };
    let bytes = std::fs::read(&program).unwrap();
    let (_, empty_dir) = output("share-release-empty");
    let (_, tar_path) = output("share-release-empty.tar.gz");
    let _ = std::fs::remove_dir_all(&empty_dir);
    let _ = std::fs::remove_file(&tar_path);
    std::fs::create_dir_all(&empty_dir).unwrap();
    let tar = Command::new("tar")
        .args(["-czf"])
        .arg(&tar_path)
        .args(["-C"])
        .arg(&empty_dir)
        .arg(".")
        .status()
        .expect("tar failed");
    assert!(tar.success());

    for tier in TIERS {
        let (_, store) = output(&format!("share-release-store-t{tier}"));
        let _ = std::fs::remove_dir_all(&store);
        appine_kernel::import_rootfs(&store, &tar_path).unwrap();
        appine_kernel::write_file(&store, "/hoststdio", &bytes, 0o755, true, 0, 0).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--rootfs"])
            .arg(&store)
            .args(["--tier", tier, "/hoststdio", "share-release"])
            .output()
            .expect("failed to run appine-run");
        assert_eq!(out.status.code(), Some(0), "tier {tier}: {}", stderr(&out));
        // Only the program binary and the single shared object (reused in place by /tmp/share_b)
        // should exist in `objects/`; without releasing the deleted open sharer on close, writing
        // /tmp/share_b would have copied into a third object.
        let objects: Vec<_> = std::fs::read_dir(store.join("objects"))
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(
            objects.len(),
            2,
            "tier {tier}: expected 2 objects (binary + in-place settled share_b), got {objects:?}"
        );
        let _ = std::fs::remove_dir_all(&store);
    }
    let _ = std::fs::remove_dir_all(&empty_dir);
    let _ = std::fs::remove_file(&tar_path);
}

#[test]
fn missing_program_exits_127() {
    let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
        .arg("/nonexistent/program")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(127));
}

fn run_c_guest(name: &str) {
    run_c_guest_with(name, &[], false);
}

fn run_c_guest_with(name: &str, args: &[&str], test_hooks: bool) {
    let Some(program) = build_c_guest(name) else {
        return;
    };
    for tier in TIERS {
        let mut run = Command::new(env!("CARGO_BIN_EXE_appine-run"));
        if test_hooks {
            run.env("APPINE_TEST_HOOKS", "1");
        }
        let out = run
            .args(["--tier", tier])
            .arg(&program)
            .args(args)
            .output()
            .expect("failed to run appine-run");
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: {}{}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: {}",
            stdout(&out)
        );
        assert!(
            !stderr(&out).contains("appine: internal error"),
            "tier {tier}: unexpected internal error in stderr: {}",
            stderr(&out)
        );
    }
}

fn run_guest_in_empty_rootfs(name: &str) {
    let Some(program) = build_c_guest(name) else {
        return;
    };
    let bytes = std::fs::read(&program).unwrap();
    let (_, empty_dir) = output(&format!("{name}-empty"));
    let (_, tar_path) = output(&format!("{name}-empty.tar.gz"));
    let _ = std::fs::remove_dir_all(&empty_dir);
    let _ = std::fs::remove_file(&tar_path);
    std::fs::create_dir_all(&empty_dir).unwrap();
    let tar = Command::new("tar")
        .args(["-czf"])
        .arg(&tar_path)
        .args(["-C"])
        .arg(&empty_dir)
        .arg(".")
        .status()
        .expect("tar failed");
    assert!(tar.success());
    let guest_path = format!("/{name}");
    for tier in TIERS {
        let (_, store) = output(&format!("{name}-store-t{tier}"));
        let _ = std::fs::remove_dir_all(&store);
        appine_kernel::import_rootfs(&store, &tar_path).unwrap();
        appine_kernel::write_file(&store, &guest_path, &bytes, 0o755, true, 0, 0).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
            .args(["--rootfs"])
            .arg(&store)
            .args(["--tier", tier, &guest_path])
            .output()
            .expect("failed to run appine-run");
        let _ = std::fs::remove_dir_all(&store);
        assert_eq!(
            out.status.code(),
            Some(0),
            "tier {tier}: stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            stdout(&out).ends_with("all ok\n"),
            "tier {tier}: stdout={} stderr={}",
            stdout(&out),
            stderr(&out)
        );
        assert!(
            !stderr(&out).contains("appine: internal error"),
            "tier {tier}: unexpected internal error in stderr: {}",
            stderr(&out)
        );
    }
    let _ = std::fs::remove_dir_all(&empty_dir);
    let _ = std::fs::remove_file(&tar_path);
}

#[test]
fn stability_regressions() {
    run_guest_in_empty_rootfs("stability");
}

#[test]
fn isolation_regressions() {
    run_guest_in_empty_rootfs("isolation");
}

#[test]
fn fs_mm_regressions() {
    run_guest_in_empty_rootfs("fs_mm");
}

#[test]
fn ipc_poll_unix_regressions() {
    run_guest_in_empty_rootfs("ipc_poll_unix");
}

#[test]
fn poll_opt_regressions() {
    run_guest_in_empty_rootfs("poll_opt");
}

#[test]
fn sig_ptrace_tty_regressions() {
    run_guest_in_empty_rootfs("sig_ptrace_tty");
}

#[test]
fn sig_ptrace_tty_console_write_after_end() {
    use appine_kernel::errno::Errno;
    use appine_kernel::{ExitStatus, Machine, MachineOptions, Stdio, Tier};
    use std::os::unix::ffi::OsStrExt;

    let hello = build_guest("hello");
    let path = hello.as_os_str().as_bytes().to_vec();
    for tier in [Tier::Interpreter, Tier::Dbt] {
        let machine = Machine::start(&MachineOptions {
            tier,
            rootfs: None,
            memory_limit: None,
            low_port_offset: None,
            always_map_low_ports: false,
            exception_trace: false,
        })
        .unwrap();
        let id = machine.open_console(24, 80).unwrap();
        let pid = machine
            .spawn(&path, &[b"hello".to_vec()], &[], Stdio::Console(id))
            .unwrap();
        assert_eq!(machine.wait(pid), ExitStatus::Exited(0), "{tier:?}");

        // Drain all output until EOF (0).
        let mut buf = [0u8; 256];
        while machine.read_console(id, &mut buf).unwrap() > 0 {}

        // Writing after the console session ended must fail with EIO and produce no echoes.
        assert_eq!(
            machine.write_console(id, b"late input\n"),
            Err(Errno::EIO),
            "{tier:?}"
        );
        assert_eq!(machine.read_console(id, &mut buf), Ok(0), "{tier:?}");
    }
}

#[test]
fn fs_io_regressions() {
    run_guest_in_empty_rootfs("fs_io_regressions");
}

#[test]
fn mm_mount_pseudo_regressions() {
    run_guest_in_empty_rootfs("mm_mount_pseudo");
}

#[test]
fn mount_proc_sys_regressions() {
    run_guest_in_empty_rootfs("mount_proc_sys");
}

#[test]
fn new_mount_api_no_lift_and_nsfs_pinning() {
    run_guest_in_empty_rootfs("mount_api");
}

#[test]
fn exec_runs_post_syscall_sweeps() {
    run_guest_in_empty_rootfs("exec_sweep");
}

#[test]
fn mm_gap_semantics_and_shared_futex_maps() {
    run_guest_in_empty_rootfs("mm_fixes");
}

#[test]
fn netlink_resumable_and_nft_setelem_dumps() {
    run_c_guest("netlink_dump");
}

#[test]
fn netns_same_port_bind_conflicts_and_routing() {
    run_guest_in_empty_rootfs("netns_bind");
}

#[test]
fn oom_victim_reaping_and_vfork_safety() {
    run_guest_in_empty_rootfs("oom_reap");
}

#[test]
fn overlay_origin_remount() {
    run_guest_in_empty_rootfs("overlay_origin");
}

#[test]
fn overlay_node_eviction_and_mmap_copy_up() {
    run_guest_in_empty_rootfs("overlay_fixes");
}

#[test]
fn ptrace_and_process_vm_cold_fuse_pages() {
    run_guest_in_empty_rootfs("ptrace_fuse");
}

#[test]
fn fuse_mm_writeback_unix_lookup_and_prefault() {
    run_guest_in_empty_rootfs("fuse_mm_fixes");
}

#[test]
fn store_relatime_semantics_and_multichunk_reads() {
    run_guest_in_empty_rootfs("store_relatime");
}

#[test]
fn doomed_elf_fails_to_spawn() {
    // Minimal 64-bit aarch64 ET_EXEC whose PT_LOAD has p_offset != p_vaddr (mod page),
    // which loader::load marks as Image::doomed.
    let mut elf = vec![0u8; 128];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2; // ELFCLASS64
    elf[5] = 1; // ELFDATA2LSB
    elf[6] = 1; // EV_CURRENT
    elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf[24..32].copy_from_slice(&0x400078u64.to_le_bytes()); // e_entry
    elf[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    elf[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    elf[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    elf[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    // PT_LOAD at offset 64: p_offset = 1, p_vaddr = 0x400000 (misaligned within page -> doomed)
    elf[64..68].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf[68..72].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
    elf[72..80].copy_from_slice(&1u64.to_le_bytes()); // p_offset
    elf[80..88].copy_from_slice(&0x400000u64.to_le_bytes()); // p_vaddr
    elf[96..104].copy_from_slice(&16u64.to_le_bytes()); // p_filesz
    elf[104..112].copy_from_slice(&16u64.to_le_bytes()); // p_memsz
    elf[112..120].copy_from_slice(&4096u64.to_le_bytes()); // p_align

    let (_, path) = output("doomed-elf");
    std::fs::write(&path, &elf).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
        .arg(&path)
        .output()
        .expect("failed to run appine-run");
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        out.status.code(),
        Some(126),
        "doomed ELF must fail load instead of launching at pc 0: stderr={}",
        stderr(&out)
    );
}

/// Runs a guest program once under each tier, returning (tier, output).
fn run(name: &str, args: &[&str]) -> Vec<(&'static str, Output)> {
    let program = build_guest(name);
    TIERS
        .iter()
        .map(|&tier| {
            let out = Command::new(env!("CARGO_BIN_EXE_appine-run"))
                .args(["--tier", tier])
                .arg(&program)
                .args(args)
                .output()
                .expect("failed to run appine-run");
            (tier, out)
        })
        .collect()
}

fn build_guest(name: &str) -> PathBuf {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/guest")
        .join(format!("{name}.S"));
    let (out, tmp) = output(name);
    let cc = std::env::var("CC").unwrap_or_else(|_| "cc".into());
    let status = Command::new(&cc)
        .args([
            "-nostdlib",
            "-static",
            "-no-pie",
            "-Wl,--build-id=none",
            "-o",
        ])
        .arg(&tmp)
        .arg(&src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {cc}: {e}"));
    assert!(status.success(), "assembling {} failed", src.display());
    std::fs::rename(&tmp, &out).unwrap();
    out
}

/// Builds tests/guest/<name>.c statically with musl-gcc; returns None without musl-gcc.
fn build_c_guest(name: &str) -> Option<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/guest")
        .join(format!("{name}.c"));
    let (out, tmp) = output(name);
    let status = Command::new("musl-gcc")
        .args([
            "-static", "-O2", "-Wall", "-Wextra", "-Werror", "-pthread", "-o",
        ])
        .arg(&tmp)
        .arg(&src)
        .status();
    let Ok(status) = status else {
        assert!(
            std::env::var_os("APPINE_REQUIRE_MUSL").is_none_or(|v| v != "1"),
            "musl-gcc not found; install musl-tools"
        );
        eprintln!("skipping {name}: musl-gcc not found");
        return None;
    };
    assert!(status.success(), "compiling {} failed", src.display());
    std::fs::rename(&tmp, &out).unwrap();
    Some(out)
}

/// The path of a built guest program, and the temporary file written while building it: several
/// test cases may build the same program at once; each writes its own and then renames it into
/// place, so that none runs a file another one has half written.
fn output(name: &str) -> (PathBuf, PathBuf) {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let tmp = dir.join(format!("guest-{name}.{}.{n}", std::process::id()));
    (dir.join(format!("guest-{name}")), tmp)
}

fn stdout(out: &Output) -> &str {
    std::str::from_utf8(&out.stdout).unwrap()
}

fn stderr(out: &Output) -> &str {
    std::str::from_utf8(&out.stderr).unwrap()
}
