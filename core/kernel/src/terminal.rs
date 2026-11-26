//! The host-side console: an in-process PTY master held by the host (the kernel/tty map).
//!
//! [`crate::Machine`] opens a console for each terminal session, and the session leader uses its
//! slave as stdin/stdout/stderr and controlling terminal. Bytes the host writes go through the
//! line discipline (^C becomes SIGINT sent to the foreground process group), and the host takes
//! the guest's output. Host threads are not guest threads, but like them they access kernel
//! objects only while holding the BKL, and they wait through the same mechanism: a guest write to
//! the terminal requests a wake, and a host thread waiting for output wakes up.
//!
//! `appine-run` uses [`bridge`] to connect the host terminal to a console.

use std::rc::Rc;
use std::sync::Arc;

use appine_hal::Event;

use crate::cell::RefCell;
use crate::errno::Errno;
use crate::fd::{FileKind, FileRef, OpenFile, oflags};
use crate::kernel::{Kernel, Shared, Tid, block_for, request_wake, request_wake_object, wake};
use crate::process::{Signal, ThreadGroup};
use crate::signal::{self, SigInfo};
use crate::tty::flags::{ECHO, ICANON};
use crate::tty::{PtyEnd, Tty, Winsize};

// ---- Consoles ----

/// A console.
pub(crate) struct Console {
    /// The PTY master.
    pub master: PtyEnd,
    /// A process already has it as controlling terminal: from then on, all slaves being closed
    /// means the session has ended.
    pub attached: bool,
}

/// Creates a console and returns its PTY number (`/dev/pts/<number>`).
pub(crate) fn open(k: &mut Kernel, size: Winsize) -> u32 {
    let fs = crate::tty::BOOT_PTS;
    let index = (0..).find(|i| !k.ptys.contains_key(&(fs, *i))).unwrap();
    let tty = Rc::new(RefCell::new(Tty::new(index)));
    {
        let mut t = tty.borrow_mut();
        t.locked = false;
        t.winsize = size;
    }
    k.ptys.insert((fs, index), Rc::downgrade(&tty));
    k.consoles.insert(
        index,
        Console {
            master: PtyEnd::new(tty, true),
            attached: false,
        },
    );
    index
}

/// Makes `leader` the console's session leader: returns the slave's open file and the PTY.
/// Returns EBUSY when the console already belongs to a session.
pub(crate) fn attach(
    k: &mut Kernel,
    id: u32,
    leader: Tid,
) -> Result<(FileRef, Rc<RefCell<Tty>>), Errno> {
    let console = k.consoles.get_mut(&id).ok_or(Errno::ENOENT)?;
    let tty = console.master.tty.clone();
    {
        let mut t = tty.borrow_mut();
        if t.session.is_some() {
            return Err(Errno::EBUSY);
        }
        t.session = Some(leader);
        t.fg = Some(leader);
    }
    console.attached = true;
    let path: Rc<[u8]> = Rc::from(format!("/dev/pts/{id}").into_bytes());
    let slave = OpenFile::with_path(
        FileKind::Pty(PtyEnd::new(tty.clone(), false)),
        oflags::O_RDWR | oflags::O_LARGEFILE,
        Some(path),
    );
    Ok((slave, tty))
}

/// Undoes [`attach`] for `leader`, whose process could not be started: the console has no session
/// again, and counts as attached only if it was before (`attached`), so its end of session is
/// what it was.
pub(crate) fn detach(k: &mut Kernel, id: u32, leader: Tid, attached: bool) {
    let Some(console) = k.consoles.get_mut(&id) else {
        return;
    };
    {
        let mut t = console.master.tty.borrow_mut();
        if t.session == Some(leader) {
            t.session = None;
            t.fg = None;
        }
    }
    console.attached = attached;
}

/// The wake objects to register when waiting for console `id`'s output or for room in its input
/// queue: its PTY. Closing a console requests a wake of the whole channel. None when the console
/// does not exist.
pub(crate) fn wake_objects(k: &Kernel, id: u32) -> Option<Vec<wake::Object>> {
    tty_of(k, id).ok().map(|t| vec![wake::of(&t)])
}

/// Takes up to `max` bytes of output. Returns None when there is no output; returns an empty Vec
/// when the session has ended (all slaves closed) and all output has been taken.
pub(crate) fn take_output(k: &Kernel, id: u32, max: usize) -> Result<Option<Vec<u8>>, Errno> {
    let tty = tty_of(k, id)?;
    let out = tty.borrow_mut().take_output(max);
    Ok(taken(k, id, &tty, out, false).map(|(out, _)| out))
}

/// As [`take_output`], but only up to where the output's writer changes between the foreground
/// process group and another, with whether another wrote it (a job left in the background, or a
/// process of another session).
pub(crate) fn take_output_run(
    k: &Kernel,
    id: u32,
    max: usize,
) -> Result<Option<(Vec<u8>, bool)>, Errno> {
    let tty = tty_of(k, id)?;
    let (out, background) = tty.borrow_mut().take_output_run(max);
    Ok(taken(k, id, &tty, out, background))
}

fn taken(
    k: &Kernel,
    id: u32,
    tty: &Rc<RefCell<Tty>>,
    out: Vec<u8>,
    background: bool,
) -> Option<(Vec<u8>, bool)> {
    if !out.is_empty() {
        // The output queue has room again, so threads waiting to write the terminal can go on
        request_wake_object(wake::of(tty));
        return Some((out, background));
    }
    let ended = k.consoles[&id].attached && tty.borrow().slaves == 0;
    ended.then(|| (Vec::new(), false))
}

/// Whether the console's session has ended (a session was attached and every slave end is now
/// closed).
pub(crate) fn ended(k: &Kernel, id: u32) -> Result<bool, Errno> {
    let console = k.consoles.get(&id).ok_or(Errno::ENOENT)?;
    Ok(console.attached && console.master.tty.borrow().slaves == 0)
}

/// How many more bytes the input queue can hold.
pub(crate) fn input_room(k: &Kernel, id: u32) -> Result<usize, Errno> {
    Ok(tty_of(k, id)?.borrow().input_room())
}

/// Hands host input to the line discipline and sends the resulting signals to the foreground
/// process group. Fails with EIO once the console's session has ended so input (and echoes) are
/// never accepted after EOF.
pub(crate) fn feed(k: &Kernel, id: u32, data: &[u8]) -> Result<(), Errno> {
    if ended(k, id)? {
        return Err(Errno::EIO);
    }
    let tty = tty_of(k, id)?;
    let signals = tty.borrow_mut().write_input(data);
    request_wake_object(wake::of(&tty));
    let fg = tty.borrow().fg;
    if let Some(fg) = fg {
        for sig in signals {
            signal::send_to_pgrp(k, fg, sig, SigInfo::kernel());
        }
    }
    Ok(())
}

/// The console's foreground process group, for the app to tell when the program that reported
/// progress or its status gave the terminal back (the android/vt map). ESRCH when there is
/// none (the shell has exited).
pub(crate) fn fg_pgrp(k: &Kernel, id: u32) -> Result<Tid, Errno> {
    tty_of(k, id)?.borrow().fg.ok_or(Errno::ESRCH)
}

/// Snapshot of a console's foreground process group (the android/vt and android/vtcore maps):
/// used to report automatic command titles for shells without a preexec hook (busybox ash) and
/// fallback busy/command-completion state when a shell emits no OSC 133 marks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsoleForeground {
    /// Foreground process group id (`tty.fg`).
    pub pgid: i32,
    /// Controlling session leader id (`tty.session`), if any.
    pub session: Option<i32>,
    /// Representative process in the foreground group (group leader if alive, else first member).
    pub pid: i32,
    /// Process name (`comm`, up to 15 bytes).
    pub comm: String,
    /// Space-joined command line read from `mm.args` (bounded), or empty if unavailable.
    pub cmdline: String,
    /// Whether the console line discipline is in canonical input mode (`ICANON`).
    pub canonical_input: bool,
    /// Whether the foreground process appears to be an interactive shell waiting for commands
    /// (rather than a non-interactive script/command or non-shell program).
    pub interactive_shell: bool,
}

/// Maximum bytes read from guest `mm.args` when building [`ConsoleForeground::cmdline`].
const FG_CMDLINE_MAX: usize = 512;

/// Prefer the process group leader, falling back to a live member if the leader exited.
fn fg_member(k: &Kernel, fg: Tid) -> Result<(Tid, Tid), Errno> {
    let member = |group: &Rc<RefCell<ThreadGroup>>| {
        let g = group.borrow();
        if g.pgid != fg {
            return None;
        }
        Some((g.tgid, *g.threads.first()?))
    };
    k.groups
        .get(&fg)
        .and_then(member)
        .or_else(|| k.groups.values().find_map(member))
        .ok_or(Errno::ESRCH)
}

/// Snapshot of the console's foreground process group (leader process, or first member if the
/// leader has exited). ESRCH when there is no foreground process group or live thread in it.
pub(crate) fn fg_process(k: &Kernel, id: u32) -> Result<ConsoleForeground, Errno> {
    let tty = tty_of(k, id)?;
    let (fg, session, canonical_input) = {
        let t = tty.borrow();
        (
            t.fg.ok_or(Errno::ESRCH)?,
            t.session,
            t.termios.lflag & ICANON != 0,
        )
    };
    let (tgid, tid) = fg_member(k, fg)?;
    let task = k.tasks.get(&tid).ok_or(Errno::ESRCH)?;
    let raw_comm = task.comm.get();
    let comm_end = raw_comm
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw_comm.len());
    let comm = String::from_utf8_lossy(&raw_comm[..comm_end]).into_owned();
    let raw_args = {
        let res = task.res.borrow();
        let mm = res.mm.borrow();
        let (start, end) = mm.args;
        if end > start {
            let len = usize::try_from(end - start)
                .unwrap_or(FG_CMDLINE_MAX)
                .min(FG_CMDLINE_MAX);
            let mut buf = vec![0u8; len];
            if mm
                .read(crate::uaccess::UserSlice::new(start, len), &mut buf)
                .is_ok()
            {
                buf
            } else {
                Vec::new()
            }
        } else {
            Vec::new()
        }
    };
    let args = split_args(&raw_args);
    let cmdline = args
        .iter()
        .map(|a| String::from_utf8_lossy(a))
        .collect::<Vec<_>>()
        .join(" ");
    let interactive_shell = is_interactive_shell(&comm, &args);
    Ok(ConsoleForeground {
        pgid: fg,
        session,
        pid: tgid,
        comm,
        cmdline,
        canonical_input,
        interactive_shell,
    })
}

fn split_args(raw: &[u8]) -> Vec<&[u8]> {
    let Some(last) = raw.iter().rposition(|&b| b != 0) else {
        return Vec::new();
    };
    raw[..=last].split(|&b| b == 0).collect()
}

fn shell_basename(arg: &str) -> &str {
    let base = arg.rsplit('/').next().unwrap_or(arg);
    base.strip_prefix('-').unwrap_or(base)
}

fn is_known_shell(name: &str) -> bool {
    matches!(
        name,
        "sh" | "ash"
            | "dash"
            | "bash"
            | "zsh"
            | "mksh"
            | "ksh"
            | "ksh93"
            | "pdksh"
            | "oksh"
            | "csh"
            | "tcsh"
            | "fish"
            | "nu"
            | "elvish"
            | "osh"
            | "ysh"
            | "ion"
            | "xonsh"
    )
}

/// Classifies whether `(comm, args)` looks like an interactive shell rather than a non-shell
/// command or a non-interactive shell invocation (`sh -c ...`, `bash script.sh`).
fn is_interactive_shell(comm: &str, args: &[&[u8]]) -> bool {
    let Some((argv0, mut rest)) = args.split_first() else {
        return is_known_shell(comm.strip_prefix('-').unwrap_or(comm));
    };
    let mut shell = String::from_utf8_lossy(argv0);
    if shell_basename(&shell) == "busybox" {
        let Some((applet, options)) = rest.split_first() else {
            return false;
        };
        shell = String::from_utf8_lossy(applet);
        rest = options;
    }
    if !is_known_shell(shell_basename(&shell)) {
        return false;
    }
    let mut read_stdin = false;
    let mut i = 0;
    while i < rest.len() {
        let arg = String::from_utf8_lossy(rest[i]);
        if arg == "--" || arg == "-" {
            return read_stdin || i + 1 >= rest.len();
        }
        if arg.starts_with("--") {
            if arg == "--command" || arg.starts_with("--command=") {
                return false;
            }
            if matches!(
                arg.as_ref(),
                "--rcfile" | "--init-file" | "--config" | "--env-config"
            ) {
                i += 2;
                continue;
            }
            i += 1;
            continue;
        }
        if (arg.starts_with('-') || arg.starts_with('+')) && arg.len() > 1 {
            let bytes = arg.as_bytes();
            let is_minus = bytes[0] == b'-';
            let mut takes_next = false;
            for &b in &bytes[1..] {
                match b {
                    b'c' if is_minus => return false,
                    b's' if is_minus => read_stdin = true,
                    b'o' | b'O' => takes_next = true,
                    _ => {}
                }
            }
            i += if takes_next { 2 } else { 1 };
            continue;
        }
        return read_stdin;
    }
    true
}

/// The current directory of the console's foreground process group (where restored tabs start after
/// the app is killed, the android/service map, and new tabs, the android/terminal map): the leader's, or any process in the group's once the
/// leader has exited; the path is relative to that process's root (as its `/proc/<pid>/cwd` is).
/// ESRCH when there is no foreground process group (the shell has exited).
pub(crate) fn fg_cwd(k: &Kernel, id: u32) -> Result<Vec<u8>, Errno> {
    let fg = fg_pgrp(k, id)?;
    let (tgid, tid) = fg_member(k, fg)?;
    let task = k.tasks.get(&tid).ok_or(Errno::ESRCH)?;
    let (root, cwd) = {
        let res = task.res.borrow();
        let fs = res.fs.borrow();
        (fs.root.clone(), fs.cwd.clone())
    };
    let vfs = k.vfs.as_ref().ok_or(Errno::ENOENT)?;
    let view = crate::pseudo::View {
        k,
        vfs,
        tid,
        tgid,
        cred: None,
        opening: false,
    };
    vfs.path_of(&view, &root, &cwd)
}

/// Whether the console's line discipline reads whole lines without echoing them (ICANON on, ECHO
/// off), as programs set it while reading a password: the app then draws the cursor as a lock, as
/// Ghostty does by the same rule (the android/vtview map).
pub(crate) fn password_input(k: &Kernel, id: u32) -> Result<bool, Errno> {
    let lflag = tty_of(k, id)?.borrow().termios.lflag;
    Ok(lflag & (ICANON | ECHO) == ICANON)
}

/// The window size changed: updates the PTY and sends SIGWINCH to the foreground process group.
pub(crate) fn resize(k: &Kernel, id: u32, w: Winsize) -> Result<(), Errno> {
    let tty = tty_of(k, id)?;
    let (changed, fg) = {
        let mut t = tty.borrow_mut();
        (std::mem::replace(&mut t.winsize, w) != w, t.fg)
    };
    if let (true, Some(fg)) = (changed, fg) {
        signal::send_to_pgrp(k, fg, Signal::WINCH, SigInfo::kernel());
    }
    Ok(())
}

/// Closes a console: as when Linux hangs up a terminal, sends SIGHUP and SIGCONT to the session
/// leader. Afterwards the slave reads EOF and writes fail.
pub(crate) fn close(k: &mut Kernel, id: u32) -> Result<(), Errno> {
    let console = k.consoles.remove(&id).ok_or(Errno::ENOENT)?;
    let tty = console.master.tty.clone();
    drop(console);
    crate::syscall::hang_up(k, &tty);
    request_wake();
    Ok(())
}

// ---- The appine-run bridge ----

/// A terminal attached to the host ([`RunOptions::terminal`](crate::RunOptions::terminal)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terminal {
    /// Host fd that keyboard input is read from.
    pub input: i32,
    /// Host fd that terminal output is written to.
    pub output: i32,
    /// Host terminal whose window size is followed (TIOCGWINSZ); without one the window size is
    /// 24×80.
    pub size: Option<i32>,
    /// Host fd that becomes readable when the window size changes (for example a pipe written by
    /// a SIGWINCH handler).
    pub resize: Option<i32>,
}

const POLLIN: i16 = 1;
/// How much input to read from the host at a time.
const READ_CHUNK: usize = 4096;

/// The EOF handed to the program after the host's input ends ([`send_eof`]).
#[derive(Clone, Copy, PartialEq)]
enum Eof {
    /// Input has not ended yet.
    Open,
    /// Input has ended; waiting for the program to read the input already sent in.
    Pending,
    Sent,
}

/// The host terminal's current window size; 24×80 when it is not a terminal.
pub(crate) fn initial_size(term: &Terminal) -> Winsize {
    term.size.and_then(host_winsize).unwrap_or_default()
}

/// The bridge thread of `appine-run`: connects the host terminal to console `id` until process
/// `pid` ends, all guest threads have exited and the output has been written.
pub(crate) fn bridge(shared: Arc<Shared>, term: Terminal, id: u32, pid: Tid) {
    let event = Arc::new(Event::new().expect("cannot create an eventfd for the terminal"));
    let mut eof = Eof::Open;
    let mut buf = vec![0u8; READ_CHUNK];
    let mut k = shared.lock();
    loop {
        match take_output(&k, id, 64 * 1024) {
            Ok(Some(out)) if !out.is_empty() => {
                drop(k);
                write_all(term.output, &out);
                k = shared.lock();
                continue;
            }
            // The console has closed, or all slaves have closed and the output has been taken
            Err(_) | Ok(Some(_)) => break,
            Ok(None) => {}
        }
        if k.watched.get(&pid).is_some_and(Option::is_some) && k.tasks.is_empty() {
            break;
        }
        if eof == Eof::Pending && send_eof(&k, id) {
            eof = Eof::Sent;
        }
        let room = input_room(&k, id).unwrap_or(0);
        let mut fds = Vec::new();
        if eof == Eof::Open && room > 0 {
            fds.push((term.input, POLLIN, 0));
        }
        if let Some(r) = term.resize {
            fds.push((r, POLLIN, 0));
        }
        let objects = wake_objects(&k, id);
        let (k2, _) = block_for(
            &shared,
            k,
            &event,
            None,
            &mut fds,
            wake::ALL,
            objects.as_deref(),
        );
        k = k2;
        for (fd, _, revents) in fds {
            if revents == 0 {
                continue;
            }
            if fd == term.input {
                drop(k);
                let n = appine_hal::read(fd, &mut buf[..room.min(READ_CHUNK)]);
                k = shared.lock();
                match n {
                    Ok(n) if n > 0 => {
                        let _ = feed(&k, id, &buf[..n]);
                    }
                    // The host's input has ended (stdin is a pipe or file): stop reading, and once
                    // the program has read the input already sent in, hand it an EOF
                    _ => eof = Eof::Pending,
                }
            } else {
                appine_hal::drain(fd);
                if let Some(w) = term.size.and_then(host_winsize) {
                    let _ = resize(&k, id, w);
                }
            }
        }
    }
}

/// Writes all the data to the host fd; drops it when the host side has closed.
fn write_all(fd: i32, mut data: &[u8]) {
    while !data.is_empty() {
        match appine_hal::write(fd, data) {
            Ok(0) | Err(_) => return,
            Ok(n) => data = &data[n..],
        }
    }
}

/// After the host's input ends, sends a VEOF (^D) into the console's input, as util-linux's
/// script does: in canonical mode a VEOF at the start of a line makes read return 0, so programs
/// that end at EOF, such as a shell or cat, exit; outside canonical mode the program receives the
/// character (a shell's line editor treats it as EOF). As script does, it waits until the program
/// has read the input already sent in: while that is unread it returns false, and the console's
/// PTY wakes the bridge thread when the program reads input. A program that leaves canonical mode
/// before reading the EOF gets the VEOF character ([`Tty::inject_eof`]). Sends nothing when VEOF
/// is disabled.
fn send_eof(k: &Kernel, id: u32) -> bool {
    let Ok(tty) = tty_of(k, id) else {
        return true;
    };
    if tty.borrow().input_pending() {
        return false;
    }
    let signals = tty.borrow_mut().inject_eof();
    request_wake_object(wake::of(&tty));
    let fg = tty.borrow().fg;
    if let Some(fg) = fg {
        for sig in signals {
            signal::send_to_pgrp(k, fg, sig, SigInfo::kernel());
        }
    }
    true
}

/// The host terminal's window size.
fn host_winsize(fd: i32) -> Option<Winsize> {
    const TIOCGWINSZ: u64 = 0x5413;
    let mut b = [0u8; 8];
    appine_hal::ioctl(fd, TIOCGWINSZ, &mut b).ok()?;
    let w = Winsize::decode(&b);
    (w.rows > 0 && w.cols > 0).then_some(w)
}

// ---- Shared helpers ----

fn tty_of(k: &Kernel, id: u32) -> Result<Rc<RefCell<Tty>>, Errno> {
    k.consoles
        .get(&id)
        .map(|c| c.master.tty.clone())
        .ok_or(Errno::ENOENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::Tier;

    #[test]
    fn feed_returns_eio_after_console_session_ends() {
        let mut k = Kernel::new(Tier::Interpreter);
        let id = open(&mut k, Winsize::default());
        // Before any session attaches, input is accepted.
        assert!(!ended(&k, id).unwrap());
        feed(&k, id, b"pre").unwrap();
        let _ = take_output(&k, id, 64).unwrap();

        // Attach a session leader and then close its slave fd (session ended).
        let (slave, _tty) = attach(&mut k, id, 10).unwrap();
        assert!(!ended(&k, id).unwrap());
        feed(&k, id, b"a").unwrap();
        assert_eq!(take_output(&k, id, 64).unwrap(), Some(b"a".to_vec()));

        drop(slave);
        assert!(ended(&k, id).unwrap());
        assert_eq!(feed(&k, id, b"after"), Err(Errno::EIO));
        // Echoes must not have been produced after session end.
        assert_eq!(take_output(&k, id, 64).unwrap(), Some(Vec::new()));
    }

    #[test]
    fn interactive_shell_classification_covers_shells_and_commands() {
        let check = |comm: &str, argv: &[&[u8]]| is_interactive_shell(comm, argv);
        // Interactive shells (login, non-login, options, busybox applet form).
        assert!(check("ash", &[b"-ash"]));
        assert!(check("ash", &[b"/bin/ash", b"-l"]));
        assert!(check("sh", &[b"/bin/sh"]));
        assert!(check("dash", &[b"dash", b"-i"]));
        assert!(check("bash", &[b"bash", b"--rcfile", b"/tmp/rc", b"-i"]));
        assert!(check("sh", &[b"sh", b"-o", b"vi"]));
        assert!(check("ash", &[b"busybox", b"ash", b"-l"]));
        assert!(check("sh", &[b"sh", b"-s", b"arg1"]));
        assert!(check("sh", &[b"sh", b"--"]));
        assert!(check("mksh", &[]));
        assert!(check("tcsh", &[b"-tcsh"]));
        assert!(check("elvish", &[b"/usr/bin/elvish"]));

        // Non-interactive shells and regular commands.
        assert!(!check("sh", &[b"sh", b"-c", b"sleep 5"]));
        assert!(!check("sh", &[b"sh", b"-lc", b"echo hi"]));
        assert!(!check("bash", &[b"bash", b"build.sh"]));
        assert!(!check("sh", &[b"sh", b"--", b"script.sh"]));
        assert!(!check("fish", &[b"fish", b"--command", b"sleep 1"]));
        assert!(!check("sleep", &[b"busybox", b"sleep", b"5"]));
        assert!(!check("sleep", &[b"sleep", b"0.2"]));
        assert!(!check("doas", &[b"doas", b"-s"]));
        assert!(!check("su", &[b"su", b"alice", b"-c", b"exec sh -l"]));
        assert!(!check("ssh", &[b"ssh", b"example.com"]));
    }
}
