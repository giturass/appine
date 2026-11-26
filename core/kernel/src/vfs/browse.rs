//! The host browsing the store (the app's DocumentsProvider, the android/documents map): without
//! going through the kernel, looks up guest paths, lists directories and opens files directly in
//! the store, and creates, writes, removes, renames and moves inside the app's home directory.
//!
//! What it sees is the store as it is, that is, what it looks like when the kernel is not running:
//! mounts (procfs, `/dev`, the `/run` tmpfs, bind mounts) are all ignored, and `/proc` and the
//! like are empty directories in the store. Symlinks are followed, and absolute paths count from
//! the guest's root, the same as seen in the guest. Only directories and regular files are given:
//! device nodes, FIFOs, sockets and broken symlinks are not listed and cannot be opened (a host
//! read of a FIFO would wait forever).
//!
//! Guest permissions are not checked: everything in the store belongs to the app's user anyway,
//! and `doas` in the terminal can see all of it too.

use std::fs::File;

use super::store::{Ino, ROOT, Stat, Store, mode};
use crate::errno::Errno;

// ---- Reads ----

/// An entry in a directory: the name and its metadata (after following symlinks).
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Vec<u8>,
    pub stat: Stat,
}

/// The metadata of a path (following symlinks). ENOENT for anything but directories and regular
/// files.
pub fn stat(store: &Store, path: &[u8]) -> Result<Stat, Errno> {
    let st = store.stat(resolve(store, path)?)?;
    if !shown(&st) {
        return Err(Errno::ENOENT);
    }
    Ok(st)
}

/// Lists directory `dir`, sorted by name. Symlinks give their target's metadata; broken ones and
/// ones pointing at special files are not listed.
pub fn list(store: &Store, dir: &[u8]) -> Result<Vec<Entry>, Errno> {
    let ino = resolve(store, dir)?;
    if store.kind(ino)? != mode::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    let mut out = Vec::new();
    for e in store.readdir(ino)? {
        let st = match e.mode & mode::S_IFMT {
            mode::S_IFLNK => {
                let mut path = dir.to_vec();
                path.push(b'/');
                path.extend_from_slice(&e.name);
                match resolve(store, &path).and_then(|i| store.stat(i)) {
                    Ok(st) => st,
                    Err(_) => continue,
                }
            }
            _ => match store.stat(e.ino) {
                Ok(st) => st,
                Err(_) => continue,
            },
        };
        if shown(&st) {
            out.push(Entry {
                name: e.name,
                stat: st,
            });
        }
    }
    Ok(out)
}

/// Only directories and regular files are shown to the host.
fn shown(st: &Stat) -> bool {
    matches!(st.kind(), mode::S_IFDIR | mode::S_IFREG)
}

/// Opens a regular file for reading: returns the object file on the host. EISDIR for a directory.
pub fn open(store: &Store, path: &[u8]) -> Result<File, Errno> {
    let ino = resolve(store, path)?;
    match store.kind(ino)? {
        mode::S_IFREG => store.open_object(ino, false),
        mode::S_IFDIR => Err(Errno::EISDIR),
        _ => Err(Errno::ENOENT),
    }
}

/// How many bytes at the start of a file [`looks_like_text`] looks at.
const SNIFF_BYTES: usize = 4096;

/// The regular file the path points at looks like text ([`is_text`]): the Files app uses this when
/// it cannot guess the type from the extension (`/etc/profile`, `.bashrc`, scripts, `Makefile`);
/// text is treated as text/plain, so that editors can open it. False for directories and files
/// that cannot be opened.
pub fn looks_like_text(store: &Store, path: &[u8]) -> bool {
    let Ok(file) = open(store, path) else {
        return false;
    };
    let mut head = [0u8; SNIFF_BYTES];
    let mut n = 0;
    while n < head.len() {
        match std::io::Read::read(&mut &file, &mut head[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    is_text(&head[..n], n < head.len())
}

/// The start of a file, `head`, looks like text: no NUL and valid UTF-8, close to how git decides
/// a file is binary (it only looks for NUL). When the end of the file was not reached (`whole`
/// false), the last character may be cut off. Empty files count too. Text in other encodings such
/// as Latin-1 does not count.
pub fn is_text(head: &[u8], whole: bool) -> bool {
    if head.contains(&0) {
        return false;
    }
    match std::str::from_utf8(head) {
        Ok(_) => true,
        Err(e) => !whole && e.error_len().is_none(),
    }
}

/// Finds entries below directory `dir` (not including itself) whose names contain `query`
/// (case-insensitive), at most `limit` of them, breadth first: shallower ones first. Returns the
/// paths (built starting from `dir`) and metadata. Does not enter directories that symlinks point
/// at, to avoid going in circles; looks at most at `budget` entries, so it does not keep searching
/// forever in a large tree.
pub fn search(
    store: &Store,
    dir: &[u8],
    query: &str,
    limit: usize,
    budget: usize,
) -> Result<Vec<(Vec<u8>, Stat)>, Errno> {
    let query = query.to_lowercase();
    let root = resolve(store, dir)?;
    let mut queue = std::collections::VecDeque::from([(root, dir.to_vec())]);
    let mut out = Vec::new();
    let mut seen = 0;
    while let Some((ino, path)) = queue.pop_front() {
        for e in store.readdir(ino)? {
            seen += 1;
            if seen > budget {
                return Ok(out);
            }
            let mut child = path.clone();
            if !child.ends_with(b"/") {
                child.push(b'/');
            }
            child.extend_from_slice(&e.name);
            if e.mode & mode::S_IFMT == mode::S_IFDIR {
                queue.push_back((e.ino, child.clone()));
            }
            if !String::from_utf8_lossy(&e.name)
                .to_lowercase()
                .contains(&query)
            {
                continue;
            }
            if let Ok(st) = stat(store, &child) {
                out.push((child, st));
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
    }
    Ok(out)
}

// ---- Changes (only inside the app's home directory) ----
//
// All writes are confined to `top` (the home directory of the app's login account): counted by
// real path, so getting outside through a symlink is not allowed (EACCES). The entry being removed
// or renamed is itself not followed (what is removed is the link, not what it points at); the
// directory it is in is followed.

/// What the host changed in the store ([`crate::browse_changing`]): handed to the running kernel
/// that uses the same store, which reports inotify events as the corresponding syscall would, so
/// programs watching in the guest (editors, build tools' watch modes) learn that the Files app
/// changed a file. Directories and names are inodes and dentries in the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// `name` was created in directory `dir`.
    Created {
        dir: Ino,
        name: Vec<u8>,
        is_dir: bool,
    },
    /// `name` in directory `dir` was removed (it was `ino`). A whole directory tree is removed
    /// entry by entry, inside first.
    Removed {
        dir: Ino,
        name: Vec<u8>,
        ino: Ino,
        is_dir: bool,
    },
    /// `ino` moved from `from` to `to` (directory and name), without overwriting.
    Moved {
        from: (Ino, Vec<u8>),
        to: (Ino, Vec<u8>),
        ino: Ino,
        is_dir: bool,
    },
    /// Regular file `ino` (named `parent.1` in directory `parent.0`) was opened for writing,
    /// truncated if `truncated`; with `unshared` it shared its object until then and now has one
    /// of its own, which its open descriptions must follow.
    Opened {
        ino: Ino,
        parent: (Ino, Vec<u8>),
        truncated: bool,
        unshared: bool,
    },
    /// The object switch committed but the subsequent provider open failed.
    Unshared(Ino),
    /// A regular file opened for writing was closed: something was written (the other side
    /// writes the host object directly, and the kernel does not see each write).
    Written { ino: Ino, parent: (Ino, Vec<u8>) },
}

/// The last numbered alternative after the requested name is taken.
const MAX_NAME_SUFFIX: u32 = 100;

/// Creates a file (0644) or directory (0755) in directory `dir` inside `top`, owned by `uid` and
/// `gid`. When the name is taken another one is used ([`numbered`]); returns the name actually
/// used.
pub fn create(
    store: &Store,
    top: &[u8],
    dir: &[u8],
    name: &[u8],
    directory: bool,
    (uid, gid): (u32, u32),
    changes: &mut Vec<Change>,
) -> Result<Vec<u8>, Errno> {
    check_name(name)?;
    let (dir, name) = store.transaction(|s| {
        let dir = dir_in(s, top, dir)?;
        let name = with_available_name(name, directory, |candidate| {
            if directory {
                s.mkdir(dir, candidate, 0o755, uid, gid).map(drop)
            } else {
                s.create_file(dir, candidate, 0o644, uid, gid).map(drop)
            }
        })?;
        Ok((dir, name))
    })?;
    changes.push(Change::Created {
        dir,
        name: name.clone(),
        is_dir: directory,
    });
    Ok(name)
}

/// Streams one file into a detached directory, then publishes it in the account's home.
/// The open store pins the staging directory during the copy. Boot reclaims it after a crash.
pub fn import_file(
    store: &Store,
    home: &[u8],
    name: &[u8],
    (uid, gid): (u32, u32),
    fill: impl FnOnce(&File) -> Result<(), Errno>,
    changes: &mut Vec<Change>,
) -> Result<Vec<u8>, Errno> {
    check_name(name)?;
    let (dir, stage, ino, file) = store.transaction(|s| {
        let (dir, _) = top_of(s, home)?;
        let stage = s.create_detached_dir(0o700, uid, gid)?;
        let (ino, file) = s.create_file(stage, b"data", 0o644, uid, gid)?;
        Ok((dir, stage, ino, file))
    })?;
    // Release the SQLite writer even when this is the only connection. A provider may block.
    store.commit()?;
    let copy_and_publish = || -> Result<_, Errno> {
        fill(&file)?;
        file.sync_all()
            .map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
        let name = store.transaction(|s| {
            let (current_dir, _) = top_of(s, home)?;
            if current_dir != dir {
                return Err(Errno::ESTALE);
            }
            let name = with_available_name(name, false, |candidate| {
                s.rename(stage, b"data", dir, candidate, true, false)
            })?;
            s.remove_detached_dir(stage)?;
            Ok(name)
        })?;
        store.commit()?;
        Ok(name)
    };
    let name = copy_and_publish().inspect_err(|_| {
        // A failed cleanup leaves only a detached tree for boot to reclaim.
        let _ = store.remove_detached_dir(stage);
    })?;
    let parent = (dir, name.clone());
    changes.push(Change::Created {
        dir,
        name: name.clone(),
        is_dir: false,
    });
    changes.push(Change::Opened {
        ino,
        parent: parent.clone(),
        truncated: false,
        unshared: false,
    });
    changes.push(Change::Written { ino, parent });
    Ok(name)
}

fn with_available_name(
    name: &[u8],
    directory: bool,
    mut install: impl FnMut(&[u8]) -> Result<(), Errno>,
) -> Result<Vec<u8>, Errno> {
    for n in 0..=MAX_NAME_SUFFIX {
        let candidate = if n == 0 {
            name.to_vec()
        } else {
            numbered(name, n, directory)
        };
        check_name(&candidate)?;
        match install(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(Errno::EEXIST) => continue,
            Err(e) => return Err(e),
        }
    }
    Err(Errno::EEXIST)
}

/// The name to use when a name is taken: `a (1).txt` for a file (the extension stays last),
/// `a (1)` for a directory.
fn numbered(name: &[u8], n: u32, directory: bool) -> Vec<u8> {
    let dot = name
        .iter()
        .rposition(|&b| b == b'.')
        .filter(|&i| i > 0 && !directory);
    let (stem, ext) = name.split_at(dot.unwrap_or(name.len()));
    let mut out = stem.to_vec();
    out.extend_from_slice(format!(" ({n})").as_bytes());
    out.extend_from_slice(ext);
    out
}

/// Removes a file, a symlink or a whole directory tree inside `top` (for a symlink, only the
/// link).
pub fn remove(
    store: &Store,
    top: &[u8],
    path: &[u8],
    changes: &mut Vec<Change>,
) -> Result<(), Errno> {
    let mut removed = Vec::new();
    store.transaction(|s| {
        let (dir, name) = entry_in(s, top, path)?;
        remove_tree(s, dir, &name, &mut removed)?;
        s.retire_document(dir, &name)
    })?;
    changes.extend(removed);
    Ok(())
}

fn remove_tree(
    store: &Store,
    dir: Ino,
    name: &[u8],
    changes: &mut Vec<Change>,
) -> Result<(), Errno> {
    let ino = store.lookup(dir, name)?.ok_or(Errno::ENOENT)?;
    let is_dir = store.kind(ino)? == mode::S_IFDIR;
    if is_dir {
        for e in store.readdir(ino)? {
            remove_tree(store, ino, &e.name, changes)?;
        }
        store.rmdir(dir, name)?;
    } else {
        store.unlink(dir, name)?;
    }
    changes.push(Change::Removed {
        dir,
        name: name.to_vec(),
        ino,
        is_dir,
    });
    Ok(())
}

/// Renames within the same directory; EEXIST if the new name is taken, without overwriting.
pub fn rename(
    store: &Store,
    top: &[u8],
    path: &[u8],
    new_name: &[u8],
    changes: &mut Vec<Change>,
) -> Result<(), Errno> {
    check_name(new_name)?;
    let change = store.transaction(|s| {
        let (dir, name) = entry_in(s, top, path)?;
        if name == new_name {
            return Ok(None);
        }
        moved(s, (dir, &name), (dir, new_name)).map(Some)
    })?;
    changes.extend(change);
    Ok(())
}

/// Moves to another directory `to` inside `top`, keeping the name; EEXIST if it is already there,
/// EINVAL for moving a directory into itself.
pub fn move_to(
    store: &Store,
    top: &[u8],
    path: &[u8],
    to: &[u8],
    changes: &mut Vec<Change>,
) -> Result<(), Errno> {
    let change = store.transaction(|s| {
        let (dir, name) = entry_in(s, top, path)?;
        let to = dir_in(s, top, to)?;
        moved(s, (dir, &name), (to, &name))
    })?;
    changes.push(change);
    Ok(())
}

/// A new name: not empty, `.` or `..`, no `/` or NUL, at most 255 bytes.
fn check_name(name: &[u8]) -> Result<(), Errno> {
    if name.is_empty() || name == b"." || name == b".." || name.contains(&b'/') || name.contains(&0)
    {
        return Err(Errno::EINVAL);
    }
    if name.len() > NAME_MAX {
        return Err(Errno::ENAMETOOLONG);
    }
    Ok(())
}

/// The maximum name length, the same as Linux's `NAME_MAX`.
const NAME_MAX: usize = 255;

/// An entry to remove, rename or move away: its directory is inside `top`, and the name itself is
/// not followed. `top` itself is not allowed.
fn entry_in(store: &Store, top: &[u8], path: &[u8]) -> Result<(Ino, Vec<u8>), Errno> {
    let comps: Vec<Vec<u8>> = components(path).collect();
    let (name, dirs) = comps.split_last().ok_or(Errno::EACCES)?;
    if name == b".." {
        return Err(Errno::EINVAL);
    }
    let dir = dir_in(store, top, &join(dirs))?;
    store.lookup(dir, name)?.ok_or(Errno::ENOENT)?;
    Ok((dir, name.clone()))
}

/// Directory `dir` inside `top` (following symlinks).
fn dir_in(store: &Store, top: &[u8], dir: &[u8]) -> Result<Ino, Errno> {
    let (_, top) = top_of(store, top)?;
    let (ino, real) = walk(store, dir)?;
    if store.kind(ino)? != mode::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    if !real.starts_with(&top) {
        return Err(Errno::EACCES);
    }
    Ok(ino)
}

/// Moves `ino` from `from` to `to` (without overwriting) and records it.
fn moved(store: &Store, from: (Ino, &[u8]), to: (Ino, &[u8])) -> Result<Change, Errno> {
    let ino = store.lookup(from.0, from.1)?.ok_or(Errno::ENOENT)?;
    let is_dir = store.kind(ino)? == mode::S_IFDIR;
    store.rename(from.0, from.1, to.0, to.1, true, false)?;
    if from != to {
        store.retire_document(from.0, from.1)?;
    }
    Ok(Change::Moved {
        from: (from.0, from.1.to_vec()),
        to: (to.0, to.1.to_vec()),
        ino,
        is_dir,
    })
}

/// Opens a regular file inside `top` for reading and writing (following symlinks; the file pointed
/// at must also be inside `top`), truncating it first with `truncate` and opening with `O_APPEND`
/// with `append`. Returns the object on the host, recorded as written by the host until
/// [`written`] reports the close by the same `path` ([`Store::host_opened`]).
pub fn open_write(
    store: &Store,
    top: &[u8],
    path: &[u8],
    truncate: bool,
    append: bool,
    changes: &mut Vec<Change>,
) -> Result<File, Errno> {
    let (ino, parent, file, unshared) = store.transaction(|s| {
        let (ino, parent) = writable_file(s, top, path)?;
        let (file, unshared) = s.open_provider_object(ino, truncate, append)?;
        Ok((ino, parent, file, unshared))
    })?;
    let finish = || {
        if truncate {
            store.truncate_host_object(&file)?;
        }
        store.host_opened(ino, path)
    };
    if let Err(e) = finish() {
        if unshared {
            changes.push(Change::Unshared(ino));
        }
        return Err(e);
    }
    changes.push(Change::Opened {
        ino,
        parent,
        truncated: truncate,
        unshared,
    });
    Ok(file)
}

/// A file opened by [`open_write`] was closed (the other side writes to the host object, not
/// through here): its object may be shared again, and [`Change::Written`] is recorded, unless the
/// file was removed or moved away in the meantime.
pub fn written(
    store: &Store,
    top: &[u8],
    path: &[u8],
    changes: &mut Vec<Change>,
) -> Result<(), Errno> {
    store.host_closed(path);
    let (ino, parent) = store.snapshot(|s| writable_file(s, top, path))?;
    changes.push(Change::Written { ino, parent });
    Ok(())
}

/// Regular file `path` inside `top` (following symlinks; the file pointed at must also be inside
/// `top`): its inode, and the directory and name it has on its real path.
fn writable_file(store: &Store, top: &[u8], path: &[u8]) -> Result<(Ino, (Ino, Vec<u8>)), Errno> {
    let (_, top) = top_of(store, top)?;
    let (ino, mut real) = walk(store, path)?;
    if !real.starts_with(&top) {
        return Err(Errno::EACCES);
    }
    match store.kind(ino)? {
        mode::S_IFREG => {}
        mode::S_IFDIR => return Err(Errno::EISDIR),
        _ => return Err(Errno::ENOENT),
    }
    let name = real.pop().ok_or(Errno::EISDIR)?;
    let dir = resolve(store, &join(&real))?;
    Ok((ino, (dir, name)))
}

/// Resolves the provider's write boundary to a directory in a login home tree.
fn top_of(store: &Store, top: &[u8]) -> Result<(Ino, Vec<Vec<u8>>), Errno> {
    if !top.starts_with(b"/") || top.contains(&0) {
        return Err(Errno::EACCES);
    }
    let (ino, real) = walk(store, top)?;
    if store.kind(ino)? != mode::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    let allowed = match real.first().map(Vec::as_slice) {
        Some(b"root") => true,
        Some(b"home") => real.len() >= 2,
        None
        | Some(
            b"bin" | b"sbin" | b"usr" | b"lib" | b"lib64" | b"etc" | b"proc" | b"sys" | b"dev"
            | b"run" | b"boot" | b"var" | b"tmp" | b"opt" | b"srv" | b"mnt" | b"media"
            | b"lost+found",
        ) => false,
        Some(_) => custom_home(store, &real)?,
    };
    if allowed {
        Ok((ino, real))
    } else {
        Err(Errno::EACCES)
    }
}

// The caller has already excluded protected first components. A nonempty canonical
// home that prefixes this path therefore cannot authorize a protected tree.
fn custom_home(store: &Store, real: &[Vec<u8>]) -> Result<bool, Errno> {
    use std::io::{BufRead, BufReader};
    let passwd = match super::open_config_file(store, b"/etc/passwd") {
        Ok(file) => file,
        Err(Errno::ENOENT | Errno::ENOTDIR | Errno::EINVAL) => return Ok(false),
        Err(e) => return Err(e),
    };
    for line in BufReader::new(passwd).split(b'\n') {
        let line = line.map_err(|e| Errno(e.raw_os_error().unwrap_or(Errno::EIO.0)))?;
        if let Some(home) = login_home(&line)
            && let Ok((_, home)) = walk(store, home)
            && !home.is_empty()
            && real.starts_with(&home)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn login_home(line: &[u8]) -> Option<&[u8]> {
    let mut fields = line
        .strip_suffix(b"\r")
        .unwrap_or(line)
        .split(|&b| b == b':');
    let name = fields.next()?;
    let uid = fields.nth(1)?;
    let home = fields.nth(2)?;
    let shell = fields.next()?;
    if name.is_empty()
        || line.contains(&0)
        || fields.next().is_some()
        || !home.starts_with(b"/")
        || !uid.iter().all(u8::is_ascii_digit)
        || std::str::from_utf8(uid).ok()?.parse::<u32>().ok()? < 1000
        || matches!(
            shell,
            b"" | b"/sbin/nologin"
                | b"/usr/sbin/nologin"
                | b"/bin/false"
                | b"/usr/bin/false"
                | b"/sbin/false"
        )
    {
        return None;
    }
    Some(home)
}

// ---- Paths for the host ----

/// The path of directory `dir` in the store (found by climbing the parent and name each directory
/// records). ENOENT for deleted directories and ones not under the root directory (tmpfs roots).
pub fn dir_path(store: &Store, dir: Ino) -> Result<Vec<u8>, Errno> {
    let mut comps = Vec::new();
    let mut cur = dir;
    while cur != ROOT {
        let up = store.parent(cur)?;
        if up == cur || comps.len() > 4096 {
            return Err(Errno::ENOENT);
        }
        comps.push(store.name_of(up, cur)?.ok_or(Errno::ENOENT)?);
        cur = up;
    }
    comps.reverse();
    Ok(join(&comps))
}

/// A guest path → a string on the host (Java) side (the app's document ID): valid UTF-8 parts
/// stay as they are, and `%`, control characters and non-UTF-8 bytes are written as `%XX`, so
/// [`decode_path`] turns it back exactly and it contains no tabs or newlines (the JNI side uses
/// one line per entry, separated by tabs).
pub fn encode_path(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            if c == '%' || c.is_control() {
                let mut buf = [0u8; 4];
                for b in c.encode_utf8(&mut buf).bytes() {
                    let _ = write!(out, "%{b:02X}");
                }
            } else {
                out.push(c);
            }
        }
        for b in chunk.invalid() {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The reverse of [`encode_path`]; a `%` not followed by two ASCII hex digits is kept as it is.
pub fn decode_path(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%'
            && let Some(&[hi, lo]) = b.get(i + 1..i + 3)
            && let (Some(hi), Some(lo)) = (hex_digit(hi), hex_digit(lo))
        {
            out.push((hi << 4) | lo);
            i += 3;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ---- Path resolution ----

/// The limit on the number of symlinks followed, the same as Linux's `MAXSYMLINKS`.
const MAX_LINKS: usize = 40;

/// Finds the inode for a guest path, following all symlinks (including in the last component).
/// `..` at the root directory stays put.
pub fn resolve(store: &Store, path: &[u8]) -> Result<Ino, Errno> {
    walk(store, path).map(|(ino, _)| ino)
}

/// [`resolve`], also giving the components of the real path (with every symlink replaced by where
/// it points, like realpath).
fn walk(store: &Store, path: &[u8]) -> Result<(Ino, Vec<Vec<u8>>), Errno> {
    walk_with(store, path, |_, _| Ok(()))
}

/// SAF identifiers retain the original path until a provider mutation retires an entry traversed
/// by the walk. Include intermediate symlinks and their targets, even across an absolute link.
pub fn document_generations(store: &Store, paths: &[Vec<u8>]) -> Result<Vec<u64>, Errno> {
    store.snapshot(|s| {
        if !s.has_retired_documents()? {
            return Ok(vec![0; paths.len()]);
        }
        paths
            .iter()
            .map(|path| {
                let mut newest = 0;
                let r = walk_with(s, path, |dir, name| {
                    newest = newest.max(s.document_generation(dir, name)?);
                    Ok(())
                });
                match r {
                    Ok(_) | Err(Errno::ENOENT | Errno::ENOTDIR | Errno::ELOOP) => Ok(newest),
                    Err(e) => Err(e),
                }
            })
            .collect()
    })
}

fn walk_with(
    store: &Store,
    path: &[u8],
    mut visit: impl FnMut(Ino, &[u8]) -> Result<(), Errno>,
) -> Result<(Ino, Vec<Vec<u8>>), Errno> {
    // The components not walked yet, in reverse (the top of the stack is the next one); following
    // a symlink pushes the target's components
    let mut pending: Vec<Vec<u8>> = components(path).rev().collect();
    // The directories reached: the components of the real path and their inodes (going back one
    // level for `..` is the real parent)
    let mut real: Vec<Vec<u8>> = Vec::new();
    let mut inos: Vec<Ino> = Vec::new();
    let mut links = 0;
    while let Some(name) = pending.pop() {
        let dir = inos.last().copied().unwrap_or(ROOT);
        if store.kind(dir)? != mode::S_IFDIR {
            return Err(Errno::ENOTDIR);
        }
        if name == b".." {
            real.pop();
            inos.pop();
            continue;
        }
        visit(dir, &name)?;
        let ino = store.lookup(dir, &name)?.ok_or(Errno::ENOENT)?;
        if store.kind(ino)? == mode::S_IFLNK {
            links += 1;
            if links > MAX_LINKS {
                return Err(Errno::ELOOP);
            }
            let target = store.readlink(ino)?;
            if target.starts_with(b"/") {
                real.clear();
                inos.clear();
            }
            pending.extend(components(&target).rev());
            continue;
        }
        real.push(name);
        inos.push(ino);
    }
    Ok((inos.last().copied().unwrap_or(ROOT), real))
}

/// The components of a path, dropping empty ones and `.`.
fn components(path: &[u8]) -> impl DoubleEndedIterator<Item = Vec<u8>> + '_ {
    path.split(|&b| b == b'/')
        .filter(|c| !c.is_empty() && *c != b".")
        .map(<[u8]>::to_vec)
}

/// Joins components into an absolute path.
fn join(comps: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    for c in comps {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    if out.is_empty() {
        out.push(b'/');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn sample(name: &str) -> (Store, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("appine-browse-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let s = Store::create(&dir).unwrap();
        let home = s.mkdir(ROOT, b"home", 0o755, 0, 0).unwrap();
        let alice = s.mkdir(home, b"alice", 0o700, 1000, 1000).unwrap();
        let docs = s.mkdir(alice, b"Docs", 0o755, 1000, 1000).unwrap();
        let etc = s.mkdir(ROOT, b"etc", 0o755, 0, 0).unwrap();
        s.create_file(etc, b"motd", 0o644, 0, 0)
            .unwrap()
            .1
            .write_all(b"welcome\n")
            .unwrap();
        s.create_file(docs, b"Notes.txt", 0o644, 1000, 1000)
            .unwrap()
            .1
            .write_all(b"hello")
            .unwrap();
        s.symlink(alice, b"motd", b"/etc/motd", 1000, 1000).unwrap();
        s.symlink(alice, b"up", b"..", 1000, 1000).unwrap();
        s.symlink(alice, b"rel", b"Docs/../Docs/Notes.txt", 1000, 1000)
            .unwrap();
        s.symlink(alice, b"broken", b"/nowhere", 1000, 1000)
            .unwrap();
        s.symlink(alice, b"loop", b"loop", 1000, 1000).unwrap();
        s.mknod(alice, b"fifo", mode::S_IFIFO | 0o644, 0, 1000, 1000)
            .unwrap();
        (s, dir)
    }

    #[test]
    fn provider_tops_are_resolved_home_directories() {
        let (s, dir) = sample("tops");
        let mkdir = |parent, name: &[u8]| s.mkdir(parent, name, 0o755, 0, 0).unwrap();
        let root = mkdir(ROOT, b"root");
        mkdir(root, b"100% home");
        let users = mkdir(ROOT, b"users");
        let bob = mkdir(users, b"bob");
        mkdir(bob, b"sub");
        mkdir(users, b"svc");
        mkdir(users, b"daemon");
        mkdir(users, b"bob2");
        let etc = resolve(&s, b"/etc").unwrap();
        mkdir(etc, b"custom");
        for name in [b"usr".as_slice(), b"bin", b"sbin", b"var", b"tmp"] {
            mkdir(ROOT, name);
        }
        for (name, target) in [
            (b"system".as_slice(), b"/etc".as_slice()),
            (b"all", b"/"),
            (b"homes", b"/home"),
            (b"bob-home", b"/users/bob"),
        ] {
            s.symlink(ROOT, name, target, 0, 0).unwrap();
        }
        assert_eq!(top_of(&s, b"/users/bob"), Err(Errno::EACCES));
        super::super::write_file(
            &s,
            b"/etc/passwd",
            b"bob:x:1000:1::/bob-home:/bin/sh\n\
            daemon:x:2:2::/sbin:/bin/sh\nsystem:x:2:2::/users/daemon:/bin/sh\n\
            nobody:x:65534:1::/:/bin/sh\nsvc:x:1000:1::/users/svc:/sbin/nologin\n\
            admin:x:1000:1::/system/custom:/bin/sh\n",
            0o644,
            true,
        )
        .unwrap();
        for top in [
            b"/root".as_slice(),
            b"/root/100% home",
            b"/home/alice",
            b"/home/alice/Docs",
            b"/users/bob",
            b"/users/bob/sub",
        ] {
            assert!(top_of(&s, top).is_ok(), "{top:?}");
        }
        for top in [
            b"".as_slice(),
            b"/",
            b"/home",
            b"/etc",
            b"/usr",
            b"/bin",
            b"/sbin",
            b"/var",
            b"/tmp",
            b"home/alice",
            b"/home/alice\0",
            b"/system",
            b"/all",
            b"/homes",
            b"/users/svc",
            b"/users/daemon",
            b"/users/bob2",
            b"/etc/custom",
        ] {
            assert_eq!(top_of(&s, top), Err(Errno::EACCES), "{top:?}");
        }
        assert_eq!(top_of(&s, b"/missing"), Err(Errno::ENOENT));
        assert_eq!(top_of(&s, b"/etc/motd"), Err(Errno::ENOTDIR));
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn provider_revalidates_custom_home_on_publication_and_writer_close() {
        let (s, dir) = sample("custom-home-changes");
        let users = s.mkdir(ROOT, b"users", 0o755, 0, 0).unwrap();
        let bob = s.mkdir(users, b"bob", 0o700, 1000, 1000).unwrap();
        let top = b"/users/bob";
        let path = b"/users/bob/data";
        let ino = s.create_file(bob, b"data", 0o644, 1000, 1000).unwrap().0;
        let passwd = |data: &[u8]| super::super::write_file(&s, b"/etc/passwd", data, 0o644, true);
        passwd(b"bob:x:1000:1000::/users/bob:/bin/sh\n").unwrap();
        let mut changes = Vec::new();
        let file = open_write(&s, top, path, false, false, &mut changes).unwrap();
        assert!(s.host_writing(ino).unwrap());
        changes.clear();
        assert_eq!(
            import_file(
                &s,
                top,
                b"pending",
                (1000, 1000),
                |_| passwd(b""),
                &mut changes
            ),
            Err(Errno::EACCES)
        );
        assert!(changes.is_empty());
        assert_eq!(s.lookup(bob, b"pending"), Ok(None));
        drop(file);
        assert_eq!(written(&s, top, path, &mut changes), Err(Errno::EACCES));
        assert!(!s.host_writing(ino).unwrap());
        assert!(changes.is_empty());
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn retired_document_ids_follow_aliases_and_survive_reopen() {
        let (s, dir) = sample("document-ids");
        let top = b"/home/alice";
        let source = b"/home/alice/Docs";
        let paths = [
            b"/home/alice/Docs/Notes.txt".to_vec(),
            b"/home/alice/rel".to_vec(),
            b"/home/alice/motd".to_vec(),
        ];
        let mut changes = Vec::new();
        rename(&s, top, source, b"Docs", &mut changes).unwrap();
        assert_eq!(
            rename(&s, top, source, b"motd", &mut changes),
            Err(Errno::EEXIST)
        );
        assert_eq!(document_generations(&s, &paths).unwrap(), [0, 0, 0]);
        rename(&s, top, source, b"moved", &mut changes).unwrap();
        rename(&s, top, b"/home/alice/moved", b"Docs", &mut changes).unwrap();
        let first = document_generations(&s, &paths).unwrap();
        assert!(first[0] > 0);
        assert_eq!(first, [first[0], first[0], 0]);
        remove(&s, top, source, &mut changes).unwrap();
        drop(s);
        let s = Store::open(&dir, &[]).unwrap();
        let next = document_generations(&s, &paths).unwrap();
        assert!(next[0] > first[0]);
        assert_eq!(next, [next[0], next[0], 0]);
        drop(s);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn paths_resolve_through_links() {
        let (s, dir) = sample("resolve");
        let notes = |p: &[u8]| {
            let mut text = String::new();
            open(&s, p).unwrap().read_to_string(&mut text).unwrap();
            text
        };
        assert_eq!(notes(b"/home/alice/Docs/Notes.txt"), "hello");
        assert_eq!(notes(b"/home/alice/rel"), "hello");
        assert_eq!(notes(b"/home/alice/motd"), "welcome\n");
        assert_eq!(notes(b"/../home/./alice//Docs/Notes.txt"), "hello");
        assert!(stat(&s, b"/home/alice/up").unwrap().is_dir());
        assert_eq!(stat(&s, b"/home/alice/broken").unwrap_err(), Errno::ENOENT);
        assert_eq!(stat(&s, b"/home/alice/loop").unwrap_err(), Errno::ELOOP);
        assert_eq!(stat(&s, b"/home/alice/fifo").unwrap_err(), Errno::ENOENT);
        assert_eq!(open(&s, b"/home/alice").unwrap_err(), Errno::EISDIR);
        assert_eq!(
            stat(&s, b"/etc/motd/x").unwrap_err(),
            Errno::ENOTDIR,
            "a file in the middle of the path"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn listings_follow_links_and_hide_special_files() {
        let (s, dir) = sample("list");
        let names: Vec<_> = list(&s, b"/home/alice")
            .unwrap()
            .into_iter()
            .map(|e| (String::from_utf8(e.name).unwrap(), e.stat.kind()))
            .collect();
        assert_eq!(
            names,
            [
                ("Docs".to_owned(), mode::S_IFDIR),
                ("motd".to_owned(), mode::S_IFREG),
                ("rel".to_owned(), mode::S_IFREG),
                ("up".to_owned(), mode::S_IFDIR),
            ]
        );
        assert_eq!(list(&s, b"/etc/motd").unwrap_err(), Errno::ENOTDIR);
        let found: Vec<_> = search(&s, b"/home", "NOTES", 10, 1000)
            .unwrap()
            .into_iter()
            .map(|(p, _)| String::from_utf8(p).unwrap())
            .collect();
        assert_eq!(found, ["/home/alice/Docs/Notes.txt"]);
        // Shallower first, stopping at the limit
        let found = search(&s, b"/", "o", 2, 1000).unwrap();
        let paths: Vec<_> = found.iter().map(|(p, _)| p.as_slice()).collect();
        assert_eq!(paths, [b"/home".as_slice(), b"/etc/motd"]);
        assert!(search(&s, b"/", "notes", 10, 3).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A file without an extension is judged text or not by its content: the Files app gives it
    /// text/plain accordingly.
    #[test]
    fn text_is_told_by_content() {
        let (s, dir) = sample("text");
        let etc = resolve(&s, b"/etc").unwrap();
        let file = |name: &[u8], data: &[u8]| {
            s.create_file(etc, name, 0o644, 0, 0)
                .unwrap()
                .1
                .write_all(data)
                .unwrap();
        };
        file(
            b"profile",
            b"export PATH=/bin\n# \xe4\xb8\xad\xe6\x96\x87\n",
        );
        file(b"empty", b"");
        file(b"elf", b"\x7fELF\x02\x01\x01\0\0\0");
        file(b"latin1", b"caf\xe9\n");
        // A long file with a Chinese character cut off at byte 4096: still text
        let mut long = vec![b'a'; SNIFF_BYTES - 1];
        long.extend_from_slice("中文".as_bytes());
        file(b"long", &long);
        assert!(looks_like_text(&s, b"/etc/profile"));
        assert!(looks_like_text(&s, b"/etc/motd"));
        assert!(looks_like_text(&s, b"/home/alice/motd"), "through a link");
        assert!(looks_like_text(&s, b"/etc/empty"));
        assert!(looks_like_text(&s, b"/etc/long"));
        assert!(!looks_like_text(&s, b"/etc/elf"));
        assert!(!looks_like_text(&s, b"/etc/latin1"));
        assert!(!looks_like_text(&s, b"/etc"), "a directory");
        assert!(!looks_like_text(&s, b"/etc/missing"));
        // A whole file that is only one cut-off character: not text
        assert!(!is_text("中".as_bytes().get(..2).unwrap(), true));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn paths_survive_the_round_trip() {
        for p in [
            b"/home/alice/Notes.txt".as_slice(),
            "/home/alice/中文 名字".as_bytes(),
            b"/tmp/100%",
            b"/tmp/tab\there\nnew line",
            b"/tmp/\xff\xfe not utf-8 \xe4\xb8",
            b"/tmp/%41",
        ] {
            let s = encode_path(p);
            assert!(!s.contains(['\t', '\n']), "{s}");
            assert_eq!(decode_path(&s), p, "{s}");
        }
        assert_eq!(encode_path(b"/a%b\tc"), "/a%25b%09c");
        assert_eq!(encode_path("中".as_bytes()), "中");
        assert_eq!(decode_path("/x%zz%4%+a%+0"), b"/x%zz%4%+a%+0");
    }

    #[test]
    fn changes_stay_inside_the_top_directory() {
        let (s, dir) = sample("write");
        let top = b"/home/alice";
        let owner = (1000, 1000);
        let mut c = Vec::new();
        let read = |p: &[u8]| {
            let mut text = String::new();
            open(&s, p).unwrap().read_to_string(&mut text).unwrap();
            text
        };
        // When the name is taken another is used; the extension stays last, and a name starting
        // with a dot has no extension
        assert_eq!(
            create(&s, top, top, b"a.txt", false, owner, &mut c).unwrap(),
            b"a.txt"
        );
        assert_eq!(
            create(&s, top, top, b"a.txt", false, owner, &mut c).unwrap(),
            b"a (1).txt"
        );
        assert_eq!(
            create(&s, top, top, b"Docs", true, owner, &mut c).unwrap(),
            b"Docs (1)"
        );
        assert_eq!(
            create(&s, top, top, b".rc", false, owner, &mut c).unwrap(),
            b".rc"
        );
        assert_eq!(
            create(&s, top, top, b".rc", false, owner, &mut c).unwrap(),
            b".rc (1)"
        );
        for bad in [b"".as_slice(), b"..", b"x/y", b"nul\0"] {
            assert_eq!(
                create(&s, top, top, bad, false, owner, &mut c).unwrap_err(),
                Errno::EINVAL
            );
        }
        let st = stat(&s, b"/home/alice/a.txt").unwrap();
        assert_eq!((st.uid, st.gid, st.mode & 0o7777), (1000, 1000, 0o644));
        let st = stat(&s, b"/home/alice/Docs (1)").unwrap();
        assert_eq!((st.uid, st.mode & 0o7777), (1000, 0o755));
        // Write; write again after truncating
        open_write(&s, top, b"/home/alice/a.txt", false, false, &mut c)
            .unwrap()
            .write_all(b"hello")
            .unwrap();
        // Append: written at the end
        open_write(&s, top, b"/home/alice/a.txt", false, true, &mut c)
            .unwrap()
            .write_all(b"!")
            .unwrap();
        assert_eq!(read(b"/home/alice/a.txt"), "hello!");
        c.clear();
        open_write(&s, top, b"/home/alice/a.txt", true, false, &mut c)
            .unwrap()
            .write_all(b"hi")
            .unwrap();
        assert_eq!(read(b"/home/alice/a.txt"), "hi");
        written(&s, top, b"/home/alice/a.txt", &mut c).unwrap();
        let a = resolve(&s, b"/home/alice/a.txt").unwrap();
        let home = resolve(&s, top).unwrap();
        let parent = (home, b"a.txt".to_vec());
        assert_eq!(
            c,
            [
                Change::Opened {
                    ino: a,
                    parent: parent.clone(),
                    truncated: true,
                    unshared: false
                },
                Change::Written { ino: a, parent }
            ]
        );
        // Outside the home directory, or getting out through a symlink: neither is allowed
        assert_eq!(
            create(&s, top, b"/etc", b"x", false, owner, &mut c).unwrap_err(),
            Errno::EACCES
        );
        let motd = b"/home/alice/motd";
        assert_eq!(
            open_write(&s, top, motd, true, false, &mut c).unwrap_err(),
            Errno::EACCES
        );
        assert_eq!(read(b"/etc/motd"), "welcome\n");
        assert_eq!(
            remove(&s, top, b"/home/alice/up/alice", &mut c).unwrap_err(),
            Errno::EACCES
        );
        assert_eq!(remove(&s, top, top, &mut c).unwrap_err(), Errno::EACCES);
        assert_eq!(
            move_to(&s, top, b"/home/alice/a.txt", b"/etc", &mut c).unwrap_err(),
            Errno::EACCES
        );
        // A home of `/`, literally or through a link, does not make the whole system writable
        for root in [b"/".as_slice(), b"/home/alice/up/.."] {
            assert_eq!(
                create(&s, root, b"/etc", b"x", false, owner, &mut c).unwrap_err(),
                Errno::EACCES
            );
            assert_eq!(
                open_write(&s, root, b"/etc/motd", true, false, &mut c).unwrap_err(),
                Errno::EACCES
            );
            assert_eq!(
                remove(&s, root, b"/etc/motd", &mut c).unwrap_err(),
                Errno::EACCES
            );
        }
        assert_eq!(read(b"/etc/motd"), "welcome\n");
        // Removing a symlink removes only the link
        remove(&s, top, motd, &mut c).unwrap();
        assert_eq!(stat(&s, motd).unwrap_err(), Errno::ENOENT);
        assert_eq!(read(b"/etc/motd"), "welcome\n");
        // Renaming does not overwrite
        let a1 = b"/home/alice/a (1).txt";
        assert_eq!(
            rename(&s, top, a1, b"a.txt", &mut c).unwrap_err(),
            Errno::EEXIST
        );
        assert_eq!(
            rename(&s, top, a1, b"x/y", &mut c).unwrap_err(),
            Errno::EINVAL
        );
        rename(&s, top, a1, b"b.txt", &mut c).unwrap();
        assert!(stat(&s, b"/home/alice/b.txt").is_ok());
        // Move; a directory cannot be moved into itself
        move_to(&s, top, b"/home/alice/b.txt", b"/home/alice/Docs", &mut c).unwrap();
        assert!(stat(&s, b"/home/alice/Docs/b.txt").is_ok());
        assert_eq!(
            move_to(&s, top, b"/home/alice/Docs", b"/home/alice/Docs", &mut c).unwrap_err(),
            Errno::EINVAL
        );
        // Remove a whole directory tree
        c.clear();
        remove(&s, top, b"/home/alice/Docs", &mut c).unwrap();
        assert_eq!(stat(&s, b"/home/alice/Docs").unwrap_err(), Errno::ENOENT);
        // The recorded changes: inside first
        let home = resolve(&s, top).unwrap();
        let Some((
            Change::Removed {
                dir: parent,
                name,
                ino: docs,
                is_dir: true,
            },
            inside,
        )) = c.split_last()
        else {
            panic!("{c:?}");
        };
        assert_eq!((*parent, name.as_slice()), (home, b"Docs".as_slice()));
        assert!(
            inside
                .iter()
                .any(|x| matches!(x, Change::Removed { name, .. } if name == b"b.txt"))
        );
        assert!(
            inside
                .iter()
                .all(|x| matches!(x, Change::Removed { dir, is_dir: false, .. } if dir == docs))
        );
        remove(&s, top, b"/home/alice/fifo", &mut c).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
