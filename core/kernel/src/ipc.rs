//! System V IPC (svipc(7)): the kernel objects for message queues, semaphore sets and shared
//! memory segments.
//!
//! Each of the three kinds of object has a table. An id is `sequence * 32768 + index`, as on
//! Linux: once an index is allocated again, the old id is no longer valid. Permissions are checked
//! by `ipc_perm` (effective user ID; `CAP_IPC_OWNER` can bypass them). A shared memory segment is
//! a piece of host memory ([`SharedMemory`]) that shmat maps into the address space; all guest
//! processes are in the same host process, so they see the same memory. How many times a segment
//! is attached is not recorded separately; the mappings in the address spaces are counted
//! instead, so fork, execve and process exit need no extra handling. For the syscalls see
//! `syscall::ipc`.

use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cred::{Cred, UserNs, cap};
use crate::errno::Errno;
use crate::kernel::{Kernel, Tid, request_wake};
use crate::mm::SharedMemory;

pub(crate) const IPC_PRIVATE: i32 = 0;
pub(crate) const IPC_CREAT: i32 = 0o1000;
pub(crate) const IPC_EXCL: i32 = 0o2000;
pub(crate) const IPC_NOWAIT: i32 = 0o4000;
/// The shared memory segment has been IPC_RMID'd and waits for its last mapping to go away
/// (recorded in mode).
pub(crate) const SHM_DEST: u32 = 0o1000;
/// The shared memory segment is locked by SHM_LOCK (recorded in mode).
pub(crate) const SHM_LOCKED: u32 = 0o2000;
/// semop's `SEM_UNDO`: this operation is undone when the process exits.
pub(crate) const SEM_UNDO: i16 = 0x1000;

/// The number of indexes (`IPCMNI`).
const IPCMNI: i32 = 32768;

/// Fixed limits, as on Linux.
pub(crate) mod limits {
    pub const SEMVMX: i32 = 32767;
    pub const SEMAEM: i32 = 32767;
    pub const SHMMIN: u64 = 1;
}

/// Limits that can be changed through `/proc/sys/kernel` (`msgmax`, `sem`, etc.), with defaults as
/// on Linux.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Tunables {
    pub msgmax: u64,
    pub msgmnb: u64,
    pub msgmni: u64,
    /// `sem`: semmsl, semmns, semopm, semmni.
    pub sem: [u64; 4],
    pub shmmax: u64,
    pub shmall: u64,
    pub shmmni: u64,
}

impl Tunables {
    /// The contents of `/proc/sys/kernel/<name>`; returns None for a file that is not one of these.
    pub fn read(&self, name: &[u8]) -> Option<String> {
        Some(match name {
            b"msgmax" => format!("{}\n", self.msgmax),
            b"msgmnb" => format!("{}\n", self.msgmnb),
            b"msgmni" => format!("{}\n", self.msgmni),
            b"sem" => {
                let [a, b, c, d] = self.sem;
                format!("{a}\t{b}\t{c}\t{d}\n")
            }
            b"shmmax" => format!("{}\n", self.shmmax),
            b"shmall" => format!("{}\n", self.shmall),
            b"shmmni" => format!("{}\n", self.shmmni),
            _ => return None,
        })
    }

    /// Writes `/proc/sys/kernel/<name>`: EINVAL when the value is not a non-negative integer, when
    /// a `*mni` exceeds IPCMNI, or when one of Linux's int sysctls (`msgmax`, `msgmnb`, `sem`)
    /// exceeds `INT_MAX` (`shmmax` and `shmall` are unsigned longs there too).
    pub fn write(&mut self, name: &[u8], data: &[u8]) -> Result<(), Errno> {
        let text = std::str::from_utf8(data).map_err(|_| Errno::EINVAL)?;
        let nums: Vec<u64> = text
            .split_whitespace()
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| Errno::EINVAL)?;
        let one = || match nums[..] {
            [v] => Ok(v),
            _ => Err(Errno::EINVAL),
        };
        let mni = |v: u64| {
            if v <= IPCMNI as u64 {
                Ok(v)
            } else {
                Err(Errno::EINVAL)
            }
        };
        // msgsnd, semget and semtimedop allocate by these, so they must not go beyond what Linux
        // allows either
        let int = |v: u64| {
            if v <= i32::MAX as u64 {
                Ok(v)
            } else {
                Err(Errno::EINVAL)
            }
        };
        match name {
            b"msgmax" => self.msgmax = int(one()?)?,
            b"msgmnb" => self.msgmnb = int(one()?)?,
            b"msgmni" => self.msgmni = mni(one()?)?,
            b"sem" => {
                let [a, b, c, d] = nums[..] else {
                    return Err(Errno::EINVAL);
                };
                self.sem = [int(a)?, int(b)?, int(c)?, mni(d)?];
            }
            b"shmmax" => self.shmmax = one()?,
            b"shmall" => self.shmall = one()?,
            b"shmmni" => self.shmmni = mni(one()?)?,
            _ => return Err(Errno::EINVAL),
        }
        Ok(())
    }
}

impl Default for Tunables {
    fn default() -> Tunables {
        Tunables {
            msgmax: 8192,
            msgmnb: 16384,
            msgmni: 32000,
            sem: [32000, 1_024_000_000, 500, 32000],
            shmmax: u64::MAX - (1 << 24),
            shmall: u64::MAX - (1 << 24),
            shmmni: 4096,
        }
    }
}

/// `struct ipc_perm`.
#[derive(Clone, Debug)]
pub(crate) struct Perm {
    pub key: i32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
    /// Permission bits (the low 9 bits) and the object's own flag bits (`SHM_DEST` etc.).
    pub mode: u32,
    pub seq: u16,
}

impl Perm {
    /// `ipcperms`: `flag` is the permission required (`S_IRUGO`, `S_IWUGO`, or the permission bits
    /// of msgget and the like); `owner` is the user namespace owning the IPC namespace, over which
    /// `CAP_IPC_OWNER` counts.
    pub fn check(&self, cred: &Cred, owner: &UserNs, flag: u32) -> Result<(), Errno> {
        let want = (flag >> 6 | flag >> 3 | flag) & 7;
        let granted = if cred.euid == self.cuid || cred.euid == self.uid {
            self.mode >> 6
        } else if cred.in_group(self.cgid) || cred.in_group(self.gid) {
            self.mode >> 3
        } else {
            self.mode
        };
        if want & !granted & 7 != 0 && !cred.ns_capable(owner, cap::IPC_OWNER) {
            return Err(Errno::EACCES);
        }
        Ok(())
    }

    /// IPC_SET, IPC_RMID: the creator, the owner, or a holder of `CAP_SYS_ADMIN` over `owner`, the
    /// user namespace owning the IPC namespace (`ipcctl_obtain_check`).
    pub fn may_change(&self, cred: &Cred, owner: &UserNs) -> Result<(), Errno> {
        if cred.euid == self.cuid || cred.euid == self.uid || cred.ns_capable(owner, cap::SYS_ADMIN)
        {
            Ok(())
        } else {
            Err(Errno::EPERM)
        }
    }

    /// Encodes as asm-generic's `struct ipc64_perm` (48 bytes), with IDs translated into the user
    /// namespace of the caller's `cred` (Linux's `kernel_to_ipc64_perm`).
    pub fn encode(&self, cred: &Cred) -> [u8; 48] {
        let mut b = [0u8; 48];
        for (i, v) in [
            self.key as u32,
            cred.uid_out(self.uid),
            cred.gid_out(self.gid),
            cred.uid_out(self.cuid),
            cred.gid_out(self.cgid),
            self.mode,
        ]
        .into_iter()
        .enumerate()
        {
            b[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
        }
        b[24..26].copy_from_slice(&self.seq.to_le_bytes());
        b
    }

    /// IPC_SET: takes the owner, group and permission bits from a `struct ipc64_perm`. Owner and
    /// group are translated into kernel IDs through the user namespace of the caller's `cred`, and
    /// an unmapped one is EINVAL (Linux's `ipc_update_perm`).
    pub fn set(&mut self, b: &[u8], cred: &Cred) -> Result<(), Errno> {
        let word = |off: usize| u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        let (Some(uid), Some(gid)) = (cred.uid_in(word(4)), cred.gid_in(word(8))) else {
            return Err(Errno::EINVAL);
        };
        self.uid = uid;
        self.gid = gid;
        self.mode = (self.mode & !0o777) | (word(20) & 0o777);
        Ok(())
    }
}

/// The table of one kind of IPC object.
pub(crate) struct Table<T> {
    slots: Vec<Option<(Perm, T)>>,
    /// The sequence number each index uses at its next allocation.
    seqs: Vec<u16>,
}

impl<T> Table<T> {
    /// The common part of msgget, semget and shmget: finds an existing object by key (`existing`
    /// does the object's own checks), or creates a new one (`create`); at most `max` (`msgmni`
    /// etc.) exist at once.
    pub fn get_or_create(
        &mut self,
        key: i32,
        flags: i32,
        (cred, owner): (&Cred, &UserNs),
        max: u64,
        existing: impl FnOnce(&T) -> Result<(), Errno>,
        create: impl FnOnce() -> Result<T, Errno>,
    ) -> Result<i32, Errno> {
        if key != IPC_PRIVATE {
            if let Some(id) = self.find(key) {
                if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 {
                    return Err(Errno::EEXIST);
                }
                let (perm, obj) = self.get(id)?;
                existing(obj)?;
                perm.check(cred, owner, flags as u32 & 0o777)?;
                return Ok(id);
            }
            if flags & IPC_CREAT == 0 {
                return Err(Errno::ENOENT);
            }
        }
        if self.len() as u64 >= max {
            return Err(Errno::ENOSPC);
        }
        let perm = Perm {
            key,
            uid: cred.euid,
            gid: cred.egid,
            cuid: cred.euid,
            cgid: cred.egid,
            mode: flags as u32 & 0o777,
            seq: 0,
        };
        let obj = create()?;
        self.insert(perm, obj)
    }

    fn find(&self, key: i32) -> Option<i32> {
        self.iter()
            .find(|(_, p, _)| p.key == key)
            .map(|(id, _, _)| id)
    }

    fn insert(&mut self, mut perm: Perm, obj: T) -> Result<i32, Errno> {
        let i = match self.slots.iter().position(Option::is_none) {
            Some(i) => i,
            None if self.slots.len() < IPCMNI as usize => {
                self.slots.push(None);
                self.seqs.push(0);
                self.slots.len() - 1
            }
            None => return Err(Errno::ENOSPC),
        };
        perm.seq = self.seqs[i];
        // The sequence number must fit in an id: (sequence * 32768 + index) must not overflow i32
        self.seqs[i] = (self.seqs[i] + 1) % (i32::MAX / IPCMNI) as u16;
        let id = perm.seq as i32 * IPCMNI + i as i32;
        self.slots[i] = Some((perm, obj));
        Ok(id)
    }

    /// The object for an id; EINVAL when there is none (including when it was removed or its index
    /// allocated again).
    pub fn get(&self, id: i32) -> Result<&(Perm, T), Errno> {
        let (i, seq) = Self::index_of(id).ok_or(Errno::EINVAL)?;
        self.slots
            .get(i)
            .and_then(Option::as_ref)
            .filter(|(p, _)| p.seq == seq)
            .ok_or(Errno::EINVAL)
    }

    pub fn get_mut(&mut self, id: i32) -> Result<&mut (Perm, T), Errno> {
        let (i, seq) = Self::index_of(id).ok_or(Errno::EINVAL)?;
        self.slots
            .get_mut(i)
            .and_then(Option::as_mut)
            .filter(|(p, _)| p.seq == seq)
            .ok_or(Errno::EINVAL)
    }

    /// Looks up by index (the `*_STAT` commands), returning the full id.
    pub fn by_index(&self, index: i32) -> Result<(i32, &(Perm, T)), Errno> {
        let slot = usize::try_from(index)
            .ok()
            .and_then(|i| self.slots.get(i))
            .and_then(Option::as_ref)
            .ok_or(Errno::EINVAL)?;
        Ok((slot.0.seq as i32 * IPCMNI + index, slot))
    }

    /// The highest index in use (the return value of `IPC_INFO` and the like).
    pub fn max_index(&self) -> i32 {
        self.slots.iter().rposition(Option::is_some).unwrap_or(0) as i32
    }

    pub fn remove(&mut self, id: i32) -> Option<(Perm, T)> {
        self.get(id).ok()?;
        let (i, _) = Self::index_of(id)?;
        request_wake();
        self.slots[i].take()
    }

    fn index_of(id: i32) -> Option<(usize, u16)> {
        (id >= 0).then_some(((id % IPCMNI) as usize, (id / IPCMNI) as u16))
    }

    /// All objects: (id, permissions, object).
    pub fn iter(&self) -> impl Iterator<Item = (i32, &Perm, &T)> {
        self.slots.iter().enumerate().filter_map(|(i, s)| {
            s.as_ref()
                .map(|(p, o)| (p.seq as i32 * IPCMNI + i as i32, p, o))
        })
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.is_some()).count()
    }
}

impl<T> Default for Table<T> {
    fn default() -> Table<T> {
        Table {
            slots: Vec::new(),
            seqs: Vec::new(),
        }
    }
}

/// One message in a message queue.
pub(crate) struct Msg {
    pub mtype: i64,
    pub text: Vec<u8>,
}

/// A message queue.
pub(crate) struct MsgQueue {
    pub msgs: VecDeque<Msg>,
    /// Queue capacity (bytes).
    pub qbytes: u64,
    /// Total bytes of the messages in the queue.
    pub cbytes: u64,
    pub stime: i64,
    pub rtime: i64,
    pub ctime: i64,
    /// The processes of the last msgsnd and msgrcv.
    pub lspid: Tid,
    pub lrpid: Tid,
}

impl MsgQueue {
    /// A new queue, with capacity `msgmnb`.
    pub fn new(qbytes: u64) -> MsgQueue {
        MsgQueue {
            msgs: VecDeque::new(),
            qbytes,
            cbytes: 0,
            stime: 0,
            rtime: 0,
            ctime: now(),
            lspid: 0,
            lrpid: 0,
        }
    }

    /// Whether a message of `len` bytes still fits (`msg_fits_queue`).
    pub fn fits(&self, len: usize) -> bool {
        self.cbytes + len as u64 <= self.qbytes && (self.msgs.len() as u64) < self.qbytes
    }

    /// The message msgrcv selects: for `mtype` 0, the first one; greater than 0, the first whose
    /// type equals it (with `except`, does not equal it); less than 0, among the messages whose
    /// type is at most `-mtype`, the first one with the lowest type.
    pub fn select(&self, mtype: i64, except: bool) -> Option<usize> {
        match mtype {
            0 => (!self.msgs.is_empty()).then_some(0),
            t if t > 0 => self.msgs.iter().position(|m| (m.mtype == t) != except),
            t => self
                .msgs
                .iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= t.saturating_neg())
                .min_by_key(|&(i, m)| (m.mtype, i))
                .map(|(i, _)| i),
        }
    }
}

/// One semop operation (`struct sembuf`).
#[derive(Clone, Copy, Debug)]
pub(crate) struct SemOp {
    pub num: u16,
    pub op: i16,
    pub flg: i16,
}

/// A semaphore set.
pub(crate) struct SemSet {
    pub vals: Vec<i32>,
    /// The process that last operated on each semaphore.
    pub pids: Vec<Tid>,
    /// The number of threads waiting for each semaphore to grow (semncnt) or become 0 (semzcnt).
    pub ncnt: Vec<u32>,
    pub zcnt: Vec<u32>,
    pub otime: i64,
    pub ctime: i64,
}

impl SemSet {
    /// ENOMEM when the host cannot allocate `n` semaphores.
    pub fn new(n: usize) -> Result<SemSet, Errno> {
        Ok(SemSet {
            vals: zeroed(n)?,
            pids: zeroed(n)?,
            ncnt: zeroed(n)?,
            zcnt: zeroed(n)?,
            otime: 0,
            ctime: now(),
        })
    }

    /// Tries to complete all operations atomically (`perform_atomic_semop`): returns `Ok(None)`
    /// when all are done; when one has to wait, changes nothing and returns its index; ERANGE when
    /// a result is out of range. `undo` is this process's undo values for this semaphore set,
    /// updated at the same time by operations with `SEM_UNDO`.
    pub fn apply(
        &mut self,
        ops: &[SemOp],
        undo: &mut Vec<i32>,
        pid: Tid,
    ) -> Result<Option<usize>, Errno> {
        let mut vals = self.vals.clone();
        let mut adj = undo.clone();
        adj.resize(vals.len(), 0);
        for (i, o) in ops.iter().enumerate() {
            let v = &mut vals[o.num as usize];
            let op = o.op as i32;
            if op == 0 && *v != 0 || op < 0 && *v + op < 0 {
                return Ok(Some(i));
            }
            *v += op;
            if *v > limits::SEMVMX {
                return Err(Errno::ERANGE);
            }
            if o.flg & SEM_UNDO != 0 {
                let a = &mut adj[o.num as usize];
                *a -= op;
                if !(-limits::SEMAEM - 1..=limits::SEMAEM).contains(a) {
                    return Err(Errno::ERANGE);
                }
            }
        }
        self.vals = vals;
        *undo = adj;
        for o in ops {
            self.pids[o.num as usize] = pid;
        }
        self.otime = now();
        request_wake();
        Ok(None)
    }
}

/// A shared memory segment.
pub(crate) struct ShmSeg {
    pub mem: SharedMemory,
    /// The size in bytes at shmget (mappings round it up to pages).
    pub size: u64,
    pub atime: i64,
    pub dtime: i64,
    pub ctime: i64,
    /// The creator, and the process of the last shmat or shmdt.
    pub cpid: Tid,
    pub lpid: Tid,
}

/// A shared memory segment: the number of the IPC namespace it is in and the segment's id (each
/// namespace numbers its ids separately).
pub(crate) type ShmKey = (u64, i32);

/// Shared SysV `SEM_UNDO` list identity (Linux's `struct sem_undo_list`): shared across tasks
/// created with `CLONE_SYSVSEM`, unshared by `unshare(CLONE_SYSVSEM | CLONE_NEWIPC)` or IPC
/// `setns`, and applied only when its last sharer leaves.
pub(crate) struct SemUndo {
    pub id: u64,
}

impl SemUndo {
    pub fn new() -> SemUndo {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        SemUndo {
            id: NEXT.fetch_add(1, Ordering::Relaxed),
        }
    }
}

/// All objects in an IPC namespace ([`crate::nsproxy::IpcNs`]): System V IPC objects and POSIX
/// message queues, and their limits.
#[derive(Default)]
pub(crate) struct Ipc {
    pub msg: Table<MsgQueue>,
    pub sem: Table<SemSet>,
    pub shm: Table<ShmSeg>,
    /// SEM_UNDO undo values: (undo list id, semaphore set) → a value per semaphore.
    pub undo: BTreeMap<(u64, i32), Vec<i32>>,
    pub tunables: Tunables,
    /// POSIX message queues, by name (`syscall::mqueue`).
    pub mqueues: BTreeMap<Vec<u8>, Rc<crate::cell::RefCell<crate::syscall::MessageQueue>>>,
    /// `/proc/sys/fs/mqueue/*`.
    pub mq_limits: crate::syscall::MqLimits,
    /// The owner and times of the mqueue filesystem's root directory.
    pub mq_dir: crate::cell::RefCell<crate::syscall::MqDir>,
}

impl Ipc {
    /// A semaphore's value was set directly by SETVAL or SETALL: every undo list's adjustment for
    /// it is cleared. `num` None means the whole set.
    pub fn clear_undo(&mut self, id: i32, num: Option<usize>) {
        for ((_, sid), adj) in self.undo.iter_mut() {
            if *sid == id {
                match num {
                    Some(n) => {
                        if let Some(a) = adj.get_mut(n) {
                            *a = 0;
                        }
                    }
                    None => adj.fill(0),
                }
            }
        }
    }

    /// Removes a semaphore set, dropping its undo values too.
    pub fn remove_sem(&mut self, id: i32) {
        self.sem.remove(id);
        self.undo.retain(|&(_, sid), _| sid != id);
    }

    /// Last sharer of undo list `undo_id` exited or left this IPC namespace: adjusts semaphores by
    /// the SEM_UNDO undo values (results clamped between 0 and SEMVMX) and records `tgid` as the
    /// last operating process.
    pub fn exit(&mut self, undo_id: u64, tgid: Tid) {
        let mine: Vec<(i32, Vec<i32>)> = self
            .undo
            .range((undo_id, i32::MIN)..=(undo_id, i32::MAX))
            .map(|(&(_, id), adj)| (id, adj.clone()))
            .collect();
        for (id, adj) in mine {
            self.undo.remove(&(undo_id, id));
            if let Ok((_, set)) = self.sem.get_mut(id) {
                for (i, a) in adj.iter().enumerate().filter(|(_, a)| **a != 0) {
                    if let Some(v) = set.vals.get_mut(i) {
                        *v = (*v + a).clamp(0, limits::SEMVMX);
                        set.pids[i] = tgid;
                    }
                }
                set.otime = now();
                request_wake();
            }
        }
    }
}

/// Frees shared memory segments marked for removal that have no mappings left (in every IPC
/// namespace).
pub(crate) fn reap_shm(k: &mut Kernel) {
    let doomed: Vec<ShmKey> = k
        .ipcs
        .iter()
        .flat_map(|(&ns, (_, ipc))| {
            ipc.shm
                .iter()
                .filter(|(_, p, _)| p.mode & SHM_DEST != 0)
                .map(move |(id, _, _)| (ns, id))
        })
        .collect();
    for key in doomed {
        if nattch(k, key) == 0 {
            k.ipc_mut(key.0).shm.remove(key.1);
        }
    }
}

/// Last sharer of undo list `undo_id` exited: applies its SEM_UNDO adjustments in every IPC
/// namespace ([`Ipc::exit`]).
pub(crate) fn exit(k: &mut Kernel, undo_id: u64, tgid: Tid) {
    for (_, ipc) in k.ipcs.values_mut() {
        ipc.exit(undo_id, tgid);
    }
}

/// Detaches the calling task from its current `SEM_UNDO` list (`unshare(CLONE_SYSVSEM |
/// CLONE_NEWIPC)` or IPC `setns`), installing a fresh list and applying the old list's adjustments
/// in the current IPC namespace only if this task was its last sharer.
pub(crate) fn leave_undo(cx: &mut crate::kernel::Cx<'_>) {
    let old = std::mem::replace(&mut cx.t.sem_undo, Rc::new(SemUndo::new()));
    if Rc::strong_count(&old) == 1 {
        let tgid = cx.tgid();
        cx.ipc_mut().exit(old.id, tgid);
    }
}

/// The contents of `/proc/sysvipc/{msg,sem,shm}` for IPC namespace `ns`, with owners and groups
/// translated into the user namespace of `reader` (Linux's `seq_user_ns`) and pids into the
/// reader's pid namespace `pid_ns` (`pid_vnr`).
pub(crate) fn proc_listing(
    k: &Kernel,
    ns: u64,
    which: &[u8],
    reader: &Cred,
    pid_ns: &crate::pidns::PidNs,
) -> String {
    use std::fmt::Write;
    let ipc = k.ipc(ns);
    let pid = |p: Tid| pid_ns.vnr(p).unwrap_or(0);
    let mut s = String::new();
    match which {
        b"msg" => {
            s.push_str("       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n");
            for (id, p, q) in ipc.msg.iter() {
                writeln!(
                    s,
                    "{:10} {:10} {:5o} {:11} {:10} {:5} {:5} {:5} {:5} {:5} {:5} {:10} {:10} {:10}",
                    p.key,
                    id,
                    p.mode & 0o777,
                    q.cbytes,
                    q.msgs.len(),
                    pid(q.lspid),
                    pid(q.lrpid),
                    reader.uid_out(p.uid),
                    reader.gid_out(p.gid),
                    reader.uid_out(p.cuid),
                    reader.gid_out(p.cgid),
                    q.stime,
                    q.rtime,
                    q.ctime
                )
                .unwrap();
            }
        }
        b"sem" => {
            s.push_str("       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n");
            for (id, p, set) in ipc.sem.iter() {
                writeln!(
                    s,
                    "{:10} {:10} {:5o} {:10} {:5} {:5} {:5} {:5} {:10} {:10}",
                    p.key,
                    id,
                    p.mode & 0o777,
                    set.vals.len(),
                    reader.uid_out(p.uid),
                    reader.gid_out(p.gid),
                    reader.uid_out(p.cuid),
                    reader.gid_out(p.cgid),
                    set.otime,
                    set.ctime
                )
                .unwrap();
            }
        }
        _ => {
            s.push_str("       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n");
            for (id, p, seg) in ipc.shm.iter() {
                writeln!(
                    s,
                    "{:10} {:10} {:5o} {:21} {:5} {:5} {:6} {:5} {:5} {:5} {:5} {:10} {:10} {:10} {:21} {:21}",
                    p.key, id, p.mode & (0o777 | SHM_DEST | SHM_LOCKED), seg.size, pid(seg.cpid), pid(seg.lpid), nattch(k, (ns, id)),
                    reader.uid_out(p.uid), reader.gid_out(p.gid), reader.uid_out(p.cuid), reader.gid_out(p.cgid), seg.atime, seg.dtime, seg.ctime,
                    seg.mem.len(), 0
                )
                .unwrap();
            }
        }
    }
    s
}

/// How many times a shared memory segment is attached: counts the mappings in all address spaces
/// (each address space counted only once).
pub(crate) fn nattch(k: &Kernel, id: ShmKey) -> u64 {
    let mut seen: Vec<*const crate::cell::RefCell<crate::mm::Mm>> = Vec::new();
    let mut n = 0;
    for t in k.tasks.values() {
        let mm = t.res.borrow().mm.clone();
        if seen.contains(&Rc::as_ptr(&mm)) {
            continue;
        }
        seen.push(Rc::as_ptr(&mm));
        n += mm.borrow().shm_attachments(id) as u64;
    }
    n
}

/// Current CLOCK_REALTIME seconds (for timestamps such as `*_stime`).
pub(crate) fn now() -> i64 {
    appine_hal::clock_gettime(0).map_or(0, |(s, _)| s)
}

/// `n` zeros, or ENOMEM when the host cannot allocate them: sizes the guest chooses (up to the
/// IPC limits) must fail the call as on Linux, not abort the app as a failed `vec!` does.
pub(crate) fn zeroed<T: Clone + Default>(n: usize) -> Result<Vec<T>, Errno> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Errno::ENOMEM)?;
    v.resize(n, T::default());
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(uid: u32) -> Cred {
        let mut c = Cred::root();
        c.setresgid(Some(uid), Some(uid), Some(uid)).unwrap();
        c.setresuid(Some(uid), Some(uid), Some(uid)).unwrap();
        c
    }

    #[test]
    fn ids_are_reused_with_a_new_sequence() {
        let root = Cred::root();
        let ns = root.user_ns.clone();
        let mut t: Table<()> = Table::default();
        let a = t
            .get_or_create(IPC_PRIVATE, 0o600, (&root, &ns), 4, |_| Ok(()), || Ok(()))
            .unwrap();
        assert_eq!(
            t.get_or_create(7, 0o600, (&root, &ns), 4, |_| Ok(()), || Ok(())),
            Err(Errno::ENOENT)
        );
        let b = t
            .get_or_create(7, IPC_CREAT | 0o640, (&root, &ns), 4, |_| Ok(()), || Ok(()))
            .unwrap();
        assert_eq!(
            t.get_or_create(
                7,
                IPC_CREAT | IPC_EXCL,
                (&root, &ns),
                4,
                |_| Ok(()),
                || Ok(())
            ),
            Err(Errno::EEXIST)
        );
        assert_eq!(
            t.get_or_create(7, 0, (&root, &ns), 4, |_| Ok(()), || Ok(())),
            Ok(b)
        );
        // Another user: no read permission
        assert_eq!(
            t.get_or_create(7, 0o400, (&user(1000), &ns), 4, |_| Ok(()), || Ok(())),
            Err(Errno::EACCES)
        );
        t.remove(a);
        assert_eq!(t.get(a).err(), Some(Errno::EINVAL));
        let c = t
            .get_or_create(IPC_PRIVATE, 0o600, (&root, &ns), 4, |_| Ok(()), || Ok(()))
            .unwrap();
        assert_ne!(c, a);
        assert_eq!(c % IPCMNI, a % IPCMNI);
    }

    #[test]
    fn msgrcv_selects_by_type() {
        let mut q = MsgQueue::new(16384);
        for t in [3, 1, 2, 1] {
            q.msgs.push_back(Msg {
                mtype: t,
                text: Vec::new(),
            });
        }
        assert_eq!(q.select(0, false), Some(0));
        assert_eq!(q.select(2, false), Some(2));
        assert_eq!(q.select(3, true), Some(1));
        assert_eq!(q.select(-2, false), Some(1));
        assert_eq!(q.select(5, false), None);
    }

    #[test]
    fn semop_is_atomic_and_undone_at_exit() {
        let mut ipc = Ipc::default();
        let root = Cred::root();
        let id = ipc
            .sem
            .get_or_create(
                IPC_PRIVATE,
                0o600,
                (&root, &root.user_ns),
                4,
                |_| Ok(()),
                || SemSet::new(2),
            )
            .unwrap();
        let mut undo = Vec::new();
        let set = &mut ipc.sem.get_mut(id).unwrap().1;
        let up = |num, op| SemOp {
            num,
            op,
            flg: SEM_UNDO,
        };
        assert_eq!(set.apply(&[up(0, 2), up(1, 1)], &mut undo, 10), Ok(None));
        // The second operation has to wait: the first takes no effect either
        assert_eq!(
            set.apply(&[up(0, -1), up(1, -2)], &mut undo, 10),
            Ok(Some(1))
        );
        assert_eq!(set.vals, vec![2, 1]);
        assert_eq!(
            set.apply(
                &[SemOp {
                    num: 0,
                    op: i16::MAX,
                    flg: 0
                }],
                &mut undo,
                10
            ),
            Err(Errno::ERANGE)
        );
        ipc.undo.insert((10, id), undo);
        ipc.exit(10, 10);
        assert_eq!(ipc.sem.get(id).unwrap().1.vals, vec![0, 0]);
    }

    #[test]
    fn sem_undo_exit_is_scoped_to_undo_list_id() {
        let mut ipc = Ipc::default();
        let root = Cred::root();
        let user_ns = root.user_ns.clone();
        let id = ipc
            .sem
            .get_or_create(
                77,
                IPC_CREAT | 0o600,
                (&root, &user_ns),
                16,
                |_| Ok(()),
                || SemSet::new(1),
            )
            .unwrap();
        let mut u1 = vec![0i32; 1];
        let mut u2 = vec![0i32; 1];
        {
            let (_, s) = ipc.sem.get_mut(id).unwrap();
            s.apply(
                &[SemOp {
                    num: 0,
                    op: 3,
                    flg: SEM_UNDO,
                }],
                &mut u1,
                10,
            )
            .unwrap();
            s.apply(
                &[SemOp {
                    num: 0,
                    op: 5,
                    flg: SEM_UNDO,
                }],
                &mut u2,
                20,
            )
            .unwrap();
        }
        ipc.undo.insert((1, id), u1);
        ipc.undo.insert((2, id), u2);
        assert_eq!(ipc.sem.get(id).unwrap().1.vals, vec![8]);
        // Exiting undo list 1 reverts only its +3 adjustment, leaving list 2's +5 intact
        ipc.exit(1, 10);
        assert_eq!(ipc.sem.get(id).unwrap().1.vals, vec![5]);
        assert!(ipc.undo.contains_key(&(2, id)));
        ipc.exit(2, 20);
        assert_eq!(ipc.sem.get(id).unwrap().1.vals, vec![0]);
        assert!(ipc.undo.is_empty());
    }

    #[test]
    fn int_sysctls_stop_at_int_max() {
        let mut t = Tunables::default();
        assert_eq!(t.write(b"msgmax", b"2147483647\n"), Ok(()));
        assert_eq!(t.msgmax, i32::MAX as u64);
        assert_eq!(t.write(b"msgmax", b"2147483648\n"), Err(Errno::EINVAL));
        assert_eq!(
            t.write(b"msgmnb", b"18446744073709551615"),
            Err(Errno::EINVAL)
        );
        assert_eq!(t.write(b"sem", b"1 1 2147483648 1"), Err(Errno::EINVAL));
        assert_eq!(t.write(b"sem", b"2147483647 2 3 4"), Ok(()));
        assert_eq!(t.sem, [i32::MAX as u64, 2, 3, 4]);
        // Unsigned longs on Linux too
        assert_eq!(t.write(b"shmmax", b"18446744073709551615"), Ok(()));
    }

    #[test]
    fn proc_listing_translates_pids_and_shows_shm_locked() {
        let mut k = Kernel::new(crate::process::Tier::Interpreter);
        let ns_id = k.init_ns.ipc.id;
        let root = Cred::root();
        let user_ns = root.user_ns.clone();

        let msg_id = k
            .ipc_mut(ns_id)
            .msg
            .get_or_create(
                111,
                IPC_CREAT | 0o600,
                (&root, &user_ns),
                16,
                |_| Ok(()),
                || Ok(MsgQueue::new(16384)),
            )
            .unwrap();
        {
            let (_, q) = k.ipc_mut(ns_id).msg.get_mut(msg_id).unwrap();
            q.lspid = 42;
            q.lrpid = 99;
        }

        let shm_id = k
            .ipc_mut(ns_id)
            .shm
            .get_or_create(
                222,
                IPC_CREAT | 0o600,
                (&root, &user_ns),
                16,
                |_| Ok(()),
                || {
                    Ok(ShmSeg {
                        mem: SharedMemory::new(4096)?,
                        size: 4096,
                        atime: 0,
                        dtime: 0,
                        ctime: 0,
                        cpid: 42,
                        lpid: 99,
                    })
                },
            )
            .unwrap();
        k.ipc_mut(ns_id).shm.get_mut(shm_id).unwrap().0.mode |= SHM_LOCKED;

        // Global tid 42 is local pid 7 in child_ns; global tid 99 is invisible (0)
        let init_pid_ns = crate::pidns::PidNs::init();
        let child_pid_ns = crate::pidns::PidNs::child(&init_pid_ns, user_ns);
        crate::pidns::PidNs::register(&child_pid_ns, 42, &[7]).unwrap();

        let msg_out = proc_listing(&k, ns_id, b"msg", &root, &child_pid_ns);
        let msg_cols: Vec<&str> = msg_out.lines().nth(1).unwrap().split_whitespace().collect();
        assert_eq!(msg_cols[5], "7");
        assert_eq!(msg_cols[6], "0");

        let shm_out = proc_listing(&k, ns_id, b"shm", &root, &child_pid_ns);
        let shm_cols: Vec<&str> = shm_out.lines().nth(1).unwrap().split_whitespace().collect();
        assert_eq!(shm_cols[2], "2600");
        assert_eq!(shm_cols[4], "7");
        assert_eq!(shm_cols[5], "0");
    }
}
