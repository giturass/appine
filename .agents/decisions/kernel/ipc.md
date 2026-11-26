# System V IPC and message queues (kernel/ipc) Decisions

> Snapshot of current consensus. Evolution: `git log --grep="MODULE: kernel/ipc"`
>
> Last distilled: 2026-11-24 (HEAD = 231480cb)

## Active

### D1: SysV IPC and POSIX message queues are one kernel/ipc module
- **What**: kernel/ipc owns the per-namespace object model, the 12 SysV syscalls and the six `mq_*` syscalls with `MessageQueue`, while the IPC namespace lifecycle stays in kernel/process, shm host memory and VMAs in kernel/mm, mqueue node views and sysctls in kernel/procfs, and mqueue mounts and file-syscall dispatch in kernel/vfs.
- **Why**: About 2300 lines in `ipc.rs`, `syscall/ipc.rs` and `syscall/mqueue.rs` had no module, so no map described them and their bugs had nowhere to be recorded.
- **Tradeoffs**: Message-queue behaviour is spread over four maps (readiness in kernel/poll too), and the map's Linux comparisons come from recalled upstream source.
- **Watch out**: `RLIMIT_MSGQUEUE` remains unenforced in the map's bug list (earlier open items for sibling `SEM_UNDO`, `/proc/sysvipc` pid translation, `semmns`/`shmall` and bare-tgid `mq_notify` registrations are now resolved by D9 and D11).
- **Source**: 4140c75 (bug list since updated by 5d23297, b43ff37, 5d7b936, 2aca260, b51818cf and 15347732)

### D2: mremap duplicates of shm segments count as attachments
- **What**: A copy made by mremap with an old length of 0 tags its shm segment with its own start, so nattch counts it and shmdt at its address detaches it (kernel/mm D21).
- **Why**: Linux counts a duplicated segment VMA as another attachment through its `vm_ops` open.
- **Tradeoffs**: None.
- **Watch out**: None known.
- **Source**: 5dcf7db

### D3: Message-queue timeouts stay on the realtime clock
- **What**: mq_timedsend and mq_timedreceive keep their absolute `CLOCK_REALTIME` timeout as an `Expiry` on the realtime base (kernel/process D19).
- **Why**: Their timeouts are absolute realtime times, which fired late once turned into monotonic instants.
- **Tradeoffs**: None.
- **Watch out**: None known.
- **Source**: 63b9e59

### D4: IPC limits stay within int, and large allocations fail with ENOMEM
- **What**: msgmax, msgmnb and the four sem values refuse values above `INT_MAX` (shmmax and shmall stay unsigned longs), msgsnd, semaphore sets and semtimedop allocate through `ipc::zeroed`, which returns `ENOMEM` when the host cannot, and semtimedop takes nsops as an unsigned int.
- **Why**: After root raised these limits, any process in the namespace could abort the app with one msgsnd, semget or semtimedop allocating by them.
- **Tradeoffs**: `zeroed` touches a large message's pages before the copy, which would touch them anyway.
- **Watch out**: Allocations the host overcommits still succeed and may later be killed by the host's low-memory killer rather than fail with `ENOMEM`.
- **Source**: 09188ec

### D5: Interrupted message-queue waits restart
- **What**: mq_timedsend and mq_timedreceive return `ERESTARTSYS` when a signal interrupts their wait, so `SA_RESTART` handlers and stops resume them with the same absolute deadline (D3).
- **Why**: They returned `EINTR`, so `SA_RESTART` handlers and even stops ended the wait.
- **Tradeoffs**: None.
- **Watch out**: None known.
- **Source**: 5d23297

### D6: Closing a queue descriptor ends its process's notification registration
- **What**: `mqueue_closed(group, files)` runs at every close site (close, close_range, dup3, close-on-exec, seccomp addfd) and when a thread exit drops the last reference to its fd table, as Linux's `mqueue_flush_file` does, and `remove_notification` sends the `NOTIFY_REMOVED` cookie for `SIGEV_THREAD`, also when a stale registration is replaced.
- **Why**: A registration outlived its process's queue descriptors, so another process got `EBUSY`, and ending a `SIGEV_THREAD` registration left musl's helper thread blocked forever.
- **Tradeoffs**: Registrations now pin a weak `ThreadGroup` reference rather than bare tgid (D9).
- **Watch out**: A close path added later must call `mqueue_closed` too.
- **Source**: b43ff37

### D7: Removed shm segments are reaped where attachments end, and mqueue defaults follow the sysctls
- **What**: `reap_shm` also runs after munmap, mremap, `MAP_FIXED` mmap, execve and thread exit, and a new queue's default limits are capped by `msg_max` and `msgsize_max` as `mqueue_get_inode` does.
- **Why**: Removed shm segments stayed until the next shm call, and mqueue defaults ignored `msg_max` and `msgsize_max`.
- **Tradeoffs**: Each such call scans the marked segments once more.
- **Watch out**: None known.
- **Source**: 5d7b936

### D8: SysV capability checks go over the IPC namespace's owner
- **What**: `Ids::check` and `may_change` take the IPC namespace's owning user namespace and check `IPC_OWNER` and `SYS_ADMIN` with `ns_capable` over it, `SHM_LOCK` checks `IPC_LOCK` over it, and every SysV syscall passes the owner.
- **Why**: Root of a container could not stat or remove another user's queue in its IPC namespace, where Linux's `ipcperms` and `ipcctl_obtain_check` check those capabilities over the namespace's owner.
- **Tradeoffs**: Every call reads the owner from the task's namespace set (a cheap `Rc` clone).
- **Watch out**: Objects created before an IPC namespace switch are still checked against the namespace they are looked up in.
- **Source**: 2aca260

### D9: `/proc/sysvipc` translates PIDs and preserves `SHM_LOCKED`, and `mq_notify` pins registrant `ThreadGroup`s

- **What**: `ipc::proc_listing` takes `&PidNs` to translate PIDs with `vnr().unwrap_or(0)` and preserves `SHM_DEST | SHM_LOCKED` in shm perms, while `Notify` replaces bare `tgid` with a `Registrant` holding a weak `ThreadGroup` reference.
- **Why**: `/proc/sysvipc` leaked global PIDs across pid namespaces and masked out `SHM_LOCKED`, and bare-tgid `mq_notify` registrations let a dead registrant whose fd table survived via `CLONE_FILES` block or signal a later process reusing that tgid.
- **Tradeoffs**: `Notify` stores a `Weak<RefCell<ThreadGroup>>` alongside `tgid` and `mqueue::closed` takes `&Rc<RefCell<ThreadGroup>>`.
- **Watch out**: `close_replaced` (seccomp `ADDFD`) looks up `groups.get(&tgid)` before calling `mqueue_closed`, relying on `live_group` to treat an already-exited target's registration as dead.
- **Source**: b51818cf

### D10: `shmat` enforces `vm.mmap_min_addr` and `mq_open` marks descriptors pseudo

- **What**: `shmat` rejects non-zero fixed addresses failing `syscall::mem::below_min_addr` with `EPERM`, and `mq_open` sets `OpenFile::pseudo = true` on its descriptors.
- **Why**: Fixed `shmat` attachments bypassed `vm.mmap_min_addr` without `CAP_SYS_RAWIO`, and `mq_open` descriptors must stay distinct from descriptors opened on a user-visible mqueue mount so they do not block `umount2`.
- **Tradeoffs**: `OpenFile::pseudo` now marks both memfds and `mq_open` descriptors rather than memfds alone.
- **Watch out**: Callers checking `file.pseudo` must pair it with `FileKind` to distinguish `Regular` memfds from `MessageQueue` descriptors.
- **Source**: 0e02d7cd

### D11: `SEM_UNDO` follows `CLONE_SYSVSEM`, `semmns`/`shmall` are enforced, and mqueue ops check `mq_dir` permissions

- **What**: `TaskState::sem_undo` holds a shared `Rc<SemUndo>` (shared only under `CLONE_SYSVSEM` and applied on `unshare`/`setns`/exit only when the last sharer leaves), `semget`/`shmget` enforce `semmns` and `shmall` with `ENOSPC`, and `mq_open`/`remove_queue`/`unlink_mq` check `mq_dir` `MAY_EXEC`/`MAY_WRITE` and gate sticky checks on `S_ISVTX`.
- **Why**: Keying `SEM_UNDO` by `tgid` let one thread's `unshare` or `setns` wipe sibling threads' adjustments, `semmns` and `shmall` were unenforced, and mqueue open/unlink ignored `mq_dir` permissions while enforcing sticky ownership unconditionally.
- **Tradeoffs**: `semget` and `shmget` scan used slots in the namespace table to sum existing semaphores or pages on creation.
- **Watch out**: `RLIMIT_MSGQUEUE` remains unenforced, and `finish_group` step 4 must stay intact for `trap_finish` fault-injection tests.
- **Source**: 15347732

### D12: `mq_notify` `SIGEV_THREAD` cookies route through `NetlinkSocket::enqueue`

- **What**: `send_cookie` in `core/kernel/src/syscall/mqueue.rs` delivers `SIGEV_THREAD` cookies through `NetlinkSocket::enqueue` so they share the target socket's `SO_RCVBUF` accounting and `ENOBUFS` overrun signalling.
- **Why**: Direct queue writes let `mq_notify` `SIGEV_THREAD` cookie delivery bypass netlink `SO_RCVBUF` limits.
- **Tradeoffs**: Cookies are dropped with `ENOBUFS` when the target netlink socket's receive buffer is full, matching Linux `netlink_attachskb`.
- **Watch out**: None known.
- **Source**: a1fd0beb

## Superseded

- ~~`mq_notify` registrations stay keyed by bare `tgid` (D6's tradeoff, b43ff37)~~ → replaced by **D9** in b51818cf (2026-11-23, no SUPERSEDES declared)
