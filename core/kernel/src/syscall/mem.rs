//! Memory syscalls (the kernel/mm map; process_mrelease: the kernel/oom map).

use std::os::fd::AsRawFd;
use std::rc::Rc;

use appine_engine::{PAGE_SIZE, VA_BITS, prot};

use super::SysResult;
use crate::cred::cap;
use crate::errno::Errno;
use crate::fd::{FileKind, OpenFile};
use crate::kernel::Cx;
use crate::mm::{FileSource, Fill, Mm, MsyncStep, MsyncTarget, PopulateStep, PopulateWalk, flags};
use crate::vfs::dev::Device;
use crate::vfs::ms;

const PROT_MASK: u32 = prot::READ | prot::WRITE | prot::EXEC;
/// `PROT_GROWSDOWN`, `PROT_GROWSUP`: mmap ignores them as Linux does; mprotect with
/// `PROT_GROWSDOWN` extends the range to the bottom of a grows-down mapping ([`Mm::protect`]).
///
/// [`Mm::protect`]: crate::mm::Mm::protect
const PROT_GROWS: u32 = 0x0100_0000 | 0x0200_0000;
/// Mapping type bits: `MAP_SHARED`, `MAP_PRIVATE`, `MAP_SHARED_VALIDATE`.
const MAP_TYPE: u32 = 0x0f;
const MAP_SHARED_VALIDATE: u32 = 0x03;
/// Flags MAP_SHARED_VALIDATE recognises (Linux's `LEGACY_MAP_MASK` plus `MAP_FIXED_NOREPLACE`,
/// `MAP_UNINITIALIZED`, and the page-size bits of MAP_HUGETLB).
const MAP_VALIDATE_KNOWN: u32 = MAP_TYPE
    | flags::MAP_FIXED
    | flags::MAP_ANONYMOUS
    | 0x0100 // MAP_GROWSDOWN
    | 0x0800 // MAP_DENYWRITE
    | 0x1000 // MAP_EXECUTABLE
    | 0x2000 // MAP_LOCKED
    | 0x4000 // MAP_NORESERVE
    | 0x8000 // MAP_POPULATE
    | 0x1_0000 // MAP_NONBLOCK
    | 0x2_0000 // MAP_STACK
    | 0x4_0000 // MAP_HUGETLB
    | flags::MAP_FIXED_NOREPLACE
    | 0x400_0000 // MAP_UNINITIALIZED
    | 0xfc00_0000; // page-size bits above MAP_HUGE_SHIFT
const F_SEAL_WRITE: u32 = 0x8;
const F_SEAL_FUTURE_WRITE: u32 = 0x10;
const MADV_NORMAL: i32 = 0;
const MADV_RANDOM: i32 = 1;
const MADV_SEQUENTIAL: i32 = 2;
const MADV_WILLNEED: i32 = 3;
const MADV_DONTNEED: i32 = 4;
const MADV_REMOVE: i32 = 9;
const MADV_DONTFORK: i32 = 10;
const MADV_DOFORK: i32 = 11;
const MADV_FREE: i32 = 8;
const MADV_DONTDUMP: i32 = 16;
const MADV_DODUMP: i32 = 17;
const MADV_WIPEONFORK: i32 = 18;
const MADV_KEEPONFORK: i32 = 19;
const MADV_COLD: i32 = 20;
const MADV_PAGEOUT: i32 = 21;
const MADV_POPULATE_READ: i32 = 22;
const MADV_POPULATE_WRITE: i32 = 23;
const MADV_DONTNEED_LOCKED: i32 = 24;
const MCL_CURRENT: u32 = 1;
const MCL_FUTURE: u32 = 2;
const MCL_ONFAULT: u32 = 4;

pub(super) fn mmap(
    cx: &mut Cx<'_>,
    addr: u64,
    len: u64,
    prot: u32,
    flags: u32,
    fd: i32,
    offset: u64,
) -> SysResult {
    // arm64's PROT_BTI and PROT_MTE are rejected here too: the guest does not see those features
    if prot & !(PROT_MASK | PROT_GROWS) != 0 {
        return Err(Errno::EINVAL);
    }
    let mut prot = prot & PROT_MASK;
    // READ_IMPLIES_EXEC: a readable mapping is executable too, unless it is a file on a noexec
    // mount (do_mmap)
    let implies_exec = prot & prot::READ != 0 && read_implies_exec(cx);
    if !offset.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::EINVAL);
    }
    let kind = match flags & MAP_TYPE {
        // MAP_SHARED_VALIDATE requires every flag to be recognised (MAP_SYNC works only on DAX
        // files)
        MAP_SHARED_VALIDATE if flags & !MAP_VALIDATE_KNOWN != 0 => {
            return Err(Errno::EOPNOTSUPP);
        }
        MAP_SHARED_VALIDATE => flags::MAP_SHARED,
        k @ (flags::MAP_SHARED | flags::MAP_PRIVATE) => k,
        _ => return Err(Errno::EINVAL),
    };
    let mut flags = (flags & !MAP_TYPE) | kind;
    // Shared anonymous memory cannot grow down
    let growsdown = flags & flags::MAP_GROWSDOWN != 0;
    if growsdown && flags & flags::MAP_ANONYMOUS != 0 && kind == flags::MAP_SHARED {
        return Err(Errno::EINVAL);
    }
    // A shared mapping of /dev/zero opened read-only: no write permission, now or later
    let mut deny_write = false;
    // The path and inode shown for a file mapping in /proc/<pid>/maps, and the mount it came from
    let mut label = None;
    let mut file_mnt = None;
    let mut deny_exec = false;
    let low =
        flags & (flags::MAP_FIXED | flags::MAP_FIXED_NOREPLACE) != 0 && below_min_addr(cx, addr);
    // FUSE mappings share a sparse host file populated on demand (crate::mm::Fill).
    let mut gpu_mapping = None;
    let mut fuse_fill = None;
    let mut mapping_object = None;
    let mut accessed = None;
    let mut file_source = None;
    let file = if flags & flags::MAP_ANONYMOUS != 0 {
        if low && len != 0 {
            return Err(Errno::EPERM);
        }
        if implies_exec {
            prot |= prot::EXEC;
        }
        None
    } else {
        let file = cx.fds().get(fd)?;
        // Linux checks the fd first (EBADF), then the length (EINVAL), the address (EPERM), and
        // the file's permissions (EACCES) last
        if len == 0 {
            return Err(Errno::EINVAL);
        }
        if low {
            return Err(Errno::EPERM);
        }
        if implies_exec && !on_noexec(cx, &file.borrow()) {
            prot |= prot::EXEC;
        }
        // Check access before asking the daemon for attributes.
        let shared = kind == flags::MAP_SHARED;
        let shared_write = shared && prot & prot::WRITE != 0;
        let refused = shared_write && !file.borrow().writable()
            || on_noexec(cx, &file.borrow()) && prot & prot::EXEC != 0;
        fuse_fill = super::fuse::map_fill(cx, &file, shared, refused)?;
        let mut f = file.borrow();
        match &f.kind {
            FileKind::Regular { .. } => {
                use crate::vfs::store::inode_flags;
                if !f.readable() {
                    return Err(Errno::EACCES);
                }
                if shared_write && !f.writable() {
                    return Err(Errno::EACCES);
                }
                // Files on a noexec mount cannot be mapped executable, now or later (Linux's
                // do_mmap clears VM_MAYEXEC)
                if on_noexec(cx, &f) {
                    if prot & prot::EXEC != 0 {
                        return Err(Errno::EPERM);
                    }
                    deny_exec = true;
                }
                // An overlay file opened before copy-up maps its copied-up upper object
                // (Linux 6.1's `ovl_mmap` calling `ovl_realfile`).
                if f.ovl.is_some() {
                    drop(f);
                    super::fs::follow_copy_up(cx, &file)?;
                    f = file.borrow();
                }
                let FileKind::Regular {
                    file: host, ino, ..
                } = &f.kind
                else {
                    return Err(Errno::EBADF);
                };
                label = Some((f.path.clone(), *ino));
                if !f.pseudo {
                    file_mnt = Some(f.mnt);
                }
                let inode_flags = super::fs::file_inode_flags(cx, &f)?;
                if shared && f.writable() && inode_flags & inode_flags::APPEND != 0 {
                    return Err(Errno::EACCES);
                }
                // A memfd sealed against writes cannot have a writable shared mapping, now or later
                let sealed = cx
                    .kr()
                    .seals
                    .get(ino)
                    .is_some_and(|s| s & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE) != 0);
                if shared_write && (sealed || inode_flags & inode_flags::IMMUTABLE != 0) {
                    return Err(Errno::EPERM);
                }
                let protected = inode_flags & inode_flags::PROTECTED != 0;
                let may_write = f.writable() && !(shared && (sealed || protected));
                let mut fd = host.as_raw_fd();
                let vfs = cx.vfs()?;
                let ino = *ino;
                let tmpfs_dev = f.node().and_then(|n| vfs.mapped_tmpfs_dev(&n, ino));
                if !f.pseudo {
                    drop(f);
                    let writable = shared && may_write;
                    mapping_object = loop {
                        match vfs.store().mapping_object(ino, writable) {
                            Err(Errno::EAGAIN) => super::fs::make_private(cx, ino, None)?,
                            result => break result?,
                        }
                    };
                    if let Some(object) = &mapping_object {
                        super::fs::reconcile_mapping(cx.kr(), ino, object)?;
                        fd = object.as_raw_fd();
                        file_source = Some(FileSource::PinnedStore);
                    } else {
                        f = file.borrow();
                        let FileKind::Regular { file: object, .. } = &f.kind else {
                            return Err(Errno::EBADF);
                        };
                        fd = object.as_raw_fd();
                    }
                }
                if let Some(dev) = tmpfs_dev {
                    let mapping = crate::vfs::TmpfsMapping::new(vfs, dev, ino, fd)?;
                    file_source = Some(FileSource::Tmpfs(mapping));
                }
                accessed = Some(file.clone());
                Some((fd, offset, may_write))
            }
            FileKind::Render { ino, file } => {
                if !f.readable() || (shared_write && !f.writable()) {
                    return Err(Errno::EACCES);
                }
                if !shared || prot & prot::EXEC != 0 || growsdown {
                    return Err(Errno::EINVAL);
                }
                gpu_mapping = Some(file.mapping(offset, len)?);
                label = Some((f.path.clone(), *ino));
                if !f.pseudo {
                    file_mnt = Some(f.mnt);
                }
                deny_write = !f.writable();
                None
            }
            // /dev/zero: a private mapping is anonymous memory, a shared one is shared anonymous
            // memory
            FileKind::Device {
                dev: Device::Zero, ..
            } => {
                if !f.readable() {
                    return Err(Errno::EACCES);
                }
                if shared && !f.writable() {
                    if prot & prot::WRITE != 0 {
                        return Err(Errno::EACCES);
                    }
                    deny_write = true;
                }
                flags |= flags::MAP_ANONYMOUS;
                None
            }
            FileKind::Fuse(h) => {
                if !f.readable() || shared_write && !f.writable() {
                    return Err(Errno::EACCES);
                }
                if on_noexec(cx, &f) {
                    if prot & prot::EXEC != 0 {
                        return Err(Errno::EPERM);
                    }
                    deny_exec = true;
                }
                let Some(fill) = &fuse_fill else {
                    return Err(Errno::EIO);
                };
                let ino = cx.vfs()?.fuse().get(h.id).map_or(0, |n| n.attr.ino);
                label = Some((f.path.clone(), ino));
                file_mnt = Some(f.mnt);
                Some((fill.fd(), offset, f.writable()))
            }
            FileKind::Path(_) => return Err(Errno::EBADF),
            _ => return Err(Errno::ENODEV),
        }
    };
    if let Some(aligned) = len.checked_next_multiple_of(PAGE_SIZE).filter(|&l| l != 0) {
        let map_locked = flags & flags::MAP_LOCKED != 0;
        if map_locked && cx.memlock_limit() == 0 {
            // Linux 6.1 `do_mmap`: MAP_LOCKED checks `can_do_mlock` before `mlock_future_check`.
            return Err(Errno::EPERM);
        }
        if map_locked || cx.mm().lock_future {
            check_memlock_future(cx, aligned)?;
        }
    }
    let start = if let Some(mapping) = gpu_mapping {
        cx.mm_mut().mmap_gpu(addr, len, prot, flags, mapping)?
    } else if let Some(fill) = &fuse_fill {
        cx.mm_mut()
            .mmap_fill(addr, len, prot, flags, (fill.clone(), offset))?
    } else {
        cx.mm_mut().map(addr, len, prot, flags, file, file_source)?
    };
    drop(mapping_object);
    if let Some(file) = accessed {
        super::fs::file_accessed(cx, &file.borrow());
    }
    // MAP_FIXED may have replaced a segment's last attachment
    if flags & flags::MAP_FIXED != 0 {
        crate::ipc::reap_shm(cx.k());
    }
    if let Some((name, ino)) = label {
        cx.mm_mut().label(start, len, name, ino);
    }
    if let Some(mnt) = file_mnt {
        cx.mm_mut().set_mnt(start, len, mnt);
    }
    if deny_write {
        cx.mm_mut().deny_write(start, len);
    }
    if deny_exec {
        cx.mm_mut().deny_exec(start, len);
    }
    if flags & flags::MAP_LOCKED != 0 {
        cx.mm_mut().set_locked(start, len, true)?;
    }
    // MAP_POPULATE (not with MAP_NONBLOCK), MAP_LOCKED and mlockall(MCL_FUTURE) all bring the
    // pages into memory
    const MAP_POPULATE: u32 = 0x8000;
    const MAP_NONBLOCK: u32 = 0x10000;
    let populate = flags & (MAP_POPULATE | MAP_NONBLOCK) == MAP_POPULATE
        || flags & flags::MAP_LOCKED != 0
        || cx.mm().lock_future && !cx.mm().lock_onfault;
    if populate {
        let _ = populate_range(cx, start, len, false);
    }
    Ok(start)
}

pub(super) fn mremap(
    cx: &mut Cx<'_>,
    old: u64,
    old_len: u64,
    new_len: u64,
    flags: u32,
    new_addr: u64,
) -> SysResult {
    // `Mm::insert_vma`, `Mm::move_range` and `Mm::munmap` keep `shared_maps` updated before any
    // moved or newly installed writable shared PTEs become visible to the no-BKL futex path.
    const MREMAP_MAYMOVE: u32 = 1;
    const MREMAP_FIXED: u32 = 2;
    const MREMAP_DONTUNMAP: u32 = 4;
    if flags & !(MREMAP_MAYMOVE | MREMAP_FIXED | MREMAP_DONTUNMAP) != 0
        || flags & MREMAP_FIXED != 0 && flags & MREMAP_MAYMOVE == 0
        || flags & MREMAP_DONTUNMAP != 0 && (flags & MREMAP_MAYMOVE == 0 || old_len != new_len)
    {
        return Err(Errno::EINVAL);
    }
    let fixed = (flags & MREMAP_FIXED != 0).then_some(new_addr);
    if fixed.is_some_and(|a| below_min_addr(cx, a)) {
        return Err(Errno::EPERM);
    }
    if flags & MREMAP_DONTUNMAP != 0 {
        let (new, refill) = cx.mm_mut().mremap_dontunmap(old, old_len, fixed)?;
        // MREMAP_FIXED may have unmapped a destroyed SysV segment's last attachment
        crate::ipc::reap_shm(cx.k());
        // Refill from the moved mapping's retained description, even after unlink.
        for r in refill {
            let mut mm = cx.mm_mut();
            match &r.file {
                Some(f) => {
                    let flags = flags::MAP_PRIVATE | flags::MAP_FIXED;
                    let src = Some((f.as_raw_fd(), r.offset, false));
                    mm.map(
                        r.start,
                        r.len,
                        r.prot,
                        flags,
                        src,
                        r.tmpfs.clone().map(FileSource::Tmpfs),
                    )?;
                    mm.label(r.start, r.len, r.name.clone(), r.ino);
                    if let Some(mnt) = r.mnt {
                        mm.set_mnt(r.start, r.len, mnt);
                    }
                }
                None => mm.map_anonymous(r.start, r.len, r.prot)?,
            }
            mm.apply_refill_flags(&r);
        }
        return Ok(new);
    }
    let memlock = cx.memlock_limit();
    let r = cx.mm_mut().mremap_limited(
        old,
        old_len,
        new_len,
        flags & MREMAP_MAYMOVE != 0,
        fixed,
        memlock,
    );
    // A shrunk or replaced segment attachment may have been the last one
    crate::ipc::reap_shm(cx.k());
    if let Ok(dst) = r
        && let (Some(ol), Some(nl)) = (
            old_len.checked_next_multiple_of(PAGE_SIZE),
            new_len.checked_next_multiple_of(PAGE_SIZE),
        )
        && nl > ol
        && {
            let mm = cx.mm();
            !mm.lock_onfault && mm.is_locked_at(dst + ol)
        }
    {
        let _ = populate_range(cx, dst + ol, nl - ol, false);
    }
    r
}

pub(super) fn brk(cx: &mut Cx<'_>, new: u64) -> SysResult {
    let exec = read_implies_exec(cx);
    let memlock = cx.memlock_limit();
    let (old, cur, populate) = {
        let mut mm = cx.mm_mut();
        let old = mm.brk_current();
        let cur = mm.brk_limited(new, exec, memlock);
        (old, cur, mm.lock_future && !mm.lock_onfault)
    };
    if populate
        && cur > old
        && let (Some(start), Some(end)) = (
            old.checked_next_multiple_of(PAGE_SIZE),
            cur.checked_next_multiple_of(PAGE_SIZE),
        )
        && end > start
    {
        let _ = populate_range(cx, start, end - start, false);
    }
    Ok(cur)
}

/// Reads pieces of private file mappings from their files again after `MADV_DONTNEED`
/// ([`Mm::discard_range`](crate::mm::Mm::discard_range)): zeros past the end of the file, and zeros for all of
/// a piece whose file can no longer be opened (deleted and reclaimed).
fn reread(cx: &mut Cx<'_>, rereads: Vec<crate::mm::Reread>) -> Result<(), Errno> {
    if rereads.is_empty() {
        return Ok(());
    }
    let vfs = cx.vfs()?;
    for r in rereads {
        let mut buf = vec![0u8; r.len as usize];
        if let Some(f) = (r.ino != 0)
            .then(|| vfs.store().open_object(r.ino, false).ok())
            .flatten()
        {
            let mut at = 0;
            while at < buf.len() {
                match appine_hal::pread(f.as_raw_fd(), &mut buf[at..], r.offset + at as u64) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => at += n,
                }
            }
        }
        cx.mm_mut().fill_private(r.addr, &buf);
    }
    Ok(())
}

/// remap_file_pages: deprecated, and emulated with mmap as on Linux since 4.0
/// ([`Mm::remap_file_pages`]). `prot` must be 0, and of `flags` only `MAP_NONBLOCK` is looked
/// at.
///
/// [`Mm::remap_file_pages`]: crate::mm::Mm::remap_file_pages
pub(super) fn remap_file_pages(
    cx: &mut Cx<'_>,
    start: u64,
    size: u64,
    prot: u64,
    pgoff: u64,
    flags: u32,
) -> SysResult {
    const MAP_NONBLOCK: u32 = 0x10000;
    if prot != 0 {
        return Err(Errno::EINVAL);
    }
    let start = start & !(PAGE_SIZE - 1);
    let size = size & !(PAGE_SIZE - 1);
    let offset = pgoff
        .checked_add(size / PAGE_SIZE)
        .and(pgoff.checked_mul(PAGE_SIZE))
        .ok_or(Errno::EINVAL)?;
    cx.mm_mut().remap_file_pages(start, size, offset)?;
    if flags & MAP_NONBLOCK == 0 {
        let _ = populate_range(cx, start, size, false);
    }
    Ok(0)
}

pub(super) fn mprotect(cx: &mut Cx<'_>, addr: u64, len: u64, prot: u32) -> SysResult {
    if prot & !(PROT_MASK | PROT_GROWS) != 0 || prot & PROT_GROWS == PROT_GROWS {
        return Err(Errno::EINVAL);
    }
    let implies_exec = read_implies_exec(cx);
    cx.mm_mut()
        .protect(addr, len, prot & PROT_MASK, prot & PROT_GROWS, implies_exec)
        .map(|()| 0)
}

/// The calling process has personality(2)'s `READ_IMPLIES_EXEC`: readable memory it maps
/// (mmap, mprotect, brk) is executable too where it may be.
pub(super) fn read_implies_exec(cx: &Cx<'_>) -> bool {
    cx.t.group.borrow().personality & crate::process::READ_IMPLIES_EXEC != 0
}

/// The open file is on a noexec mount (Linux's `path_noexec`): it can never be mapped
/// executable.
fn on_noexec(cx: &Cx<'_>, f: &OpenFile) -> bool {
    f.node()
        .and_then(|n| cx.vfs().ok()?.mount_flags(&n))
        .is_some_and(|m| m & ms::NOEXEC != 0)
}

/// Whether mapping at `addr` is refused: below `vm.mmap_min_addr` without `CAP_SYS_RAWIO`
/// (Linux's cap_mmap_addr, EPERM).
pub(super) fn below_min_addr(cx: &Cx<'_>, addr: u64) -> bool {
    use std::sync::atomic::Ordering;
    addr < crate::mm::MMAP_MIN_ADDR.load(Ordering::Relaxed) && !cx.cred().capable(cap::SYS_RAWIO)
}

pub(super) fn madvise(cx: &mut Cx<'_>, addr: u64, len: u64, advice: i32) -> SysResult {
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::EINVAL);
    }
    let len = len
        .checked_next_multiple_of(PAGE_SIZE)
        .filter(|&l| addr.checked_add(l).is_some())
        .ok_or(Errno::EINVAL)?;
    // No KSM, transparent huge pages or memory fault injection (MERGEABLE, HUGEPAGE, COLLAPSE,
    // HWPOISON and so on)
    if !matches!(advice, 0..=4 | 8..=11 | 16..=24) {
        crate::stub::hit(cx, crate::stub::Stub::Madvise(advice));
        return Err(Errno::EINVAL);
    }
    if len == 0 {
        return Ok(0);
    }
    match advice {
        MADV_REMOVE => {
            let plan = cx.mm_mut().remove(addr, len);
            for r in plan.tmpfs {
                super::fs::punch_tmpfs_maps(cx, r.mapping.ino, r.offset, r.offset + r.len);
                r.mapping.punch(r.offset, r.len)?;
            }
            for (fill, start, end) in plan.fuse {
                super::fuse::remove_mapped(cx, &fill, start, end)?;
            }
            plan.result.map(|()| 0)
        }
        // After DONTNEED / DONTNEED_LOCKED anonymous memory must read back as 0, and private file
        // mappings as the file. DONTNEED_LOCKED also discards mlock'd ranges without unlocking.
        MADV_DONTNEED | MADV_DONTNEED_LOCKED => {
            let (rereads, res) =
                cx.mm_mut()
                    .discard_range(addr, len, advice == MADV_DONTNEED_LOCKED);
            reread(cx, rereads)?;
            res.map(|()| 0)
        }
        MADV_FREE => cx.mm().check_free(addr, len).map(|()| 0),
        MADV_COLD | MADV_PAGEOUT => cx.mm().check_lru(addr, len).map(|()| 0),
        MADV_WIPEONFORK | MADV_KEEPONFORK => cx
            .mm_mut()
            .set_wipeonfork(addr, len, advice == MADV_WIPEONFORK)
            .map(|()| 0),
        MADV_DONTFORK | MADV_DOFORK => cx
            .mm_mut()
            .set_dontfork(addr, len, advice == MADV_DONTFORK)
            .map(|()| 0),
        // Whether it is written to core files (crate::coredump)
        MADV_DONTDUMP | MADV_DODUMP => cx
            .mm_mut()
            .set_dontdump(addr, len, advice == MADV_DONTDUMP)
            .map(|()| 0),
        MADV_POPULATE_READ | MADV_POPULATE_WRITE => {
            madvise_populate(cx, addr, len, advice == MADV_POPULATE_WRITE)
        }
        // Forward readahead/access-pattern hints to the host outside the BKL so host readahead
        // never stalls other guest threads, and prefill soft PTEs for read-only file mappings.
        MADV_NORMAL | MADV_RANDOM | MADV_SEQUENTIAL | MADV_WILLNEED => {
            let willneed = advice == MADV_WILLNEED;
            let (ranges, res) = {
                let mm = cx.mm();
                if willneed {
                    mm.prefill_file_ptes(addr, len);
                }
                let ranges = mm.advise_ranges(addr, len, !willneed);
                let res = mm.check_mapped(addr, len);
                (ranges, res)
            };
            if !ranges.is_empty() {
                cx.unlocked(move || {
                    for range in ranges {
                        range.apply(advice);
                    }
                });
            }
            if willneed && cx.mm().has_fills() {
                willneed_fuse(cx, addr, addr.saturating_add(len));
            }
            res.map(|()| 0)
        }
        _ => unreachable!("advice validated above"),
    }
}

/// Drives a resumable FUSE `Fill` cursor walk across `[start, end)`, fetching cold pages outside
/// the BKL. With `strict`, daemon read errors return `ENOMEM` (`EINTR` on kill); otherwise errors
/// skip the remainder of that VMA.
fn fill_vma_range(
    cx: &mut Cx<'_>,
    start: u64,
    end: u64,
    strict: bool,
    mut next: impl FnMut(&Mm, &mut u64, u64) -> Result<Option<(Rc<Fill>, u64, u64)>, Errno>,
) -> Result<(), Errno> {
    let mut cursor = start;
    let mut retries = 0;
    while cursor < end {
        let prev = cursor;
        let Some((fill, fpage, vma_stop)) = next(&cx.mm(), &mut cursor, end)? else {
            break;
        };
        if cursor > prev {
            retries = 0;
        } else {
            retries += 1;
            if retries > super::FUSE_RETRIES {
                if strict {
                    return Err(Errno::ENOMEM);
                }
                cursor = vma_stop;
                retries = 0;
                continue;
            }
        }
        if let Err(e) = super::fuse::fill(cx, (fill, fpage)) {
            if strict {
                return Err(if e == Errno::EINTR {
                    Errno::EINTR
                } else {
                    Errno::ENOMEM
                });
            }
            cursor = vma_stop;
            retries = 0;
        }
    }
    Ok(())
}

/// Advisory FUSE demand-readahead for `madvise(MADV_WILLNEED)`: fetches missing `Fill` pages in
/// `[addr, end)` outside the BKL without surfacing daemon I/O errors (still returning `ENOMEM`
/// from the caller if any unmapped gap existed).
fn willneed_fuse(cx: &mut Cx<'_>, addr: u64, end: u64) {
    let _ = fill_vma_range(cx, addr, end, false, |mm, cursor, end| {
        Ok(mm
            .next_unread_fill(*cursor, end)
            .map(|(page, stop, fill, fpage)| {
                *cursor = page;
                (fill, fpage, stop)
            }))
    });
}

/// Populates `[start, start + len)` for `mlock`, `mlock2`, `mlockall`, `MAP_POPULATE`/`MAP_LOCKED`,
/// and `remap_file_pages`, fetching cold FUSE `Fill` pages outside the BKL. With `fail_on_none`
/// (`mlock`/`mlock2`), `PROT_NONE` and FUSE daemon read errors stop and return `ENOMEM` (`EINTR`
/// on kill); otherwise (`mlockall`, `MAP_POPULATE`, `remap_file_pages`), errors are ignored.
fn populate_range(cx: &mut Cx<'_>, start: u64, len: u64, fail_on_none: bool) -> Result<(), Errno> {
    fill_vma_range(
        cx,
        start,
        start.saturating_add(len),
        fail_on_none,
        |mm, cursor, end| mm.populate_mlock_step(cursor, end, fail_on_none),
    )
}

/// Synchronous prefaulting (Linux 6.1's `madvise_populate`): validates permissions (`EINVAL`) and
/// backing extents (`EFAULT`), faults host/tmpfs/FUSE pages, breaks CoW on write, and reports
/// skipped unmapped gaps as `ENOMEM` at the end.
fn madvise_populate(cx: &mut Cx<'_>, addr: u64, len: u64, write: bool) -> SysResult {
    let mut walk = PopulateWalk::new(addr, len);
    let mut retries = 0;
    loop {
        let prev = walk.cursor;
        let step = cx.mm_mut().populate_step(&mut walk, write)?;
        match step {
            PopulateStep::Done => break,
            PopulateStep::Advise(range) => {
                retries = 0;
                cx.unlocked(move || range.apply(MADV_WILLNEED));
            }
            PopulateStep::Fill(fill, page) => {
                if walk.cursor > prev {
                    retries = 0;
                } else {
                    retries += 1;
                    if retries > super::FUSE_RETRIES {
                        return Err(Errno::EFAULT);
                    }
                }
                match super::fuse::fill(cx, (fill, page)) {
                    Ok(()) => {}
                    Err(Errno::EINTR) => return Err(Errno::EINTR),
                    Err(_) => return Err(Errno::EFAULT),
                }
            }
        }
    }
    if walk.has_gap {
        return Err(Errno::ENOMEM);
    }
    Ok(0)
}

/// mlock, munlock, mlock2: records which mappings are locked (host memory is never swapped out
/// anywhere the guest could notice) and checks the range and `RLIMIT_MEMLOCK`. As on Linux,
/// locking brings the pages into memory, except with `MLOCK_ONFAULT`.
pub(super) fn mlock(cx: &mut Cx<'_>, addr: u64, len: u64, flags: u32, lock: bool) -> SysResult {
    const MLOCK_ONFAULT: u32 = 1;
    if flags & !MLOCK_ONFAULT != 0 {
        return Err(Errno::EINVAL);
    }
    // Linux's do_mlock and munlock: the length is page-aligned with wrapping arithmetic; after the
    // RLIMIT_MEMLOCK check, a range that wraps past the end of the address space is EINVAL and an
    // empty one succeeds
    let start = addr & !(PAGE_SIZE - 1);
    let span = len
        .wrapping_add(addr & (PAGE_SIZE - 1))
        .wrapping_add(PAGE_SIZE - 1)
        & !(PAGE_SIZE - 1);
    if lock {
        let already = cx.mm().locked_in(start, span);
        check_memlock(cx, span - already)?;
    }
    let end = start.wrapping_add(span);
    if end < start {
        return Err(Errno::EINVAL);
    }
    if end == start {
        return Ok(0);
    }
    cx.mm_mut().set_locked(start, span, lock)?;
    if lock && flags & MLOCK_ONFAULT == 0 {
        populate_range(cx, start, span, true)?;
    }
    Ok(0)
}

pub(super) fn mlockall(cx: &mut Cx<'_>, flags: u32) -> SysResult {
    if flags == 0
        || flags & !(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT) != 0
        || flags & (MCL_CURRENT | MCL_FUTURE) == 0
    {
        return Err(Errno::EINVAL);
    }
    if flags & MCL_CURRENT != 0 {
        let mm = cx.mm();
        let more = mm.size() - mm.locked_bytes();
        drop(mm);
        check_memlock(cx, more)?;
        cx.mm_mut().set_all_locked(true);
        if flags & MCL_ONFAULT == 0 {
            let _ = populate_range(cx, 0, u64::MAX, false);
        }
    } else if cx.memlock_limit() == 0 {
        return Err(Errno::EPERM);
    }
    let mut mm = cx.mm_mut();
    mm.lock_future = flags & MCL_FUTURE != 0;
    mm.lock_onfault = flags & MCL_ONFAULT != 0;
    Ok(0)
}

pub(super) fn munlockall(cx: &mut Cx<'_>) -> SysResult {
    let mut mm = cx.mm_mut();
    mm.set_all_locked(false);
    mm.lock_future = false;
    mm.lock_onfault = false;
    Ok(0)
}

/// Without `CAP_IPC_LOCK`, locked memory may not exceed `RLIMIT_MEMLOCK` (nothing can be locked
/// when it is 0). `more` is the bytes newly locked by this call.
fn check_memlock(cx: &Cx<'_>, more: u64) -> Result<(), Errno> {
    let limit = cx.memlock_limit();
    if limit == 0 {
        return Err(Errno::EPERM);
    }
    if !cx.mm().can_lock(more, limit) {
        return Err(Errno::ENOMEM);
    }
    Ok(())
}

/// Linux 6.1's `mlock_future_check`: without `CAP_IPC_LOCK`, locking `more` additional bytes for
/// future mappings (`MCL_FUTURE`, `MAP_LOCKED`, `shmat`) fails with `EAGAIN` when exceeding
/// `RLIMIT_MEMLOCK`.
pub(super) fn check_memlock_future(cx: &Cx<'_>, more: u64) -> Result<(), Errno> {
    if !cx.mm().can_lock(more, cx.memlock_limit()) {
        return Err(Errno::EAGAIN);
    }
    Ok(())
}

/// msync of shared files waits for the host object or the FUSE daemon.
/// Walks VMAs in `[addr, end)` like Linux 6.1's `msync`: skips unmapped gaps (returning `ENOMEM`
/// at the end), stops immediately with `EBUSY` on a locked VMA under `MS_INVALIDATE`, and syncs
/// each shared file VMA in turn with the BKL released.
pub(super) fn msync(cx: &mut Cx<'_>, addr: u64, len: u64, flags: u32) -> SysResult {
    const MS_ASYNC: u32 = 1;
    const MS_INVALIDATE: u32 = 2;
    const MS_SYNC: u32 = 4;
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0
        || flags & (MS_ASYNC | MS_SYNC) == MS_ASYNC | MS_SYNC
        || !addr.is_multiple_of(PAGE_SIZE)
    {
        return Err(Errno::EINVAL);
    }
    let len = len
        .checked_next_multiple_of(PAGE_SIZE)
        .ok_or(Errno::ENOMEM)?;
    let end = addr.checked_add(len).ok_or(Errno::ENOMEM)?;
    if end == addr {
        return Ok(0);
    }
    let sync = flags & MS_SYNC != 0;
    let invalidate = flags & MS_INVALIDATE != 0;
    let mut cursor = addr;
    let mut unmapped = false;
    while cursor < end {
        let step = cx.mm().next_msync(cursor, end, sync);
        match step {
            MsyncStep::Unmapped => return Err(Errno::ENOMEM),
            MsyncStep::Vma {
                start,
                stop,
                locked,
                target,
            } => {
                if start > cursor {
                    unmapped = true;
                }
                // Locked pages cannot be invalidated (`EBUSY` takes precedence over earlier gaps).
                if invalidate && locked {
                    return Err(Errno::EBUSY);
                }
                // A shared file mapping is the host's shared mapping of the object itself: MS_SYNC
                // leaves the write-back to the host and waits with the BKL released.
                if let Some(target) = target {
                    match target {
                        MsyncTarget::Fuse(fill, fstart, fend) => {
                            super::fuse::sync_mapping(cx, &fill, fstart, fend)?;
                        }
                        MsyncTarget::Host(host) => {
                            cx.unlocked(move || host.sync())?;
                        }
                    }
                }
                cursor = stop;
            }
        }
    }
    if unmapped {
        return Err(Errno::ENOMEM);
    }
    Ok(0)
}

pub(super) fn munmap(cx: &mut Cx<'_>, addr: u64, len: u64) -> SysResult {
    cx.mm_mut().munmap(addr, len)?;
    // A segment marked for removal goes with its last attachment, whatever detaches it
    crate::ipc::reap_shm(cx.k());
    Ok(0)
}

/// mincore: reports whether each page is resident, by host memory.
/// Matches Linux 6.1's `mincore`: walks contiguous mapped VMAs from `addr` in chunks of at most
/// `PAGE_SIZE` pages, writing each chunk to `vec` (without growing the stack) before advancing,
/// and stops on the first unmapped page (`ENOMEM`) or write fault (`EFAULT`).
pub(super) fn mincore(cx: &mut Cx<'_>, addr: u64, len: u64, vec: u64) -> SysResult {
    if !addr.is_multiple_of(PAGE_SIZE) {
        return Err(Errno::EINVAL);
    }
    let end = len
        .checked_next_multiple_of(PAGE_SIZE)
        .and_then(|l| addr.checked_add(l))
        .filter(|&e| e <= 1 << VA_BITS)
        .ok_or(Errno::ENOMEM)?;
    let pages = (end - addr) / PAGE_SIZE;
    if vec.checked_add(pages).is_none_or(|e| e > 1 << VA_BITS) {
        return Err(Errno::EFAULT);
    }
    let mut cursor = addr;
    let mut out_addr = vec;
    let mut buf = Vec::new();
    while cursor < end {
        let next = cx.mm().residency_chunk(cursor, end, &mut buf)?;
        cx.mm()
            .write(crate::uaccess::UserSlice::new(out_addr, buf.len()), &buf)?;
        out_addr += buf.len() as u64;
        cursor = next;
    }
    Ok(0)
}

/// process_mrelease (Linux 6.1's `mm/oom_kill.c`): frees the private memory of a process that is
/// exiting before its threads have all gone (lmkd and earlyoom call it right after SIGKILL). Flags
/// are `EINVAL`; anything but a pidfd is `EBADF` (a `/proc/<pid>` directory too, unlike
/// pidfd_send_signal); a process with no thread left holding its address space (a zombie, or
/// reaped) is `ESRCH` (`find_lock_task_mm`); unless it is exiting as a whole (exit_group, a fatal
/// signal, or its last thread's exit) and writing no core file, and so is every other process
/// sharing its address space (`task_will_free_mem`), `EINVAL`.
pub(super) fn process_mrelease(cx: &mut Cx<'_>, pidfd: i32, flags: u32) -> SysResult {
    use std::rc::Rc;
    if flags != 0 {
        return Err(Errno::EINVAL);
    }
    let file = cx.fds().get(pidfd)?;
    let group = match &file.borrow().kind {
        FileKind::Pidfd(p) => p.group(cx.kr()).ok_or(Errno::ESRCH)?,
        _ => return Err(Errno::EBADF),
    };
    let k = cx.kr();
    let mm_of = |g: &crate::process::ThreadGroup| {
        g.threads
            .iter()
            .find_map(|t| k.tasks.get(t))
            .map(|t| t.res.borrow().mm.clone())
    };
    let mm = mm_of(&group.borrow()).ok_or(Errno::ESRCH)?;
    let dying = |g: &crate::process::ThreadGroup| will_free_mem(k, g);
    let sharers_dying = k
        .groups
        .values()
        .filter(|g| !Rc::ptr_eq(g, &group))
        .all(|g| {
            let g = g.borrow();
            mm_of(&g).is_none_or(|m| !Rc::ptr_eq(&m, &mm)) || dying(&g)
        });
    if !dying(&group.borrow()) || !sharers_dying {
        return Err(Errno::EINVAL);
    }
    // The peak resident memory (ru_maxrss of the process's wait) is taken before the memory goes
    group.borrow_mut().sample_rss(&mm.borrow());
    // No thread holds an address space borrowed across a BKL release, and the caller's own (the
    // target when another of its threads called exit_group) is not borrowed here: checked rather
    // than assumed
    if let Ok(mut m) = mm.try_borrow_mut() {
        m.release();
    }
    Ok(0)
}

/// Linux 6.1's `task_will_free_mem`: true when the thread group is not writing a core file and
/// either group exit has started (by `exit_group`, `SIGKILL`, fatal signal delivery, OOM kill,
/// or a non-coredumping fatal signal pending for an unblocked, untraced thread as Linux's
/// `complete_signal` sets `SIGNAL_GROUP_EXIT` on send), or it is a single-thread group (no
/// zombie leader and only one thread) whose thread has entered `exit(2)`.
fn will_free_mem(k: &crate::kernel::Kernel, g: &crate::process::ThreadGroup) -> bool {
    if g.core.is_some() {
        return false;
    }
    crate::oom::will_free_mem(k, g) || has_fatal_pending(k, g)
}

/// Whether `g` has a pending non-coredumping fatal signal that Linux 6.1's `complete_signal`
/// turns into `SIGNAL_GROUP_EXIT` immediately when sent: default action is terminate (not
/// ignored, stop, continue, or coredump), the process is not an unkillable pid-namespace init,
/// and a live, untraced thread does not block it.
fn has_fatal_pending(k: &crate::kernel::Kernel, g: &crate::process::ThreadGroup) -> bool {
    let unkillable = g.pid_ns.level > 0 && g.pid_ns.reaper.get() == Some(g.tgid) && !g.killable;
    if unkillable {
        return false;
    }
    let sighand = g.sighand.borrow();
    let is_fatal_no_core = |sig: crate::process::Signal| {
        sighand.get(sig).handler == crate::signal::SigAction::DEFAULT
            && !sig.ignored_by_default()
            && !sig.is_stop()
            && sig != crate::process::Signal::CONT
            && !crate::coredump::dumps_core(sig)
    };
    let group_pending = g.pending.set();
    for tid in &g.threads {
        let Some(t) = k.tasks.get(tid) else {
            continue;
        };
        if t.trace.borrow().tracer.is_some() {
            continue;
        }
        let mut bits = (group_pending | t.pending.borrow().set()) & !t.sigmask.get();
        while bits != 0 {
            let bit = bits.trailing_zeros();
            bits &= bits - 1;
            if let Some(sig) = crate::process::Signal::new(bit as i32 + 1)
                && is_fatal_no_core(sig)
            {
                return true;
            }
        }
    }
    false
}
