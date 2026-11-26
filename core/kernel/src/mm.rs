//! Guest address spaces (the kernel/mm map: `.agents/maps/kernel/mm.md`): a VMA table plus a
//! soft-MMU page table. Filling entries, keeping threads consistent and code groups are described
//! by the kernel/mmu map, the resident-memory measures and `Mm::release` by the kernel/oom map,
//! fork and copy-on-write by the kernel/cow map, and host backing and deferred release by the
//! kernel/hostmem map.
//!
//! Every VMA points at a piece of host memory (an anonymous or a file mapping), and several VMAs
//! can share one piece (after munmap/mprotect splits them, or shared mappings after fork). Host
//! memory is released only when the last VMA referring to it goes away. File mappings use a host
//! `mmap(objects/<ino>)` directly.
//!
//! An address space can be used by several threads at once (threads, vfork). After a mapping is
//! torn down or its permissions are lowered, other threads' TLBs may still hold stale
//! translations, so a TLB shootdown comes first ([`Mm::sync`]): bump the generation, kick the
//! threads running guest code and wait for them to leave; before re-entering guest code they see
//! the new generation and flush their own TLBs. Unmapped host memory is released only after the
//! shootdown completes, so guest data races never reach freed memory.
//!
//! Tier 1 translations are invalidated the same way: when an executable mapping is torn down or
//! changes permissions, or the guest declares modified code with `ic ivau`, the ranges go into
//! [`CodeLog`] and the code generation is bumped; each thread invalidates translations page by
//! page over the ranges it missed.
//!
//! On fork, private anonymous memory is copy-on-write (the kernel/cow map), other private mappings
//! are copied, and shared mappings are shared with the child. Copy-on-write is per page: pages
//! written before fork are not copied; the page tables of parent and child both point at the
//! parent's host page, without write permission. The side whose VMA holds the host page is its
//! owner and lends it; other address spaces borrow it.
//! - A borrower copies the page into the matching place in its own VMA on write
//!   ([`Mm::materialize`]).
//! - Before the owner writes, unmaps, moves or discards a lent page, every borrower copies its own
//!   first ([`Mm::recall`]).
//! - When the owner's address space is destroyed, the page stays with the borrowers (an orphan
//!   page that nobody may write again), which hold that host memory.
//! - When the last borrower returns a page, the owner's entries get write permission back at once:
//!   a shell's child execs right after fork, so the parent need not take a fault for it.
//!
//! Before a page-table entry is re-pointed, the threads using this address space must flush their
//! TLBs ([`Mm::shootdown`]); merely restoring write permission needs no flush.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::mem::ManuallyDrop;
use std::os::fd::{BorrowedFd, OwnedFd};
use std::ptr::NonNull;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use appine_engine::{MapError, Mmu, PAGE_SIZE, VA_BITS, prot};

use crate::cell::RefCell;
use crate::errno::Errno;
use crate::loader::{STACK_SIZE, STACK_TOP};
use crate::task::TaskSync;
use crate::uaccess::UserSlice;

/// mmap flags (guest ABI).
pub mod flags {
    /// Shared mapping.
    pub const MAP_SHARED: u32 = 0x01;
    /// Private mapping.
    pub const MAP_PRIVATE: u32 = 0x02;
    /// Fixed address, replacing existing mappings.
    pub const MAP_FIXED: u32 = 0x10;
    /// Anonymous mapping.
    pub const MAP_ANONYMOUS: u32 = 0x20;
    /// Grows downwards.
    pub const MAP_GROWSDOWN: u32 = 0x0100;
    /// Lock the mapping on creation.
    pub const MAP_LOCKED: u32 = 0x2000;
    /// Not counted in the memory commit.
    pub const MAP_NORESERVE: u32 = 0x4000;
    /// Fixed address, but never replacing existing mappings.
    pub const MAP_FIXED_NOREPLACE: u32 = 0x10_0000;
}

/// Minimum gap between the stack top and the upper bound of the mmap area: the default stack size
/// limit plus 1 GiB. Linux uses 128 MB plus the stack's random offset (up to about 1 GB on arm64).
const MIN_GAP: u64 = STACK_SIZE + (1 << 30);
/// Upper bound of that gap, the same as Linux's `MAX_GAP`.
const MAX_GAP: u64 = STACK_TOP / 6 * 5;
/// `/proc/sys/vm/mmap_min_addr` (Linux's `dac_mmap_min_addr`): mapping below it needs
/// `CAP_SYS_RAWIO` (checked by the syscalls), and addresses the kernel picks, mmap hints and stack
/// growth stay above it. 32768 as in the arm64 kernels of distributions and Android's GKI.
pub(crate) static MMAP_MIN_ADDR: AtomicU64 = AtomicU64::new(32768);
/// `/proc/sys/vm/overcommit_memory`: 1 (always overcommit) turns off fork's commit check
/// ([`Mm::commit_too_big`]); 0 and 2 keep it (2's strict accounting is not emulated).
pub(crate) static OVERCOMMIT_MEMORY: AtomicU8 = AtomicU8::new(0);

/// The lowest address the kernel maps on its own or a stack grows to: [`MMAP_MIN_ADDR`] rounded
/// up to a page, and at least one page (Linux's get_unmapped_area).
fn mmap_min() -> u64 {
    page_up(MMAP_MIN_ADDR.load(Ordering::Relaxed))
        .unwrap_or(1 << VA_BITS)
        .max(PAGE_SIZE)
}
/// Minimum gap between a grows-down mapping and the mapping below it (Linux's `stack_guard_gap`,
/// 256 pages).
const STACK_GUARD_GAP: u64 = 256 * PAGE_SIZE;
/// `/proc/sys/vm/max_map_count`: the most VMAs one address space may have. Every VMA is a host
/// mapping, and the host's mapping count (also 65530 on Android) is shared by the whole app
/// process.
pub(crate) static MAX_MAP_COUNT: AtomicUsize = AtomicUsize::new(65530);

/// The next [`Vma::anon`] identity handed out at fork.
static ANON_IDS: AtomicU64 = AtomicU64::new(1);

/// Host address space reserved when the heap (brk) first grows: later growth only lengthens the
/// same VMA. The untouched part takes no memory (`MAP_NORESERVE`); growth beyond it is mapped
/// separately as before.
const HEAP_RESERVE: u64 = 256 << 20;

/// On fork, child mappings up to this size are carved from one piece of host memory
/// ([`Mm::fork`]). After such a mapping is unmapped its host memory is returned only once the
/// whole piece is unused, so only small mappings get one.
const FORK_PIECE_MAX: u64 = 1 << 20;

/// On fork, written anonymous mappings up to this size lend every page without checking which
/// pages were touched ([`Mm::lend`]).
const LEND_ALL_MAX: u64 = 16 * PAGE_SIZE;

/// Mappings up to this size get their page-table entries when they are created
/// ([`Mm::map_pages`]); larger ones get them on demand: the guest's first access or the kernel
/// layer's first read or write fills in the leaf table around it ([`Mm::fault_in`]). Page tables
/// then grow with the memory touched rather than with the mapping size: ASan maps more than ten
/// TB of shadow memory, and building its entries page by page would take tens of GB.
const EAGER_MAX: u64 = 1 << 20;

/// The range one leaf table covers (512 pages): on-demand filling fills this much at once, and
/// fork's lending and resident-memory measurement look for touched places in units of it
/// ([`Mm::touched_windows`]).
const LEAF_SPAN: u64 = PAGE_SIZE << 9;

/// On-demand filling span for large read-only file mappings (16 MiB = 8 leaf tables): aligned
/// 2 MiB chunks become L2 superpages without touching host pages, reducing BKL serialization when
/// multiple threads stream through a large file (such as model weights).
const FILE_FAULT_SPAN: u64 = 8 * LEAF_SPAN;

/// Cap on soft page-table prefill per `madvise(MADV_WILLNEED)` call
/// (4 GiB = at most 2048 L2 superpage entries, ~16 KiB of L2 tables).
const FILE_PREFILL_MAX: u64 = 4 << 30;

/// The largest span [`Mm::touched_windows`] reports, so per-page records (pagemap, mincore) stay
/// small.
const WINDOW_MAX: u64 = 1 << 30;

// ---- Address space ----

/// Where a mapping's contents come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backing {
    /// Private anonymous memory.
    Anonymous,
    /// Private file mapping (copy-on-write).
    PrivateFile,
    /// Shared mapping (file or anonymous): after fork, parent and child share the same host memory.
    Shared,
}

/// A piece of a private file mapping whose written pages `MADV_DONTNEED` dropped but whose host
/// memory could not simply be given back to the host file ([`Mm::discard_range`]): the caller reads it
/// from the file again (zeros past the end of the file) and stores it with [`Mm::fill_private`].
#[derive(Debug, PartialEq, Eq)]
pub struct Reread {
    pub addr: u64,
    pub len: u64,
    /// The mapped file's inode in the store (0 if unknown) and the file offset at `addr`.
    pub ino: u64,
    pub offset: u64,
}

/// Non-lock VMA flags preserved on the remnant left at the old address by `mremap(MREMAP_DONTUNMAP)`.
#[derive(Clone, Copy)]
pub struct VmaFlags {
    may_exec: bool,
    dontdump: bool,
    wipeonfork: bool,
    dontfork: bool,
    growsdown: bool,
    noreserve: bool,
    anon: u64,
    accounted: bool,
}

impl VmaFlags {
    fn of(v: &Vma) -> Self {
        Self {
            may_exec: v.may_exec,
            dontdump: v.dontdump,
            wipeonfork: v.wipeonfork,
            dontfork: v.dontfork,
            growsdown: v.growsdown,
            noreserve: v.noreserve,
            anon: v.anon,
            accounted: v.accounted,
        }
    }

    fn apply_to(self, v: &mut Vma) {
        v.locked = false;
        v.may_exec = self.may_exec;
        v.dontdump = self.dontdump;
        v.wipeonfork = self.wipeonfork;
        v.dontfork = self.dontfork;
        v.growsdown = self.growsdown;
        v.noreserve = self.noreserve;
        v.anon = self.anon;
        v.accounted = self.accounted;
    }
}

/// A piece of a file to map again at the old address after mremap(`MREMAP_DONTUNMAP`): it was a
/// private file mapping, and on Linux its pages are read from the file again afterwards.
pub struct Refill {
    pub start: u64,
    pub len: u64,
    pub prot: u32,
    /// The mapped file's inode in the store (0 if unknown) and the file offset of this piece.
    pub ino: u64,
    pub offset: u64,
    pub name: Option<Rc<[u8]>>,
    pub mnt: Option<crate::vfs::MountId>,
    pub(crate) file: Option<Rc<OwnedFd>>,
    pub flags: VmaFlags,
    pub(crate) tmpfs: Option<Rc<crate::vfs::TmpfsMapping>>,
    interp_open: Option<Rc<crate::syscall::Opened>>,
}

/// A host-page-aligned slice of a live [`HostRegion`] retained across a BKL release so
/// non-destructive `madvise(2)` hints can run without holding the BKL.
pub struct AdviseRange {
    _region: Arc<HostRegion>,
    ptr: NonNull<u8>,
    len: usize,
}

// SAFETY: `_region` keeps the host mapping alive for the lifetime of `AdviseRange`, and
// `AdviseRange` is only used for non-destructive `madvise(2)` hints on `[ptr, ptr + len)`.
unsafe impl Send for AdviseRange {}

impl AdviseRange {
    /// Forwards non-destructive `advice` to host `madvise(2)` while retaining the backing host
    /// mapping.
    pub fn apply(self, advice: i32) {
        // SAFETY: `self._region` keeps `[self.ptr, self.ptr + self.len)` mapped and
        // host-page-aligned for the duration of the call.
        let _ = unsafe { appine_hal::advise(self.ptr, self.len, advice) };
    }
}

/// A host-page-aligned slice of a live shared file [`HostRegion`] retained across a BKL release so
/// `msync(MS_SYNC)` can wait on host write-back without holding the BKL.
pub(crate) struct MsyncHost {
    _region: Arc<HostRegion>,
    addr: usize,
    len: usize,
}

impl MsyncHost {
    /// Syncs the retained host mapping slice with `MS_SYNC`, ignoring host `ENOMEM` if the range
    /// was torn down concurrently.
    pub(crate) fn sync(self) -> Result<(), Errno> {
        match appine_hal::msync(self.addr, self.len) {
            Err(libc::ENOMEM) => Ok(()),
            r => r.map_err(Errno),
        }
    }
}

/// What a single VMA slice in `msync(2)` needs to sync when `MS_SYNC` is set.
pub(crate) enum MsyncTarget {
    Fuse(Rc<Fill>, u64, u64),
    Host(MsyncHost),
}

/// Work collected by [`Mm::remove`] (`MADV_REMOVE`) for tmpfs and FUSE VMAs visited before any
/// per-VMA error, paired with the final result (`ENOMEM` if any unmapped gap was skipped).
pub(crate) struct RemovePlan {
    pub tmpfs: Vec<TmpfsRange>,
    pub fuse: Vec<(Rc<Fill>, u64, u64)>,
    pub result: Result<(), Errno>,
}

/// One step of Linux 6.1's per-VMA `msync(2)` walk ([`Mm::next_msync`]).
pub(crate) enum MsyncStep {
    /// No VMA overlaps `[cursor, end)`.
    Unmapped,
    /// Next mapped slice `[start, stop)` inside `[cursor, end)`. If `start > cursor`,
    /// `[cursor, start)` is an unmapped gap.
    Vma {
        start: u64,
        stop: u64,
        locked: bool,
        target: Option<MsyncTarget>,
    },
}

/// Progress of a resumable `madvise(MADV_POPULATE_READ | MADV_POPULATE_WRITE)` walk
/// ([`Mm::populate_step`]).
pub(crate) struct PopulateWalk {
    pub cursor: u64,
    pub end: u64,
    pub warmed_until: u64,
    pub has_gap: bool,
}

impl PopulateWalk {
    pub(crate) fn new(addr: u64, len: u64) -> Self {
        Self {
            cursor: addr,
            end: addr + len,
            warmed_until: addr,
            has_gap: false,
        }
    }
}

/// Unlocked work requested by [`Mm::populate_step`] before resuming under the BKL.
pub(crate) enum PopulateStep {
    /// Reached `end` (or no further VMA overlaps the remaining range).
    Done,
    /// Warm a regular file slice with host `MADV_WILLNEED` outside the BKL.
    Advise(AdviseRange),
    /// Read an unread FUSE page from the daemon outside the BKL.
    Fill(Rc<Fill>, u64),
}

struct FilePages {
    tmpfs: Option<Rc<crate::vfs::TmpfsMapping>>,
    /// File offsets with private copies. Split ordinary VMAs share this set across host pages.
    copied: std::cell::RefCell<BTreeSet<u64>>,
}

impl FilePages {
    fn new(tmpfs: Option<Rc<crate::vfs::TmpfsMapping>>, copied: BTreeSet<u64>) -> Rc<Self> {
        Rc::new(Self {
            tmpfs,
            copied: copied.into(),
        })
    }

    /// Tmpfs tracks admitted guest pages. A write to an ordinary private mapping detaches
    /// a whole host page, including the part covered by another piece of a split VMA.
    fn page_size(&self) -> u64 {
        if self.tmpfs.is_some() {
            PAGE_SIZE
        } else {
            appine_hal::page_size() as u64
        }
    }

    fn page_start(&self, offset: u64) -> u64 {
        offset & !(self.page_size() - 1)
    }

    fn detached(&self, offset: u64, len: u64) -> Rc<Self> {
        let range = self.page_start(offset)..offset + len;
        Self::new(
            self.tmpfs.clone(),
            self.copied.borrow().range(range).copied().collect(),
        )
    }

    /// Admit a page at a byte offset within its VMA and return whether it can be mapped writable.
    fn admit(&self, vma: &Vma, delta: u64, write: bool) -> Result<bool, Errno> {
        let offset = self.page_start(vma.offset() + delta);
        let private = vma.backing == Backing::PrivateFile;
        if private && self.copied.borrow().contains(&offset) {
            return Ok(true);
        }
        if let Some(tmpfs) = &self.tmpfs {
            tmpfs.fault(offset, !private && write)?;
        }
        if private && write {
            // SAFETY: this host page is mapped MAP_PRIVATE and writable regardless of guest
            // permissions. Break host CoW before recording the page as independent of the file.
            let byte = unsafe { vma.host.add(delta as usize).cast::<AtomicU8>().as_ref() };
            byte.fetch_or(0, Ordering::Relaxed);
            self.copied.borrow_mut().insert(offset);
        }
        Ok(write)
    }
}

pub(crate) struct TmpfsRange {
    pub mapping: Rc<crate::vfs::TmpfsMapping>,
    pub offset: u64,
    pub len: u64,
}

pub(crate) enum FileSource {
    PinnedStore,
    Fuse(Rc<Fill>),
    Tmpfs(Rc<crate::vfs::TmpfsMapping>),
}

/// An on-demand FUSE mapping pins the open handle that created it. Independent mappings
/// of the same inode map the same sparse host file, using the guest file offsets.
pub struct Fill {
    /// Only an open that supplied a shared mapping can be used for a cached FUSE_WRITE.
    pub(crate) shared: bool,
    pub source: crate::fd::FileRef,
    pub pages: Rc<FillPages>,
}

impl std::ops::Deref for Fill {
    type Target = FillPages;

    fn deref(&self) -> &Self::Target {
        &self.pages
    }
}

/// File data shared by live mappings. Private host mappings retain normal host CoW semantics.
pub struct FillPages {
    pub(crate) host: std::fs::File,
    size: Cell<u64>,
    /// Baselines for pages exposed to potentially writable shared mappings. Guest stores run
    /// outside the BKL, so writeback compares the memfd with the last acknowledged contents.
    clean: RefCell<BTreeMap<u64, Vec<u8>>>,
    /// Writable opens pinned by mappings, including those awaiting final writeback.
    writers: RefCell<Vec<Weak<Fill>>>,
    /// Pages read so far, as runs of file page numbers (start → end).
    filled: RefCell<BTreeMap<u64, u64>>,
    /// All pages ever filled within the current EOF, including those awaiting a fresh read.
    /// An invalidated page may still have private CoW copies or unacknowledged shared bytes.
    materialized: RefCell<BTreeMap<u64, u64>>,
    pub(crate) generation: Cell<u64>,
    pub(crate) size_stale: Cell<bool>,
    /// A periodic background `FUSE_WRITE` is currently in flight for this inode; foreground I/O
    /// waits for it via `wake::LOCK` so writeback and mutations stay serialized.
    pub(crate) bg_busy: Cell<bool>,
    /// The file page where the last read ended and how many pages it took: a fault right there
    /// reads twice as much, up to [`FILL_MAX`] (Linux ramps up its read-ahead the same way).
    ahead: Cell<(u64, u64)>,
}

/// Pages one read of a [`Fill`] takes around a fault (Linux's default read-ahead, 128 KB).
const FILL_PAGES: u64 = 32;

/// The most pages one read of a [`Fill`] takes for sequential faults.
const FILL_MAX: u64 = 512;

thread_local! {
    /// The page of an on-demand file mapping ([`Fill`]) that a kernel access found not yet read:
    /// the access failed with [`Errno::FUSE_RETRY`], and the syscall dispatcher reads it
    /// ([`take_wanted`]) and runs the syscall again.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static WANTED: std::cell::RefCell<Option<(Rc<Fill>, u64)>> =
        const { std::cell::RefCell::new(None) };
}

fn request_fill(page: (Rc<Fill>, u64)) -> Errno {
    WANTED.with_borrow_mut(|wanted| *wanted = Some(page));
    Errno::FUSE_RETRY
}

/// The page a kernel access last wanted read ([`WANTED`]): the fill and its file page number.
pub fn take_wanted() -> Option<(Rc<Fill>, u64)> {
    WANTED.with_borrow_mut(Option::take)
}

impl Fill {
    #[cfg(test)]
    fn new(host: std::fs::File, size: u64, source: crate::fd::FileRef) -> Rc<Fill> {
        Rc::new(Fill {
            shared: false,
            source,
            pages: FillPages::new(host, size),
        })
    }
}

impl FillPages {
    pub(crate) fn new(host: std::fs::File, size: u64) -> Rc<Self> {
        Rc::new(Self {
            host,
            size: Cell::new(size),
            clean: RefCell::new(BTreeMap::new()),
            writers: RefCell::new(Vec::new()),
            filled: RefCell::new(BTreeMap::new()),
            materialized: RefCell::new(BTreeMap::new()),
            generation: Cell::new(0),
            size_stale: Cell::new(false),
            bg_busy: Cell::new(false),
            ahead: Cell::new((u64::MAX, 0)),
        })
    }

    pub(crate) fn has_tracked(&self) -> bool {
        !self.clean.borrow().is_empty()
    }

    pub(crate) fn add_writer(&self, fill: &Rc<Fill>) {
        let mut writers = self.writers.borrow_mut();
        writers.retain(|w| w.strong_count() != 0);
        writers.push(Rc::downgrade(fill));
    }

    pub(crate) fn writer(&self) -> Option<Rc<Fill>> {
        self.writers
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .find(|fill| fill.shared)
    }

    pub(crate) fn has_writable_open(&self) -> bool {
        self.writers.borrow().iter().any(|w| w.strong_count() != 0)
    }

    /// Snapshot before granting a writable alias, including one later upgraded by mprotect.
    fn track(&self, lo: u64, hi: u64) -> Result<(), Errno> {
        use std::os::unix::fs::FileExt;
        let mut clean = self.clean.borrow_mut();
        let was_empty = clean.is_empty();
        for page in lo..hi {
            if let std::collections::btree_map::Entry::Vacant(entry) = clean.entry(page) {
                let mut data = vec![0; PAGE_SIZE as usize];
                let n = (self.size().saturating_sub(page * PAGE_SIZE)).min(PAGE_SIZE) as usize;
                self.host
                    .read_exact_at(&mut data[..n], page * PAGE_SIZE)
                    .map_err(fill_errno)?;
                entry.insert(data);
            }
        }
        let now_non_empty = !clean.is_empty();
        drop(clean);
        if was_empty && now_non_empty {
            crate::kernel::request_wake();
        }
        Ok(())
    }

    pub(crate) fn tracked(&self, start: u64, end: u64) -> Vec<u64> {
        self.clean
            .borrow()
            .range(start / PAGE_SIZE..end.div_ceil(PAGE_SIZE))
            .map(|(&page, _)| page)
            .collect()
    }

    pub(crate) fn dirty_runs(&self, page: u64) -> Result<Vec<(u64, Vec<u8>)>, Errno> {
        use std::os::unix::fs::FileExt;
        let n = self.size().saturating_sub(page * PAGE_SIZE).min(PAGE_SIZE) as usize;
        let mut data = vec![0; n];
        self.host
            .read_exact_at(&mut data, page * PAGE_SIZE)
            .map_err(fill_errno)?;
        let clean = self.clean.borrow();
        let mut runs = Vec::new();
        if let Some(old) = clean.get(&page) {
            let mut start = 0;
            while start < n {
                if old[start] == data[start] {
                    start += 1;
                    continue;
                }
                let end = (start + 1..n).find(|&i| old[i] == data[i]).unwrap_or(n);
                runs.push((page * PAGE_SIZE + start as u64, data[start..end].to_vec()));
                start = end;
            }
        }
        Ok(runs)
    }

    /// Only bytes the daemon acknowledged become clean. New stores during the request
    /// remain different from this snapshot and are picked up by the next writeback.
    pub(crate) fn acknowledge(&self, offset: u64, data: &[u8]) {
        let at = (offset % PAGE_SIZE) as usize;
        if let Some(old) = self.clean.borrow_mut().get_mut(&(offset / PAGE_SIZE)) {
            old[at..at + data.len()].copy_from_slice(data);
        }
    }

    /// Byte intersections with resident file pages, clipped to the supplied buffer.
    fn resident_bytes(&self, offset: u64, len: usize) -> Vec<(u64, std::ops::Range<usize>)> {
        let end = offset.saturating_add(len as u64);
        Self::intersections(
            &self.materialized.borrow(),
            offset / PAGE_SIZE,
            end.div_ceil(PAGE_SIZE),
        )
        .into_iter()
        .map(|(a, b)| {
            let start = (a * PAGE_SIZE).max(offset);
            let stop = (b * PAGE_SIZE).min(end);
            (start, (start - offset) as usize..(stop - offset) as usize)
        })
        .collect()
    }

    pub(crate) fn overlay(&self, offset: u64, buf: &mut [u8]) -> Result<(), Errno> {
        use std::os::unix::fs::FileExt;
        // The daemon supplied ordinary reads. Overlay only stores not yet written back,
        // so clean mapped pages do not hide a daemon-side change from descriptor readers.
        let end = offset.saturating_add(buf.len() as u64);
        let clean = self.clean.borrow();
        let mut current = [0; PAGE_SIZE as usize];
        for (&page, old) in clean.range(offset / PAGE_SIZE..end.div_ceil(PAGE_SIZE)) {
            let base = page * PAGE_SIZE;
            let start = base.max(offset);
            let stop = (base + PAGE_SIZE).min(end).min(self.size());
            if start >= stop {
                continue;
            }
            let n = (stop - start) as usize;
            self.host
                .read_exact_at(&mut current[..n], start)
                .map_err(fill_errno)?;
            let src = (start - base) as usize;
            let dst = (start - offset) as usize;
            for i in 0..n {
                if current[i] != old[src + i] {
                    buf[dst + i] = current[i];
                }
            }
        }
        Ok(())
    }

    fn write_resident(&self, mut offset: u64, mut data: &[u8]) -> Result<(), Errno> {
        use std::os::unix::fs::FileExt;
        self.host.write_all_at(data, offset).map_err(fill_errno)?;
        while !data.is_empty() {
            let n = data.len().min((PAGE_SIZE - offset % PAGE_SIZE) as usize);
            self.acknowledge(offset, &data[..n]);
            data = &data[n..];
            offset += n as u64;
        }
        Ok(())
    }

    pub(crate) fn written(&self, offset: u64, buf: &[u8]) -> Result<(), Errno> {
        for (start, range) in self.resident_bytes(offset, buf.len()) {
            self.write_resident(start, &buf[range])?;
        }
        Ok(())
    }

    /// Apply a daemon-acknowledged hole to resident bytes, preserving unwritten gaps in
    /// this sparse memfd. Unfilled pages will see the hole on their first FUSE_READ.
    pub(crate) fn punch(&self, start: u64, end: u64) -> Result<(), Errno> {
        let end = end.min(self.size());
        if end <= start {
            return Ok(());
        }
        let zero = [0; PAGE_SIZE as usize];
        for (a, b) in Self::intersections(
            &self.materialized.borrow(),
            start / PAGE_SIZE,
            end.div_ceil(PAGE_SIZE),
        ) {
            for page in a..b {
                let offset = (page * PAGE_SIZE).max(start);
                let len = ((page + 1) * PAGE_SIZE).min(end) - offset;
                self.write_resident(offset, &zero[..len as usize])?;
            }
        }
        Ok(())
    }

    /// Call after all PTEs beyond a shrinking EOF have been revoked.
    pub(crate) fn resize(&self, size: u64) -> Result<(), Errno> {
        self.host.set_len(size).map_err(fill_errno)?;
        if size < self.size() {
            let end = size.div_ceil(PAGE_SIZE);
            for runs in [&self.filled, &self.materialized] {
                runs.borrow_mut().retain(|&start, stop| {
                    *stop = (*stop).min(end);
                    start < *stop
                });
            }
            let mut clean = self.clean.borrow_mut();
            clean.split_off(&end);
            if !size.is_multiple_of(PAGE_SIZE)
                && let Some(last) = clean.get_mut(&(size / PAGE_SIZE))
            {
                last[(size % PAGE_SIZE) as usize..].fill(0);
            }
        }
        self.size.set(size);
        Ok(())
    }

    /// Its host file.
    pub fn fd(&self) -> i32 {
        std::os::fd::AsRawFd::as_raw_fd(&self.host)
    }

    /// Current size of the mapped sparse file.
    pub fn size(&self) -> u64 {
        self.size.get()
    }

    fn in_runs(runs: &BTreeMap<u64, u64>, page: u64) -> bool {
        runs.range(..=page)
            .next_back()
            .is_some_and(|(_, &end)| page < end)
    }

    /// Whether file page `page` has been read.
    pub fn has(&self, page: u64) -> bool {
        Self::in_runs(&self.filled.borrow(), page)
    }

    fn is_materialized(&self, page: u64) -> bool {
        Self::in_runs(&self.materialized.borrow(), page)
    }

    /// Applies `FUSE_NOTIFY_STORE` data to the shared mapping backing: extends the backing if
    /// needed, updates resident/materialized pages (advancing their clean baseline), and marks
    /// newly supplied whole pages (or tail pages up to EOF) as filled so subsequent accesses need
    /// no `FUSE_READ`. Returns whether any previously materialized page was modified.
    pub(crate) fn notify_store(&self, offset: u64, data: &[u8]) -> Result<bool, Errno> {
        use std::os::unix::fs::FileExt;
        let end = offset.checked_add(data.len() as u64).ok_or(Errno::EINVAL)?;
        if end > self.size() {
            self.resize(end)?;
        }
        if data.is_empty() {
            return Ok(false);
        }
        let mut changed_resident = false;
        let mut pos = offset;
        let mut remaining = data;
        while !remaining.is_empty() {
            let page = pos / PAGE_SIZE;
            let page_start = page * PAGE_SIZE;
            let page_end = (page_start + PAGE_SIZE).min(self.size());
            let n = remaining.len().min((page_end - pos) as usize);
            let slice = &remaining[..n];
            let full_page = pos == page_start && pos + n as u64 == page_end;
            let was_materialized = self.is_materialized(page);
            if full_page {
                self.host.write_all_at(slice, pos).map_err(fill_errno)?;
                if let Some(old) = self.clean.borrow_mut().get_mut(&page) {
                    old[..n].copy_from_slice(slice);
                    old[n..].fill(0);
                }
                Self::insert_run(&mut self.filled.borrow_mut(), page, page + 1);
                Self::insert_run(&mut self.materialized.borrow_mut(), page, page + 1);
                changed_resident |= was_materialized;
            } else if self.has(page) || was_materialized {
                self.write_resident(pos, slice)?;
                changed_resident = true;
            }
            pos += n as u64;
            remaining = &remaining[n..];
        }
        self.generation.set(self.generation.get().wrapping_add(1));
        Ok(changed_resident)
    }

    /// The first file page in `[lo, hi)` not yet read.
    fn first_missing(&self, lo: u64, hi: u64) -> Option<u64> {
        let mut at = lo;
        for (s, e) in self.runs(lo, hi) {
            if at < s {
                break;
            }
            at = e;
        }
        (at < hi).then_some(at)
    }

    /// The runs of pages read within file pages `[lo, hi)`.
    fn runs(&self, lo: u64, hi: u64) -> Vec<(u64, u64)> {
        Self::intersections(&self.filled.borrow(), lo, hi)
    }

    fn intersections(filled: &BTreeMap<u64, u64>, lo: u64, hi: u64) -> Vec<(u64, u64)> {
        let first = filled.range(..=lo).next_back().map_or(lo, |(&s, _)| s);
        filled
            .range(first..hi)
            .map(|(&s, &e)| (s.max(lo), e.min(hi)))
            .filter(|(s, e)| s < e)
            .collect()
    }

    /// The bytes of the file to read for a fault on file page `page`, as (offset, length): the
    /// pages not yet read around it ([`FILL_PAGES`]), within the file. A fault right after pages
    /// already read reads ahead instead, twice as much as the last read when it continues it, or
    /// as the pages read just before (Linux's context read-ahead), up to [`FILL_MAX`]. None when
    /// the page has been read meanwhile or lies past the end.
    pub fn window(&self, page: u64) -> Option<(u64, u64)> {
        let last = self.size().div_ceil(PAGE_SIZE);
        if page >= last || self.has(page) {
            return None;
        }
        let (next, prev) = self.ahead.get();
        let before = self
            .filled
            .borrow()
            .range(..page)
            .next_back()
            .filter(|&(_, &e)| e == page)
            .map_or(0, |(&s, _)| page - s);
        let (lo, hi) = if page == next || before > 0 {
            let size = if page == next { prev } else { before };
            (page, page + (size * 2).clamp(FILL_PAGES, FILL_MAX))
        } else {
            let lo = page.saturating_sub(FILL_PAGES / 2);
            (lo, lo + FILL_PAGES)
        };
        let filled = self.filled.borrow();
        let lo = filled
            .range(..page)
            .next_back()
            .map_or(lo, |(_, &e)| lo.max(e));
        let hi = filled
            .range(page..)
            .next()
            .map_or(hi, |(&s, _)| hi.min(s))
            .min(last);
        Some((lo * PAGE_SIZE, (hi - lo) * PAGE_SIZE))
    }

    /// Like [`Fill::window`], but always starts at `page` (no backward read-around): used when a
    /// read-around short reply stopped before reaching `page`.
    pub fn window_from(&self, page: u64) -> Option<(u64, u64)> {
        let last = self.size().div_ceil(PAGE_SIZE);
        if page >= last || self.has(page) {
            return None;
        }
        let filled = self.filled.borrow();
        let hi = filled
            .range(page..)
            .next()
            .map_or(page + FILL_PAGES, |(&s, _)| (page + FILL_PAGES).min(s))
            .min(last);
        Some((page * PAGE_SIZE, (hi - page) * PAGE_SIZE))
    }

    /// Fill a missing run from its part of the reply, zeroing any short EOF tail.
    fn store_run(&self, first: u64, end: u64, reply: &[u8]) -> Result<(), Errno> {
        use std::os::unix::fs::FileExt;
        let offset = first * PAGE_SIZE;
        let len = ((end * PAGE_SIZE).min(self.size()) - offset) as usize;
        let bytes = &reply[..reply.len().min(len)];
        if bytes.len() == len && self.clean.borrow().range(first..end).next().is_none() {
            return self.host.write_all_at(bytes, offset).map_err(fill_errno);
        }

        // Merge local stores against the old baseline before recording the daemon's bytes.
        let mut merged = vec![0; len];
        merged[..bytes.len()].copy_from_slice(bytes);
        self.overlay(offset, &mut merged)?;
        self.host
            .write_all_at(&merged, offset)
            .map_err(fill_errno)?;
        for (&page, baseline) in self.clean.borrow_mut().range_mut(first..end) {
            let index = ((page - first) * PAGE_SIZE) as usize;
            let src = bytes.get(index..).unwrap_or_default();
            let count = src.len().min(baseline.len());
            baseline[..count].copy_from_slice(&src[..count]);
            baseline[count..].fill(0);
        }
        Ok(())
    }

    /// Stores what was read for [`Fill::window`] `(offset, len)` (`data`): only pages still not
    /// read, as another thread may have read some meanwhile. When `data` is shorter than `len`
    /// before the recorded end of the file, only completely read whole pages are recorded unless
    /// `eof` is true (the daemon returned 0 bytes at the requested offset, confirming early EOF),
    /// in which case only the partial/empty EOF page is marked filled rather than the whole window.
    pub fn store(&self, (offset, len): (u64, u64), data: &[u8], eof: bool) -> Result<(), Errno> {
        let lo = offset / PAGE_SIZE;
        let max_hi = (offset + len) / PAGE_SIZE;
        let hi = if offset.saturating_add(data.len() as u64) >= self.size() {
            max_hi
        } else if eof {
            (lo + (data.len() as u64).div_ceil(PAGE_SIZE).max(1)).min(max_hi)
        } else {
            (lo + (data.len() as u64) / PAGE_SIZE).min(max_hi)
        };
        if hi <= lo {
            return Ok(());
        }
        let mut at = lo;
        for (s, e) in self.runs(lo, hi).into_iter().chain([(hi, hi)]) {
            if at < s {
                let from = ((at - lo) * PAGE_SIZE) as usize;
                self.store_run(at, s, data.get(from..).unwrap_or_default())?;
            }
            at = e;
        }
        Self::insert_run(&mut self.filled.borrow_mut(), lo, hi);
        Self::insert_run(&mut self.materialized.borrow_mut(), lo, hi);
        self.ahead.set((hi, hi - lo));
        Ok(())
    }

    fn insert_run(filled: &mut BTreeMap<u64, u64>, lo: u64, hi: u64) {
        // Merge with the runs it touches
        let (mut s, mut e) = (lo, hi);
        let first = filled.range(..=lo).next_back().map_or(lo, |(&s, _)| s);
        let touching: Vec<u64> = filled
            .range(first..=hi)
            .filter(|&(_, &end)| end >= lo)
            .map(|(&start, _)| start)
            .collect();
        for start in touching {
            let end = filled.remove(&start).unwrap();
            (s, e) = (s.min(start), e.max(end));
        }
        filled.insert(s, e);
    }

    /// Revoke cached data after all address spaces have dropped translations for these pages.
    pub(crate) fn invalidate(&self, lo: u64, hi: u64) {
        let mut filled = self.filled.borrow_mut();
        let first = filled.range(..=lo).next_back().map_or(lo, |(&s, _)| s);
        let overlap: Vec<_> = filled
            .range(first..hi)
            .filter(|&(_, &e)| e > lo)
            .map(|(&s, &e)| (s, e))
            .collect();
        for (start, end) in overlap {
            filled.remove(&start);
            if start < lo {
                filled.insert(start, lo);
            }
            if hi < end {
                filled.insert(hi, end);
            }
        }
        self.ahead.set((u64::MAX, 0));
        self.size_stale.set(true);
        self.generation.set(self.generation.get().wrapping_add(1));
    }
}

fn fill_errno(error: std::io::Error) -> Errno {
    Errno(error.raw_os_error().unwrap_or(Errno::EIO.0))
}

/// Mount reference held by a file-backed VMA: keeps the mount busy for `umount2` and reports its
/// release when the VMA is unmapped or the address space is dropped ([`crate::vfs::released`]).
#[derive(Clone)]
struct MountPin(crate::vfs::MountId);

impl Drop for MountPin {
    fn drop(&mut self) {
        crate::vfs::released(self.0);
    }
}

#[derive(Clone)]
struct Vma {
    len: u64,
    prot: u32,
    backing: Backing,
    /// Whether write permission can be granted: not for a shared mapping of a file opened read-only
    /// (the host mapping itself is read-only).
    may_write: bool,
    /// Whether execute permission can be granted: not for a mapping of a file on a noexec mount
    /// (Linux's `VM_MAYEXEC`).
    may_exec: bool,
    /// A reference to the host memory, released when the last VMA referring to it goes away.
    region: Arc<HostRegion>,
    /// The name shown in `/proc/<pid>/maps` (the mapped file or program) and the file's inode.
    name: Option<Rc<[u8]>>,
    ino: u64,
    /// The ELF interpreter's open file, retained by its file-backed segments.
    interp_open: Option<Rc<crate::syscall::Opened>>,
    /// The mount the mapped file was opened through (None for anonymous, memfd, vvar, SysV shm).
    mnt: Option<MountPin>,
    /// The host address corresponding to this VMA's start. For shared anonymous memory
    /// remapped past its original extent this can be past the host region.
    host: NonNull<u8>,
    /// Bytes with contents, rounded up to 4K. Private anonymous mappings have `len` bytes,
    /// while remapped shared memory ends at the original backing extent. Pages past that end
    /// or a mapped file's EOF get no entries, so guest accesses raise SIGBUS
    /// ([`Mm::fault_past_eof`]) and fork does not read them.
    file_len: u64,
    /// After fork a read-only private file mapping shares its host mapping with other address
    /// spaces; before it becomes writable it copies its own first ([`Mm::mprotect`]).
    cow: bool,
    /// File mappings: the host file's (device, inode) and the file offset of the start. Shared
    /// mappings use it as the futex key; when the file is truncated it finds the pages that map it
    /// ([`Mm::file_truncated`]).
    file_id: Option<(u64, u64, u64)>,
    /// Private file mappings: the version of the file contents when mapped
    /// ([`content::version`]), None when there is no trusted version. A mapping never written
    /// holds the file contents of this version ([`Mm::code_sources`]).
    content: Option<(u64, u64)>,
    /// The mapped file and starting offset, retained across close, fork, splits and mremap.
    file: Option<(Rc<OwnedFd>, u64)>,
    /// A shared memory segment mapped by shmat: the segment (its IPC namespace and id) and the
    /// start of this shmat (unchanged after splitting).
    shm: Option<(crate::ipc::ShmKey, u64)>,
    /// Locked by mlock (only recorded; host memory is never swapped out anywhere the guest could
    /// notice).
    locked: bool,
    /// Anonymous memory has taken a write fault or a direct kernel write. Private files keep
    /// their conservative ever-writable bit for host page tracking. Anonymous contents
    /// never written are all zero and fork need not copy them: checking V8's 8 GB `PROT_NONE`
    /// wasm reservation page by page takes a second.
    written: Cell<bool>,
    /// `MAP_GROWSDOWN`: grows downwards when an address below it is accessed ([`Mm::grow_down`]).
    growsdown: bool,
    /// `MADV_DONTDUMP`: its contents are left out of core files ([`Mm::dump_regions`]).
    dontdump: bool,
    /// `MADV_WIPEONFORK` (private anonymous mappings only): a forked child gets this range
    /// zero-filled instead of a copy, and keeps the flag (Linux's `dup_mmap`). Libraries such as
    /// BoringSSL rely on it to reseed their random number generators in the child.
    wipeonfork: bool,
    /// `MADV_DONTFORK`: a forked child does not get this mapping at all.
    dontfork: bool,
    /// `MAP_NORESERVE`: not counted in the commit ([`Mm::commit_too_big`]).
    noreserve: bool,
    /// Linux VM_ACCOUNT stays set after removing write permission.
    accounted: bool,
    /// Page offset for joining private anonymous pieces, preserved by a faulted mapping's moves.
    anon_pgoff: u64,
    /// The logical anonymous VMA has taken a write, possibly in another host piece.
    has_anon_vma: Cell<bool>,
    /// The anon_vma this mapping would have on Linux, as far as it decides which VMAs are one
    /// ([`same_vma`]): 0 until a fork, after which each child VMA with contents of its own gets
    /// its own, shared by the pieces that were one VMA in the parent. On Linux such child VMAs no
    /// longer merge with their neighbours, while the parent's still do.
    anon: u64,
    /// Per-page faults for tmpfs quota or private writes on hosts without readable pagemap.
    pages: Option<Rc<FilePages>>,
    /// The verified musl mapping uses an immutable snapshot distinct from the pinned store fd.
    snapshot: bool,
    /// A file mapping read on demand ([`Fill`]); its `file_len` stays 0.
    fill: Option<Rc<Fill>>,
}

impl Vma {
    fn eager_len(&self) -> u64 {
        if self.tmpfs().is_some() {
            0
        } else {
            self.file_len
        }
    }

    fn tmpfs(&self) -> Option<&Rc<crate::vfs::TmpfsMapping>> {
        self.pages.as_ref()?.tmpfs.as_ref()
    }

    /// Keep first writes observable for anonymous pieces and software-tracked file pages.
    fn prefill_prot(&self) -> u32 {
        let prot = mmu_prot(self.prot);
        if self.pages.is_some() || self.backing == Backing::Anonymous && !self.written.get() {
            prot & !prot::WRITE
        } else {
            prot
        }
    }

    /// Only reserved, with no host memory yet ([`HostRegion::reserved`]).
    fn reserved(&self) -> bool {
        self.region.reserved
    }

    /// `[vvar]`: the host's memory, only read ([`HostRegion::foreign`]).
    fn foreign(&self) -> bool {
        self.region.foreign
    }

    /// The file offset of its start (0 for anonymous memory).
    fn offset(&self) -> u64 {
        self.file_id.map_or(0, |f| f.2)
    }

    fn anon_pgoff_at(&self, byte_offset: u64) -> u64 {
        self.anon_pgoff.wrapping_add(byte_offset / PAGE_SIZE)
    }

    /// Bytes of the host region available from this start, even after a VMA split or shrink.
    fn host_available(&self) -> u64 {
        let end = self.region.base.as_ptr() as usize + self.region.len;
        end.saturating_sub(self.host.as_ptr() as usize) as u64
    }

    /// Part of this VMA backed by a host mapping, including mapped file pages past EOF.
    fn host_len(&self) -> u64 {
        self.len.min(self.host_available())
    }

    /// Bytes from its start that the host memory may be read at: `file_len`, or for a mapping read
    /// on demand ([`Fill`]) up to its current EOF.
    fn contents_len(&self) -> u64 {
        match &self.fill {
            Some(f) => extent(f.size() as i64, self.offset(), self.len),
            None => self.file_len,
        }
    }

    /// FUSE ranges may share a memfd across independent opens. Combining VMAs must retain
    /// their original open handle and access limits (including a later mprotect).
    fn same_fill_source(&self, other: &Vma) -> bool {
        match (&self.fill, &other.fill) {
            (Some(a), Some(b)) => {
                Rc::ptr_eq(&a.source, &b.source)
                    && Rc::ptr_eq(&a.pages, &b.pages)
                    && self.may_write == other.may_write
                    && self.may_exec == other.may_exec
            }
            (None, None) => true,
            _ => false,
        }
    }

    /// For a mapping read on demand: the file page of guest address `addr` (in this VMA starting
    /// at `start`) and its fill, when that page lies within the file but has not been read.
    fn unread(&self, start: u64, addr: u64) -> Option<(Rc<Fill>, u64)> {
        let fill = self.fill.as_ref()?;
        let page = (self.offset() + (addr - start)) / PAGE_SIZE;
        (addr < start + self.len
            && (addr < start + self.contents_len() || fill.size_stale.get())
            && !fill.has(page))
        .then(|| (fill.clone(), page))
    }

    /// Touches host memory for `[off, off + len)` inside this VMA, marking private mappings
    /// `written` on write-populate.
    ///
    /// # Safety
    ///
    /// `[off, off + len)` must lie within backed, in-EOF host memory of this VMA (and be
    /// host-writable when `write` is true; for `Backing::Anonymous` writes, CoW must already be
    /// settled).
    unsafe fn populate_host(&self, off: usize, len: usize, write: bool) {
        // SAFETY: guaranteed by the caller.
        let host = unsafe { self.host.as_ptr().add(off) };
        if write {
            if self.backing != Backing::Shared {
                self.written.set(true);
            }
            unsafe { populate_write_host(host, len) };
        } else {
            unsafe { appine_hal::populate(host, len) };
        }
    }
}

/// Whether VMA `b`, starting where `a` ends, is part of the same VMA on Linux. Linux merges
/// adjacent VMAs with the same flags and the same source of contents, while here every mapping
/// keeps its own host memory and VMAs are only ever split (the kernel/mm map's D7), so the pieces
/// of one Linux VMA are joined wherever Linux's VMA boundaries show: `/proc/<pid>/maps`
/// ([`Mm::regions`]), mremap's rule that the old range lies in one VMA, and mprotect with
/// `PROT_GROWSDOWN`. Pieces of one shared anonymous mapping have contiguous offsets in the
/// same host region.
fn same_vma(a: &Vma, b: &Vma) -> bool {
    // A fresh DONTUNMAP remnant can keep its original linear offset alongside a
    // faulted source fragment. It has its own lifetime until a later VMA merge.
    a.has_anon_vma.get() == b.has_anon_vma.get() && can_merge(a, b)
}

/// Merge eligibility before an untouched anonymous piece inherits its neighbour's anon_vma.
fn can_merge(a: &Vma, b: &Vma) -> bool {
    let contents = match (a.file_id, b.file_id) {
        (None, None) if a.backing == Backing::Shared => {
            Arc::ptr_eq(&a.region, &b.region)
                && a.shm == b.shm
                && a.host.as_ptr().wrapping_add(a.len as usize) == b.host.as_ptr()
        }
        (None, None) => a.anon_pgoff_at(a.len) == b.anon_pgoff,
        (Some((dev, ino, offset)), Some(next)) => {
            (dev, ino, offset + a.len) == next && a.ino == b.ino
        }
        _ => false,
    };
    contents
        && a.same_fill_source(b)
        && a.backing == b.backing
        && (a.prot, a.locked, a.may_write) == (b.prot, b.locked, b.may_write)
        && (a.growsdown, a.dontdump) == (b.growsdown, b.dontdump)
        && (a.wipeonfork, a.dontfork) == (b.wipeonfork, b.dontfork)
        && a.may_exec == b.may_exec
        && a.noreserve == b.noreserve
        && a.accounted == b.accounted
        && a.anon == b.anon
        && a.name == b.name
}

/// The address space of a guest process.
pub struct Mm {
    // Destroy the page table before releasing the host memory it points at (Drop releases the
    // page table first, then the fields are dropped in declaration order).
    mmu: ManuallyDrop<Mmu>,
    vmas: BTreeMap<u64, Vma>,
    /// Host memory already unmapped, which may be released only after the shootdown completes.
    graveyard: Vec<Arc<HostRegion>>,
    brk_start: u64,
    brk: u64,
    dirty: bool,
    /// Ranges where an executable mapping was torn down or changed permissions or contents: the
    /// translations there must be invalidated.
    code_ranges: Vec<(u64, u64)>,
    /// Identifies the address space in futex keys ([`crate::futex::Key::Private`]); never reused.
    pub id: u64,
    /// Ranges of writable shared mappings ([`Mm::shared_maps`]).
    shared_maps: Arc<RwLock<Vec<(u64, u64)>>>,
    /// Shootdown generation: when it changes, users flush their TLBs before re-entering guest code.
    generation: Arc<AtomicU64>,
    /// Code generation: when it changes, users invalidate Tier 1 translations according to
    /// `code_log`. Changes to data pages (gcc's garbage collector and malloc mmap and munmap
    /// often) do not affect code already translated and leave this generation alone.
    code_generation: Arc<AtomicU64>,
    code_log: Arc<Mutex<CodeLog>>,
    /// Threads using this address space.
    users: Vec<Arc<TaskSync>>,
    /// Tier 1 translations, created when the first thread starts running ([`Mm::code_space`]).
    code_space: Option<Arc<CodeSpace>>,
    /// The translation-sharing group ([`CodeGroup`]) and the tag in it.
    code_group: Option<Rc<CodeGroup>>,
    code_tag: u16,
    /// Has left a group (or could not join one in the first place): never joins again.
    unshareable: bool,
    /// The executable mappings changed; checked against the group's registration at the next
    /// [`Mm::sync`].
    exec_changed: bool,
    /// Incremented when the Tier 1 translations are replaced ([`Generations::space`]).
    space_generation: Arc<AtomicU64>,
    /// Commands registered with membarrier(2) (`MEMBARRIER_CMD_REGISTER_*`).
    pub membarrier: i32,
    /// `mlockall(MCL_FUTURE)`: future mappings are locked too.
    pub lock_future: bool,
    /// `MCL_ONFAULT` was given as well: future mappings are locked but not populated in advance.
    pub lock_onfault: bool,
    /// The store inode of the program file being executed (ETXTBSY).
    pub exe: Option<u64>,
    /// The main program remains open even after its last segment is unmapped.
    pub(crate) exe_open: Option<crate::syscall::Opened>,
    /// Which register set Tier 1 uses when translating this program, chosen per program at
    /// execve (Go gets a different one).
    pub dbt_regs: appine_engine::DbtRegs,
    /// Known libc memop entry PCs discovered in unmodified read-only executable mappings.
    pub memops: Vec<appine_engine::DbtMemop>,
    /// `memops` changed and must be pushed to the active `DbtSpace` at the next [`Mm::sync`].
    memops_dirty: bool,
    /// Load address of the vDSO (signal handlers return to the sigreturn trampoline in it by
    /// default).
    pub vdso: u64,
    /// The vDSO's clock functions are svc stubs answered by the kernel layer: always for the built
    /// image, and for the host's once a process using this address space is in a time namespace
    /// with offsets ([`Mm::vdso_syscalls`]).
    pub vdso_svc: bool,
    /// The main program's code (Linux's `start_code`, `end_code`: its executable segments, to
    /// the end of their file contents) and data (`start_data`, `end_data`: the start of its last
    /// segment, the end of the file contents of all), as the loader mapped them; shown in
    /// `/proc/<pid>/stat`.
    pub code: (u64, u64),
    pub data: (u64, u64),
    /// Range of the argv strings on the initial stack (`/proc/<pid>/cmdline`).
    pub args: (u64, u64),
    /// Range of the envp strings on the initial stack (`/proc/<pid>/environ`).
    pub env: (u64, u64),
    /// The auxv on the initial stack (key-value pairs ending in `AT_NULL`); `/proc/<pid>/auxv`
    /// uses this copy.
    pub auxv: Rc<[u64]>,
    /// Upper bound (exclusive) of the mmap area, set from `RLIMIT_STACK` at execve
    /// ([`Mm::set_layout`]).
    mmap_top: u64,
    /// The initial stack pointer (Linux's `start_stack`): `/proc/<pid>/maps` labels the stack
    /// containing it `[stack]`.
    start_stack: u64,
    /// The current bottom of the main thread's stack; 0 while there is no stack.
    stack_low: u64,
    /// Copy-on-write pages and the loan records shared by one fork family (module docs). Accessed
    /// only while holding the BKL, but also modified through shared borrows from other address
    /// spaces, hence the RefCell.
    cow: RefCell<Cow>,
    loans: Loans,
    /// Its own handle, recorded when lending pages ([`Mm::into_shared`]).
    me: MmRef,
    /// Host mappings of read-only file mappings, shared by all address spaces ([`FileMaps`]).
    files: FileMaps,
    /// Private mappings of the same host inode only need one read descriptor across a fork family.
    private_files: Rc<RefCell<PrivateFiles>>,
    /// A mapping read on demand ([`Fill`]) has been made here (or in the parent before fork).
    fills: bool,
    pub(crate) unmapped_fills: Vec<(Rc<Fill>, u64, u64)>,
}

struct PrivateFile {
    fd: Weak<OwnedFd>,
    pinned: bool,
}

type PrivateFiles = HashMap<(u64, u64), PrivateFile>;

impl Mm {
    // ---- Creation and layout ----

    /// Creates an empty address space.
    pub fn new() -> Self {
        Mm {
            mmu: ManuallyDrop::new(Mmu::new()),
            vmas: BTreeMap::new(),
            graveyard: Vec::new(),
            brk_start: 0,
            brk: 0,
            dirty: false,
            code_ranges: Vec::new(),
            id: {
                static NEXT: AtomicU64 = AtomicU64::new(1);
                NEXT.fetch_add(1, Ordering::Relaxed)
            },
            shared_maps: Arc::default(),
            generation: Arc::new(AtomicU64::new(0)),
            code_generation: Arc::new(AtomicU64::new(0)),
            code_log: Arc::default(),
            users: Vec::new(),
            code_space: None,
            code_group: None,
            code_tag: 0,
            unshareable: false,
            exec_changed: false,
            space_generation: Arc::new(AtomicU64::new(0)),
            membarrier: 0,
            lock_future: false,
            lock_onfault: false,
            exe: None,
            exe_open: None,
            dbt_regs: appine_engine::DbtRegs::Default,
            memops: Vec::new(),
            memops_dirty: false,
            vdso: 0,
            vdso_svc: false,
            code: (0, 0),
            data: (0, 0),
            args: (0, 0),
            env: (0, 0),
            auxv: Rc::from([]),
            mmap_top: STACK_TOP - MIN_GAP,
            start_stack: 0,
            stack_low: 0,
            cow: RefCell::default(),
            loans: Rc::default(),
            me: Weak::new(),
            files: FileMaps::default(),
            private_files: Default::default(),
            fills: false,
            unmapped_fills: Vec::new(),
        }
    }

    /// Shares read-only file mappings with other address spaces ([`FileMaps`]).
    pub fn share_files(&mut self, files: &FileMaps) {
        self.files = files.clone();
    }

    /// Sets the upper bound of the mmap area from the stack size limit `stack_limit` (the
    /// `RLIMIT_STACK` at execve): like Linux's `mmap_base`, it leaves a gap that large for the
    /// stack plus [`STACK_GUARD_GAP`], clamped between [`MIN_GAP`] and [`MAX_GAP`]. When the limit
    /// is unlimited Linux switches to bottom-up allocation (the legacy layout); here allocation
    /// stays top-down with a gap of [`MAX_GAP`].
    pub fn set_layout(&mut self, stack_limit: u64) {
        let gap = stack_limit
            .saturating_add(STACK_GUARD_GAP)
            .clamp(MIN_GAP, MAX_GAP);
        self.mmap_top = (STACK_TOP - gap) & !(PAGE_SIZE - 1);
    }

    /// Creates a zeroed anonymous mapping at a fixed address (used by the loader); the range must
    /// be free.
    pub fn map_anonymous(&mut self, start: u64, len: u64, prot: u32) -> Result<(), Errno> {
        if !start.is_multiple_of(PAGE_SIZE) || len == 0 || !len.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if !self.is_free(start, len) {
            return Err(Errno::EEXIST);
        }
        let (region, host) = Self::private_anonymous(len, prot, prot & prot::WRITE != 0)?;
        self.insert(
            start,
            len,
            len,
            prot,
            Backing::Anonymous,
            true,
            region,
            host,
        )
    }

    /// Maps the host's vvar pages as `[vvar]` at a fixed address (used by the loader, below the
    /// vDSO; the range must be free): `len` bytes, of which the first `data` are readable host
    /// memory at `host`, the host's clock data that the host's vDSO code reads. The rest (the
    /// time-namespace page, newer kernels' random-number state) has no entries: accesses get
    /// SIGBUS ([`Mm::fault_past_eof`]), as on Linux outside a time namespace. Like Linux's special
    /// mapping it is private, cannot be made writable or executable, is shared by forked children,
    /// counts towards no resident memory and is not written to core files.
    pub fn map_vvar(&mut self, start: u64, len: u64, host: usize, data: u64) -> Result<(), Errno> {
        if !self.is_free(start, len) {
            return Err(Errno::EEXIST);
        }
        let host = NonNull::new(host as *mut u8).ok_or(Errno::EINVAL)?;
        let region = Arc::new(HostRegion {
            base: host,
            len: data as usize,
            anonymous: None,
            used_start: AtomicUsize::new(0),
            used_end: AtomicUsize::new(0),
            reserved: false,
            foreign: true,
            gpu: None,
        });
        self.insert(
            start,
            len,
            data,
            prot::READ,
            Backing::Shared,
            false,
            region,
            host,
        )?;
        self.vmas.get_mut(&start).unwrap().may_exec = false;
        Ok(())
    }

    /// Replaces the entries of the vDSO's clock functions with svc stubs, so they enter the kernel
    /// layer, which applies the time namespace's offsets (a process using this address space
    /// entered a time namespace with offsets; Linux's vDSO reads them from a namespace page
    /// instead). The built image's functions already are stubs. Not undone: the stubs are right in
    /// any time namespace, only slower.
    pub fn vdso_syscalls(&mut self) -> Result<(), Errno> {
        if self.vdso_svc || self.vdso == 0 {
            return Ok(());
        }
        for (offset, nr) in crate::vdso::clocks() {
            self.write_kernel(self.vdso + offset, &crate::vdso::svc_bytes(nr))?;
        }
        let len = (crate::vdso::image().len() as u64).next_multiple_of(PAGE_SIZE);
        self.invalidate_code(self.vdso, len);
        self.vdso_svc = true;
        Ok(())
    }

    /// The image the vDSO's pages come back as after being discarded: the one mapped at execve,
    /// with svc stubs once [`Mm::vdso_syscalls`] put them in.
    fn vdso_image(&self) -> &'static [u8] {
        if self.vdso_svc {
            crate::vdso::svc_image()
        } else {
            crate::vdso::image()
        }
    }

    /// Sets the initial program break (used by the loader).
    pub fn set_brk(&mut self, start: u64) {
        self.brk_start = start;
        self.brk = start;
    }

    /// Where the heap starts (Linux's `start_brk`).
    pub fn brk_start(&self) -> u64 {
        self.brk_start
    }

    /// The current program break.
    pub fn brk_current(&self) -> u64 {
        self.brk
    }

    /// The initial stack pointer (Linux's `start_stack`).
    pub fn start_stack(&self) -> u64 {
        self.start_stack
    }

    /// Maps the main thread's initial stack `[STACK_TOP - len, STACK_TOP)` (used by the loader):
    /// readable and writable, growing downwards. Host memory is reserved below it up to `reserve`
    /// bytes in all (taking no memory until touched), and while the stack grows within that range
    /// the same VMA is only lengthened in place.
    pub fn map_stack(&mut self, len: u64, reserve: u64) -> Result<(), Errno> {
        let start = STACK_TOP - len;
        if !self.is_free(start, len) {
            return Err(Errno::EEXIST);
        }
        let (region, base) = Self::new_anonymous_reserved(reserve.max(len))?;
        // SAFETY: this host memory is at least len bytes
        let host = unsafe { NonNull::new_unchecked(base.as_ptr().add(region.len - len as usize)) };
        let rw = prot::READ | prot::WRITE;
        let mut v = self.new_vma(start, len, len, rw, Backing::Anonymous, true, region, host);
        v.growsdown = true;
        self.insert_vma(start, v)?;
        self.stack_low = start;
        Ok(())
    }

    /// Records the initial stack pointer (used by the loader).
    pub fn set_start_stack(&mut self, sp: u64) {
        self.start_stack = sp;
    }

    /// Records the file's name and inode for file mappings starting in `[start, start + len)` (for
    /// `/proc/<pid>/maps`). As on Linux, the anonymous mapping in between (.bss) has no name.
    pub fn label(&mut self, start: u64, len: u64, name: Option<Rc<[u8]>>, ino: u64) {
        for (_, v) in self.vmas.range_mut(start..start.saturating_add(len)) {
            if v.file_id.is_some() {
                v.name = name.clone();
                v.ino = ino;
            }
        }
    }

    pub(crate) fn keep_interp_open(&mut self, start: u64, end: u64, file: &crate::syscall::Opened) {
        let open = Rc::new(file.clone());
        for (_, v) in self.vmas.range_mut(start..end) {
            if v.file_id.is_some() {
                v.interp_open = Some(open.clone());
            }
        }
    }

    /// Records the mount through which the file mapped at `[start, start + len)` was opened
    /// (keeps the mount busy for `umount2` and reports its release when unmapped).
    pub fn set_mnt(&mut self, start: u64, len: u64, mnt: crate::vfs::MountId) {
        for (_, v) in self.vmas.range_mut(start..start.saturating_add(len)) {
            if v.file_id.is_some() || v.region.gpu.is_some() {
                v.mnt = Some(MountPin(mnt));
            }
        }
    }

    /// Inserts the mounts of all file-backed VMAs in this address space into `out` (for `umount2`
    /// busy checks and detached-mount collection).
    pub fn mapped_mounts(&self, out: &mut std::collections::HashSet<crate::vfs::MountId>) {
        for v in self.vmas.values() {
            if let Some(m) = &v.mnt {
                out.insert(m.0);
            }
        }
    }

    /// Inserts the store inode numbers of file-backed VMAs in this address space into `out`
    /// (keeps unlinked tmpfs files charged while still mapped).
    pub fn mapped_inos(&self, out: &mut std::collections::HashSet<u64>) {
        for v in self.vmas.values() {
            if v.ino != 0 && v.fill.is_none() {
                out.insert(v.ino);
            }
        }
    }

    /// Inserts `(mount, inode)` for non-FUSE file-backed VMAs and the pinned backing open file for
    /// FUSE VMAs (both `MAP_PRIVATE` and `MAP_SHARED`), used by `sb_busy` when turning a
    /// filesystem instance read-only.
    pub fn mapped_file_inos(
        &self,
        store_out: &mut Vec<(crate::vfs::MountId, u64)>,
        fuse_out: &mut Vec<crate::fd::FileRef>,
    ) {
        for v in self.vmas.values() {
            if let Some(fill) = &v.fill {
                fuse_out.push(fill.source.clone());
            } else if let Some(m) = &v.mnt
                && v.ino != 0
            {
                store_out.push((m.0, v.ino));
            }
        }
    }

    /// Whether any non-FUSE file-backed VMA in this address space maps store inode `ino`.
    pub fn maps_ino(&self, ino: u64) -> bool {
        ino != 0 && self.vmas.values().any(|v| v.ino == ino && v.fill.is_none())
    }

    /// Restores the non-lock VMA flags on a private-file remnant recreated at the old address
    /// after `mremap(MREMAP_DONTUNMAP)`.
    pub fn apply_refill_flags(&mut self, r: &Refill) {
        if let Some(v) = self.vmas.get_mut(&r.start) {
            r.flags.apply_to(v);
            v.interp_open = r.interp_open.clone();
        }
    }

    /// Guest range `[start, end)` of the mapped vDSO, if still recorded.
    fn vdso_range(&self) -> Option<(u64, u64)> {
        (self.vdso != 0).then(|| {
            let len = (crate::vdso::image().len() as u64).next_multiple_of(PAGE_SIZE);
            (self.vdso, self.vdso + len)
        })
    }

    /// Puts it into an `Rc<RefCell<..>>` (the form `TaskState` holds) and records its own handle:
    /// when a borrower returns the last borrow, it lets the owner restore write permission through
    /// it.
    pub fn into_shared(self) -> Rc<RefCell<Mm>> {
        Rc::new_cyclic(|me| {
            let mut mm = self;
            mm.me = me.clone();
            RefCell::new(mm)
        })
    }

    /// This address space's software page table.
    pub fn mmu(&self) -> &Mmu {
        &self.mmu
    }

    // ---- Threads, shootdown and code groups ----

    /// Registers a thread that starts using this address space.
    pub fn add_user(&mut self, user: Arc<TaskSync>) {
        self.users.push(user);
    }

    /// The shootdown generation, the code generation and the code-change log ([`Mm::sync`]).
    pub fn generations(&self) -> Generations {
        Generations {
            tlb: self.generation.clone(),
            code: self.code_generation.clone(),
            log: self.code_log.clone(),
            space: self.space_generation.clone(),
        }
    }

    /// This address space's Tier 1 translations, created if missing; None when the host does not
    /// support Tier 1. Shared with other address spaces of the same program that map consistently
    /// ([`CodeGroup`]); otherwise the translations the same program (by executable inode) left in
    /// the pool are preferred, and they are checked block by block before their first run.
    pub fn code_space(&mut self, groups: &CodeGroups) -> Option<Arc<CodeSpace>> {
        if self.code_space.is_none() {
            let space = match self.join_group(groups) {
                Some(space) => space,
                None => {
                    let space = appine_engine::DbtSpace::new(self.exe.unwrap_or(0), self.dbt_regs)?;
                    // With translations a previous user left in the pool, blocks in program files
                    // of the same version need no further check
                    space.trust(&self.code_sources());
                    self.found_group(groups, &space);
                    space
                }
            };
            self.code_space = Some(Arc::new(CodeSpace {
                space,
                tag: self.code_tag,
                seen: Mutex::new(self.code_generation.load(Ordering::SeqCst)),
            }));
            self.memops_dirty = true;
            self.sync_memops();
        }
        self.code_space.clone()
    }

    /// Joins a consistently mapped group of the same program and returns its translations.
    fn join_group(&mut self, groups: &CodeGroups) -> Option<Arc<appine_engine::DbtSpace>> {
        let key = self.exe.filter(|_| !self.unshareable)?;
        let (layout, private) = self.exec_split();
        let candidates: Vec<_> = groups
            .borrow()
            .iter()
            .filter_map(Weak::upgrade)
            .filter(|g| g.key == key && !g.closed.get())
            .collect();
        for group in candidates {
            let Some(tag) = group.space.new_tag() else {
                // Out of tags: accept no new members; later processes start another group
                group.closed.set(true);
                continue;
            };
            if !group.admit(tag, &layout, &private) {
                continue;
            }
            group.members.set(group.members.get() + 1);
            // There was only one member: the translations it took from the pool may still hold
            // blocks valid only for it (left by the previous user)
            if !group.shared.replace(true) {
                group.space.retire_outside(&group.ranges.borrow());
            }
            let space = group.space.clone();
            self.code_group = Some(group);
            self.code_tag = tag;
            return Some(space);
        }
        None
    }

    /// Executable mappings whose contents are determined by the file and version
    /// ([`appine_engine::DbtSource`]): private file mappings never written that have a trusted
    /// version ([`content::version`]). They are recorded before the translations go back to the
    /// pool, and when the next user's mapping at the same place is the same piece of the same
    /// version of the file, the blocks in it need no block-by-block check (which reads every
    /// page of the program's and the dynamic linker's code segments, every time the shell spawns
    /// a process).
    fn code_sources(&self) -> Vec<appine_engine::DbtSource> {
        self.vmas
            .iter()
            .filter(|(_, v)| {
                v.prot & prot::EXEC != 0 && v.backing == Backing::PrivateFile && !v.written.get()
            })
            .filter_map(|(&start, v)| {
                let ((dev, ino, offset), (ctime, size)) = (v.file_id?, v.content?);
                Some(appine_engine::DbtSource {
                    start,
                    len: v.len,
                    id: [dev, ino, offset, ctime, size],
                })
            })
            .take(appine_engine::DbtSpace::SOURCES)
            .collect()
    }

    /// Just created its own translations: opens a group for other address spaces of the same
    /// program to join.
    fn found_group(&mut self, groups: &CodeGroups, space: &Arc<appine_engine::DbtSpace>) {
        let Some(key) = self.exe.filter(|_| !self.unshareable) else {
            return;
        };
        let (layout, private) = self.exec_split();
        let Some(tag) = (layout.len() <= CodeGroup::MAX_RANGES)
            .then(|| space.new_tag())
            .flatten()
        else {
            self.unshareable = true;
            return;
        };
        space.share(&layout);
        let group = Rc::new(CodeGroup {
            key,
            space: space.clone(),
            members: Cell::new(1),
            ranges: RefCell::new(layout),
            claims: RefCell::new(private.iter().map(|&(s, e)| (tag, s, e)).collect()),
            memops: RefCell::new(Vec::new()),
            closed: Cell::new(false),
            shared: Cell::new(false),
        });
        let mut groups = groups.borrow_mut();
        groups.retain(|g| g.strong_count() > 0);
        groups.push(Rc::downgrade(&group));
        self.code_group = Some(group);
        self.code_tag = tag;
    }

    /// The guest modified the code in `[start, start + len)` (`ic ivau`); the translations there
    /// are invalidated at the next [`Mm::sync`].
    pub fn invalidate_code(&mut self, start: u64, len: u64) {
        self.code_ranges.push((start, len));
    }

    /// Drops any recorded memop entry whose PC falls in an invalidated range or no longer lies in
    /// an unmodified read-only executable mapping.
    pub(crate) fn prune_memops(&mut self, invalidated: &[(u64, u64)]) {
        let before = self.memops.len();
        self.memops.retain(|m| {
            let hit = invalidated
                .iter()
                .any(|&(s, len)| m.pc >= s && m.pc - s < len);
            if hit {
                return false;
            }
            let Some((&s, v)) = self.vmas.range(..=m.pc).next_back() else {
                return false;
            };
            m.pc < s + v.len
                && (v.prot & prot::EXEC) != 0
                && (v.prot & prot::WRITE) == 0
                && v.backing != Backing::Shared
                && !v.written.get()
        });
        if self.memops.len() != before {
            self.memops_dirty = true;
        }
    }

    /// Publishes discovered memop entry PCs to the active `DbtSpace`. In a `CodeGroup`, only PCs
    /// inside the group's admitted shared ranges are merged so one member's private mappings cannot
    /// affect another member.
    fn sync_memops(&mut self) {
        if !std::mem::take(&mut self.memops_dirty) {
            return;
        }
        if let Some(group) = &self.code_group {
            let ranges = group.ranges.borrow();
            let mut gops = group.memops.borrow_mut();
            let before = gops.len();
            for &m in &self.memops {
                let in_group = ranges
                    .iter()
                    .any(|r| m.pc >= r.start && m.pc - r.start < r.len);
                if in_group && !gops.iter().any(|existing| existing.pc == m.pc) {
                    gops.push(m);
                }
            }
            if gops.len() != before {
                group.space.set_memops(&gops);
            }
        } else if let Some(cs) = &self.code_space {
            cs.space.set_memops(&self.memops);
        }
    }

    /// If mappings were torn down or lost permissions, does a TLB shootdown and then releases the
    /// unmapped host memory; when only code must be invalidated, it only records the ranges and
    /// bumps the generation.
    ///
    /// The caller holds the BKL; `current` is the calling thread, which flushes by itself before
    /// re-entering guest code.
    pub fn sync(&mut self, current: &Arc<TaskSync>) {
        self.sync_except(Some(current));
    }

    /// A host caller has no current guest thread, so every user takes part in the shootdown.
    pub fn sync_except(&mut self, current: Option<&Arc<TaskSync>>) {
        let exec_changed = self.exec_changed;
        self.check_code_group();
        let code = std::mem::take(&mut self.code_ranges);
        if !self.memops.is_empty() && (!code.is_empty() || exec_changed) {
            self.prune_memops(&code);
        }
        self.sync_memops();
        let dirty = std::mem::take(&mut self.dirty);
        if !dirty && code.is_empty() {
            return;
        }
        // Record the ranges before bumping the generation: a user that reads the new generation
        // is sure to find its ranges. SeqCst pairs with the user's "mark running guest code, then
        // read the generation": either it reads the new generation, or this side sees it running
        // and waits until it has been kicked and left
        if !code.is_empty() {
            let generation = self.code_generation.load(Ordering::Relaxed) + 1;
            self.code_log.lock().unwrap().push(generation, &code);
            self.code_generation.store(generation, Ordering::SeqCst);
        }
        if !dirty && self.graveyard.is_empty() {
            // Only code changed (a JIT's ic ivau): the translations are shared by this address
            // space's threads, and the thread that changed the code invalidates once before
            // re-entering guest code, after which the invalidated blocks' entries jump to the
            // forwarding stub, so other users need not be kicked. Until then they may still run
            // the old translations, just as other cores on hardware may still run old
            // instructions before context synchronization. Waiting is what membarrier's SYNC_CORE
            // (which calls quiesce) is for
            return;
        }
        if dirty {
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        self.quiesce_except(current);
        self.graveyard.clear();
    }

    /// Checks against the group's registration after the executable mappings changed
    /// ([`CodeGroup`]); leaves the group when they disagree.
    fn check_code_group(&mut self) {
        if !std::mem::take(&mut self.exec_changed) {
            return;
        }
        let Some(group) = self.code_group.clone() else {
            return;
        };
        let (layout, private) = self.exec_split();
        if group.admit(self.code_tag, &layout, &private) {
            return;
        }
        crate::debug::log(format_args!(
            "Tier 1: an address space leaves the shared translations of inode {} ({} members): \
             an executable mapping differs from theirs",
            group.key,
            group.members.get()
        ));
        group.claims.borrow_mut().retain(|c| c.0 != self.code_tag);
        self.unshareable = true;
        self.code_group = None;
        self.code_tag = 0;
        if group.members.get() == 1 {
            // Only itself: keep the existing translations and accept no new members. The
            // registered mappings hold blocks translated by other members (who exited or left),
            // and at the same addresses it maps different files (that is exactly why it leaves):
            // invalidate those blocks and keep only the ones consistent with its mappings
            group.closed.set(true);
            group.space.retire_outside(&group.consistent(&layout));
            self.memops_dirty = true;
            return;
        }
        group.members.set(group.members.get() - 1);
        // Switch to translations of its own. Other threads may be running the group's translations:
        // kick them (the shootdown of [`Mm::sync`]); they see the new generation and switch before
        // re-entering guest code
        self.code_space = None;
        self.space_generation.fetch_add(1, Ordering::SeqCst);
        self.dirty = true;
    }

    /// All executable mappings: the trusted identities ([`Mm::exec_source`]) and the remaining
    /// ranges `[start, end)` (JIT output, code that was written; adjacent ones merged).
    fn exec_split(&self) -> (Vec<appine_engine::DbtSource>, Vec<(u64, u64)>) {
        let (mut trusted, mut private) = (Vec::new(), Vec::<(u64, u64)>::new());
        for (&start, v) in self.vmas.iter().filter(|(_, v)| v.prot & prot::EXEC != 0) {
            match self.exec_source(start, v) {
                Some(s) => trusted.push(s),
                None => match private.last_mut() {
                    Some(last) if last.1 == start => last.1 = start + v.len,
                    _ => private.push((start, start + v.len)),
                },
            }
        }
        (trusted, private)
    }

    /// Whether an executable mapping can share translations with other address spaces: if so,
    /// returns its identity. Trusted are private file mappings that were never written and have a
    /// version, and an unmodified vDSO (the same in every process).
    fn exec_source(&self, start: u64, v: &Vma) -> Option<appine_engine::DbtSource> {
        if start == self.vdso && v.backing == Backing::Anonymous {
            // Read through the page table: a forked child's pages are borrowed from the parent and
            // its own host memory is still zero
            let image = crate::vdso::image();
            let mut bytes = vec![0; image.len()];
            let read = self.read(UserSlice::new(start, image.len()), &mut bytes);
            return (read.is_ok() && bytes == image).then_some(appine_engine::DbtSource {
                start,
                len: v.len,
                id: CodeGroup::VDSO_ID,
            });
        }
        if v.backing != Backing::PrivateFile || v.written.get() {
            return None;
        }
        let ((dev, ino, offset), (ctime, size)) = (v.file_id?, v.content?);
        Some(appine_engine::DbtSource {
            start,
            len: v.len,
            id: [dev, ino, offset, ctime, size],
        })
    }

    /// Kicks the other users running guest code and waits until all have left. They next take the
    /// BKL, which the caller holds, so no guest code runs in this address space until the caller
    /// releases the BKL (fork relies on this for a consistent snapshot of memory).
    pub fn quiesce(&self, current: &Arc<TaskSync>) {
        self.quiesce_except(Some(current));
    }

    fn quiesce_except(&self, current: Option<&Arc<TaskSync>>) {
        let others = self
            .users
            .iter()
            .filter(|u| current.is_none_or(|c| !Arc::ptr_eq(u, c)));
        for user in others.clone() {
            // SAFETY: a thread unregisters from users (holding the BKL) before destroying its Cpu
            unsafe { user.kicker.kick() };
        }
        for user in others {
            while user.in_guest.load(Ordering::SeqCst) {
                std::thread::yield_now();
            }
        }
    }

    /// Whether other threads still use this address space.
    pub fn shared_with_others(&self) -> bool {
        self.users.len() > 1
    }

    /// Unregisters a thread that no longer uses this address space (exit or execve).
    pub fn remove_user(&mut self, user: &Arc<TaskSync>) {
        self.users.retain(|u| !Arc::ptr_eq(u, user));
        // Emit the final close under the BKL when the address space loses its last user.
        if self.users.is_empty() && self.exe_open.take().is_some() {
            for v in self.vmas.values_mut() {
                v.interp_open = None;
            }
        }
    }

    // ---- Guest page faults ----

    /// On-demand filling ([`EAGER_MAX`]): called when a guest access to `addr` faults, or when the
    /// kernel layer reads or writes it. If the page has no entry yet and its VMA allows the access
    /// (`need`), builds the entries of every page in the same leaf table (2 MB, or
    /// [`FILE_FAULT_SPAN`] for read-only non-FUSE file mappings) that belongs to this VMA and has
    /// none yet, and returns true; retrying the access then works. Pages of a file mapping past
    /// the end of the file get none ([`Mm::fault_past_eof`]). Needs only a shared borrow: it is
    /// also called when the kernel layer reads or writes another process's memory (ptrace,
    /// process_vm_readv). Filling absent entries or granting write permission needs no TLB flush.
    pub fn fault_in(&self, addr: u64, need: u32) -> bool {
        self.try_fault_in(addr, need).unwrap_or(false)
    }

    /// Attach an anon_vma to every piece of this Linux VMA. Only the piece actually
    /// written needs writable PTEs or lending at fork.
    fn attach_anon_vma(&self, start: u64) {
        let v = &self.vmas[&start];
        if v.has_anon_vma.replace(true) {
            return;
        }
        let (mut at, mut next) = (start, v);
        for (&s, prev) in self.vmas.range(..start).rev() {
            if s + prev.len != at || !can_merge(prev, next) || prev.has_anon_vma.replace(true) {
                break;
            }
            (at, next) = (s, prev);
        }
        let (mut end, mut prev) = (start + v.len, v);
        for (&s, next) in self.vmas.range(end..) {
            if s != end || !can_merge(prev, next) || next.has_anon_vma.replace(true) {
                break;
            }
            (end, prev) = (s + next.len, next);
        }
    }

    /// A mapping or a flag change can join an untouched piece to a faulted Linux VMA.
    fn join_anon_vmas_at(&self, addr: u64) {
        let Some(right) = self.vmas.get(&addr) else {
            return;
        };
        if right.backing == Backing::Anonymous
            && let Some((&s, left)) = self.vmas.range(..addr).next_back()
            && s + left.len == addr
            && left.has_anon_vma.get() != right.has_anon_vma.get()
            && can_merge(left, right)
        {
            self.attach_anon_vma(if left.has_anon_vma.get() { addr } else { s });
        }
    }

    /// Before the first anonymous store, enable writes on existing entries. An unwritten
    /// piece cannot have loans. Later writes must leave their permissions to the CoW path.
    fn prepare_anon_write(&self, s: u64, v: &Vma) -> Result<(), Errno> {
        if v.backing == Backing::Anonymous && !v.written.replace(true) {
            self.attach_anon_vma(s);
            if v.prot & prot::WRITE != 0 {
                self.mmu
                    .protect_shared(s, v.len, mmu_prot(v.prot))
                    .map_err(map_err)?;
            }
        }
        Ok(())
    }

    pub(crate) fn try_fault_in(&self, addr: u64, need: u32) -> Result<bool, Errno> {
        let page = addr & !(PAGE_SIZE - 1);
        let Some((&s, v)) = self.vmas.range(..=page).next_back() else {
            return Ok(false);
        };
        let p = mmu_prot(v.prot);
        let end = s + v.contents_len().min(v.len);
        if page >= end || p == 0 || p & need != need {
            return Ok(false);
        }
        let present = self.mmu.next_present(page, page + PAGE_SIZE) == page;
        if let Some(t) = &v.pages
            && (t.tmpfs.is_some() || need & prot::WRITE != 0)
        {
            if present && (need & prot::WRITE == 0 || self.mmu.translate(page, need).is_some()) {
                return Ok(false);
            }
            let writable = t.admit(v, page - s, need & prot::WRITE != 0)?;
            let flags = if writable { p } else { p & !prot::WRITE };
            let result = if present {
                self.mmu.protect_shared(page, PAGE_SIZE, flags)
            } else {
                // SAFETY: this page lies inside the mapped extent retained by the VMA.
                let host = unsafe { v.host.add((page - s) as usize) };
                unsafe { self.mmu.fill_shared(page, host, PAGE_SIZE, flags) }
            };
            return Ok(result.is_ok());
        }
        if v.backing == Backing::Anonymous {
            let cow = self.cow.borrow();
            let host = if let Some(b) = cow.borrowed.get(&page) {
                Some(b.host)
            } else {
                cow.lent.contains(&page).then(|| Self::own_page(s, v, page))
            };
            if let Some(host) = host {
                if need & prot::WRITE != 0 || present {
                    return Ok(false);
                }
                // SAFETY: the VMA or borrowed record retains this page.
                return Ok(unsafe {
                    cow_map_shared(&self.mmu, page, host, PAGE_SIZE, Self::read_only(v))
                }
                .is_ok());
            }
        }
        if v.backing == Backing::Anonymous && need & prot::WRITE != 0 {
            if present && self.mmu.translate(page, need).is_some() {
                return Ok(false);
            }
            self.prepare_anon_write(s, v)?;
            if present {
                if self.mmu.translate(page, need).is_some() {
                    return Ok(true);
                }
                // A partial superpage demotion may have failed during the first upgrade.
                return Ok(self.mmu.protect_shared(page, PAGE_SIZE, p).is_ok());
            }
        }
        if present {
            return Ok(false);
        }
        let span = if v.file_id.is_some() && v.fill.is_none() && v.prot & prot::WRITE == 0 {
            FILE_FAULT_SPAN
        } else {
            LEAF_SPAN
        };
        let lo = (page & !(span - 1)).max(s);
        let hi = ((page | (span - 1)) + 1).min(end);
        if v.backing == Backing::Anonymous {
            return Ok(self.fill_anon_non_cow(s, v, lo, hi).is_ok());
        }
        let Some(fill) = &v.fill else {
            // SAFETY: [lo, hi) is inside the part of this VMA with contents, and it holds the host
            // memory
            let host = unsafe { v.host.add((lo - s) as usize) };
            return Ok(
                unsafe { self.mmu.fill_shared(lo, host, hi - lo, v.prefill_prot()) }.is_ok(),
            );
        };
        // Read on demand: only the pages already read
        if v.unread(s, page).is_some() {
            return Ok(false);
        }
        let first = (v.offset() / PAGE_SIZE) as i128 - (s / PAGE_SIZE) as i128;
        let guest = |p: u64| ((p as i128 - first) as u64) * PAGE_SIZE;
        let file = |a: u64| ((a / PAGE_SIZE) as i128 + first) as u64;
        for (a, b) in fill.runs(file(lo), file(hi)) {
            if v.backing == Backing::Shared && v.may_write && fill.track(a, b).is_err() {
                return Ok(false);
            }
            let (from, to) = (guest(a), guest(b));
            // SAFETY: [from, to) is inside the part of this VMA with contents, and it holds the
            // host memory
            let host = unsafe { v.host.add((from - s) as usize) };
            if unsafe { self.mmu.fill_shared(from, host, to - from, p) }.is_err() {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// For a guest access to `addr` that [`Mm::fault_in`] could not satisfy: the page of an
    /// on-demand file mapping ([`Fill`]) still to be read, when the mapping allows the access
    /// (`need`). The caller reads it and retries.
    pub fn fill_wanted(&self, addr: u64, need: u32) -> Option<(Rc<Fill>, u64)> {
        let (&s, v) = self.vmas.range(..=addr).next_back()?;
        let p = mmu_prot(v.prot);
        if addr >= s + v.len || p == 0 || p & need != need {
            return None;
        }
        v.unread(s, addr)
    }

    /// Whether some mapping is read on demand ([`Fill`]): only then can a buffer need reading
    /// before a syscall uses it ([`Mm::first_unread`]).
    pub fn has_fills(&self) -> bool {
        self.fills
    }

    /// The first page of `[addr, addr + len)` that lies in an on-demand file mapping ([`Fill`])
    /// allowing `need` (any mapping, even `PROT_NONE`, when 0) and has not been read.
    pub fn first_unread(&self, addr: u64, len: u64, need: u32) -> Option<(Rc<Fill>, u64)> {
        let end = addr.saturating_add(len);
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        for (&s, v) in self.vmas.range(first..end) {
            let p = mmu_prot(v.prot);
            if v.fill.is_none() || need != 0 && (p == 0 || p & need != need) {
                continue;
            }
            let fill = v.fill.as_ref().unwrap();
            let extent = if fill.size_stale.get() {
                v.len
            } else {
                v.contents_len()
            };
            let (from, to) = (addr.max(s), end.min(s + extent));
            if from >= to {
                continue;
            }
            let first = v.offset() / PAGE_SIZE;
            let (lo, hi) = ((from - s) / PAGE_SIZE, (to - s).div_ceil(PAGE_SIZE));
            if let Some(page) = fill.first_missing(first + lo, first + hi) {
                return Some((fill.clone(), page));
            }
        }
        None
    }

    /// The error of a kernel access to `addr` that found no page (`need`): when it is a page of an
    /// on-demand file mapping still to be read, [`Errno::FUSE_RETRY`], recording it for the
    /// dispatcher ([`take_wanted`]); EFAULT otherwise.
    fn miss(&self, addr: u64, need: u32) -> Errno {
        self.fill_wanted(addr, need)
            .map_or(Errno::EFAULT, request_fill)
    }

    /// Called when a guest access to `addr` requiring permission `need` faults. Checks VMA
    /// permissions first (so `PROT_NONE` or a write to a read-only mapping past EOF delivers
    /// `SIGSEGV`/`SEGV_ACCERR`, not `SIGBUS`). Returns `Some(true)` if the permitted address lies
    /// past the end of the file (raising `SIGBUS`); if the mapped file has grown
    /// since, maps the new contents and returns `Some(false)` so the instruction can re-execute.
    /// Returns `None` otherwise.
    pub fn fault_past_eof(&mut self, addr: u64, need: u32) -> Option<bool> {
        let (&s, v) = self.vmas.range(..=addr).next_back()?;
        if addr >= s + v.len || v.prot & need == 0 || addr < s + v.contents_len() {
            return None;
        }
        if !self.refresh_file_extent(addr)? {
            return Some(true);
        }
        // A large VMA can already be demand-paged. Fill the leaf containing the actual fault.
        match self.try_fault_in(addr, need) {
            Ok(filled) => filled.then_some(false),
            Err(_) => Some(true),
        }
    }

    /// Refresh a stale extent after a mapped file grows. The caller has already found that
    /// `addr` falls inside this VMA beyond its previous EOF.
    fn refresh_file_extent(&mut self, addr: u64) -> Option<bool> {
        let (&s, v) = self.vmas.range(..=addr).next_back()?;
        // The fill already tracks the current size of its memfd.
        if v.fill.is_some() {
            return Some(false);
        }
        let Some((fd, offset)) = &v.file else {
            return Some(false);
        };
        let raw = std::os::fd::AsRawFd::as_raw_fd(&**fd);
        let extent = file_extent(raw, *offset, v.len);
        if addr >= s + extent {
            return Some(false);
        }
        let from = v.file_len;
        let start = s + from;
        // Fork or mprotect may have copied private pages to anonymous memory. A cached
        // read-only mapping can also refer to an immutable snapshot. Keep its existing
        // pages and give the previously inaccessible tail a private mapping of the file.
        if v.backing == Backing::PrivateFile && (v.region.anonymous.is_some() || v.cow) {
            if from != 0 {
                self.room_for(1).ok()?;
            }
            let mapping = appine_hal::map_file(
                raw,
                offset.checked_add(from)?,
                (v.len - from) as usize,
                false,
                true,
            )
            .ok()?;
            let region = HostRegion::file(mapping.base, mapping.len);
            self.split_at(start);
            let tail = self.vmas.get_mut(&start)?;
            tail.host = mapping.ptr;
            tail.region = region;
            tail.cow = false;
            tail.snapshot = false;
            if let Some(pages) = &mut tail.pages {
                *pages = FilePages::new(pages.tmpfs.clone(), BTreeSet::new());
            }
            tail.content = None;
            tail.file_len = extent - from;
        } else {
            let v = self.vmas.get_mut(&s)?;
            v.file_len = extent;
            v.content = None;
        }
        Some(true)
    }

    /// The current bottom of the main thread's stack; 0 while there is no stack.
    pub fn stack_low(&self) -> u64 {
        self.stack_low
    }

    /// Called on an access to unmapped `addr` (a guest access fault, or before the kernel accesses
    /// guest memory): if the mapping right above it grows downwards (the main thread's stack,
    /// `MAP_GROWSDOWN`), extends the mapping to the page of `addr` and returns true. As with
    /// Linux's `expand_downwards`, after the extension a gap of [`STACK_GUARD_GAP`] must remain
    /// to the accessible mapping below, and the size may not exceed `limit` (the current
    /// `RLIMIT_STACK`); otherwise it does not grow (the guest gets SIGSEGV, a kernel access gets
    /// EFAULT).
    ///
    /// If there is reserved room below its host memory, the VMA is lengthened in place. Otherwise
    /// another piece is allocated: the grown part is a new VMA whose host memory reserves room
    /// below it as large as the current stack, so the number of VMAs grows only logarithmically
    /// with the stack.
    #[cfg(test)]
    pub fn grow_down(&mut self, addr: u64, limit: u64) -> bool {
        self.grow_down_limited(addr, limit, u64::MAX)
    }

    /// Like [`Mm::grow_down`], also enforcing `memlock_limit` (`RLIMIT_MEMLOCK`, or `u64::MAX`
    /// with `CAP_IPC_LOCK`) when the grows-down VMA is locked (`VM_LOCKED`, Linux's
    /// `acct_stack_growth`).
    pub fn grow_down_limited(&mut self, addr: u64, limit: u64, memlock_limit: u64) -> bool {
        let page = addr & !(PAGE_SIZE - 1);
        if page < mmap_min() || self.is_mapped(addr) {
            return false;
        }
        let Some((&above, v)) = self.vmas.range(addr..).next() else {
            return false;
        };
        if !v.growsdown {
            return false;
        }
        let prot = v.prot;
        let locked = v.locked;
        if let Some((&s, below)) = self.vmas.range(..page).next_back()
            && !below.growsdown
            && below.prot != 0
            && page - (s + below.len) < STACK_GUARD_GAP
        {
            return false;
        }
        // VMAs that are separate only because their host memory is not contiguous are one VMA on
        // Linux
        let mut end = above;
        for (&s, o) in self.vmas.range(above..) {
            if s != end || !o.growsdown || o.prot != prot {
                break;
            }
            end = s + o.len;
        }
        let (grow, size) = (above - page, end - above);
        if size + grow > limit {
            return false;
        }
        if locked && !self.can_lock(grow, memlock_limit) {
            return false;
        }
        let grown = if self.spare_below(above) >= grow {
            self.extend_down(above, grow)
        } else {
            let reserve = size.clamp(grow, limit - size);
            self.new_stack_chunk(page, grow, reserve, above)
        };
        if grown && above == self.stack_low {
            self.stack_low = page;
        }
        grown
    }

    /// Lengthens grows-down VMA `start` downwards in place by `grow` bytes, using the free part
    /// below its host memory ([`Mm::spare_below`]).
    fn extend_down(&mut self, start: u64, grow: u64) -> bool {
        let v = &self.vmas[&start];
        let (page, prot) = (start - grow, v.prot);
        // SAFETY: at least grow bytes below v.host belong to the same host memory, and no other
        // mapping uses them
        let host = unsafe { NonNull::new_unchecked(v.host.as_ptr().sub(grow as usize)) };
        v.region.note_used(host, grow as usize);
        // The bottom of the stack grows back after being unmapped: what was written before must
        // read as zero again
        unsafe { discard_host(host, grow as usize) };
        if Self::map_pages(&mut self.mmu, page, host, grow, v.prefill_prot(), false).is_err() {
            return false;
        }
        if prot & prot::EXEC != 0 {
            self.exec_changed = true;
            self.code_ranges.push((page, grow));
        }
        let mut v = self.vmas.remove(&start).unwrap();
        v.host = host;
        v.anon_pgoff = v.anon_pgoff.wrapping_sub(grow / PAGE_SIZE);
        v.len += grow;
        v.file_len += grow;
        self.vmas.insert(page, v);
        self.join_anon_vmas_at(page);
        true
    }

    /// Maps a new VMA of `grow` bytes at `page`, just below grows-down VMA `above`, with the same
    /// flags (on Linux the same VMA grows). It allocates `reserve` bytes of host memory and puts
    /// the VMA at the top, leaving the rest below for later growth in place; if that cannot be
    /// allocated, only `grow` bytes.
    fn new_stack_chunk(&mut self, page: u64, grow: u64, reserve: u64, above: u64) -> bool {
        let template = self.vmas[&above].clone();
        let Ok((region, base)) =
            Self::new_anonymous_reserved(reserve).or_else(|_| Self::new_anonymous_reserved(grow))
        else {
            return false;
        };
        // SAFETY: this host memory is at least grow bytes
        let host = unsafe { NonNull::new_unchecked(base.as_ptr().add(region.len - grow as usize)) };
        let chunk = Vma {
            len: grow,
            file_len: grow,
            host,
            region,
            written: Cell::new(false),
            anon_pgoff: template.anon_pgoff.wrapping_sub(grow / PAGE_SIZE),
            ..template
        };
        self.insert_extension(page, chunk).is_ok()
    }

    /// Before the kernel gives up on an access to `[addr, addr + len)`: grows the grows-down
    /// mappings above the unmapped pages in it ([`Mm::grow_down`]), as Linux's fault handler does
    /// when a kernel access (copy_to_user, a `/proc/<pid>/mem` access) faults below a stack. Stops
    /// at the first unmapped page that cannot be grown into. Also refreshes file mappings
    /// whose previously inaccessible pages now contain file data.
    pub fn grow_for(&mut self, addr: u64, len: usize, limit: u64) -> bool {
        self.grow_for_limited(addr, len, limit, u64::MAX)
    }

    /// Like [`Mm::grow_for`], passing `memlock_limit` to [`Mm::grow_down_limited`].
    pub fn grow_for_limited(
        &mut self,
        addr: u64,
        len: usize,
        limit: u64,
        memlock_limit: u64,
    ) -> bool {
        let end = addr.saturating_add(len as u64);
        let (mut page, mut grew) = (addr & !(PAGE_SIZE - 1), false);
        while page < end {
            if let Some((&s, v)) = self.vmas.range(..=page).next_back()
                && page < s + v.len
            {
                let next = s + v.len;
                let first = page.max(s + v.contents_len());
                if first < end.min(next) && v.file.is_some() && v.fill.is_none() {
                    let need = v.prot;
                    grew |= self.fault_past_eof(first, need) == Some(false);
                }
                page = next;
                continue;
            }
            if !self.grow_down_limited(page, limit, memlock_limit) {
                break;
            }
            grew = true;
        }
        grew
    }

    /// Whether some mapping ends above a guest address (Linux's `find_vma` finds one).
    pub fn mapped_above(&self, addr: u64) -> bool {
        self.vmas
            .iter()
            .next_back()
            .is_some_and(|(&s, v)| s + v.len > addr)
    }

    /// Whether a guest address falls in some mapping (telling SEGV_MAPERR from SEGV_ACCERR).
    pub fn is_mapped(&self, addr: u64) -> bool {
        self.vmas
            .range(..=addr)
            .next_back()
            .is_some_and(|(&s, v)| addr < s + v.len)
    }

    // ---- Kernel access to guest memory ----

    /// Reads from guest memory (like Linux's `copy_from_user`); every page must be readable.
    pub fn read(&self, src: UserSlice, dst: &mut [u8]) -> Result<(), Errno> {
        assert_eq!(src.len, dst.len());
        self.for_each_page(src.addr, src.len, prot::READ, |host, done, chunk| unsafe {
            std::ptr::copy_nonoverlapping(host, dst[done..].as_mut_ptr(), chunk);
        })
    }

    /// Reads guest memory for a debugger (Linux's FOLL_FORCE). Guest access permissions and
    /// page-table entries stay untouched, including for CoW loans hidden by PROT_NONE.
    pub(crate) fn read_force(&mut self, addr: u64, dst: &mut [u8]) -> Result<(), Errno> {
        let mut done = 0;
        while done < dst.len() {
            let cur = addr.checked_add(done as u64).ok_or(Errno::EFAULT)?;
            let (&start, v) = self.vmas.range(..=cur).next_back().ok_or(Errno::EFAULT)?;
            if cur >= start + v.len || v.foreign() {
                return Err(Errno::EFAULT);
            }
            if let Some(w) = v.unread(start, cur) {
                return Err(request_fill(w));
            }
            if cur >= start + v.contents_len() {
                if self.refresh_file_extent(cur) == Some(true) {
                    continue;
                }
                return Err(Errno::EFAULT);
            }
            let offset = cur % PAGE_SIZE;
            let n = (dst.len() - done).min((PAGE_SIZE - offset) as usize);
            if let Some(t) = &v.pages {
                t.admit(v, cur - offset - start, false)
                    .map_err(|_| Errno::EFAULT)?;
            }
            let out = &mut dst[done..done + n];
            if v.reserved() {
                out.fill(0);
            } else {
                let cow = self.cow.borrow();
                let (host, off) = match cow.borrowed.get(&(cur - offset)) {
                    Some(loan) => (loan.host, offset),
                    None => (v.host, cur - start),
                };
                // SAFETY: the VMA or CoW loan holds this page, within the page-rounded file extent.
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        host.as_ptr().add(off as usize),
                        out.as_mut_ptr(),
                        n,
                    )
                };
            }
            done += n;
        }
        Ok(())
    }

    /// Writes to guest memory (like Linux's `copy_to_user`); every page must be writable.
    pub fn write(&self, dst: UserSlice, data: &[u8]) -> Result<(), Errno> {
        assert_eq!(dst.len, data.len());
        self.for_each_page(dst.addr, dst.len, prot::WRITE, |host, done, chunk| unsafe {
            std::ptr::copy_nonoverlapping(data[done..].as_ptr(), host, chunk);
        })
    }

    /// Walks `[addr, addr + len)` page by page, calling `f(host pointer, bytes done, chunk length)`
    /// for each chunk.
    fn for_each_page(
        &self,
        addr: u64,
        len: usize,
        required_prot: u32,
        mut f: impl FnMut(*mut u8, usize, usize),
    ) -> Result<(), Errno> {
        let mut done = 0;
        while done < len {
            let cur = addr.checked_add(done as u64).ok_or(Errno::EFAULT)?;
            let page_left = (PAGE_SIZE - cur % PAGE_SIZE) as usize;
            let chunk = page_left.min(len - done);
            let host = match self.mmu.translate(cur, required_prot) {
                Some(host) => host,
                // Copy-on-write pages: make them writable first (Mm::cow_break); pages without
                // entries yet are filled on demand
                None if required_prot & prot::WRITE != 0 && self.cow_break(cur)
                    || self.fault_in(cur, required_prot) =>
                {
                    self.mmu
                        .translate(cur, required_prot)
                        .ok_or(Errno::EFAULT)?
                }
                None => return Err(self.miss(cur, required_prot)),
            };
            f(host.as_ptr(), done, chunk);
            done += chunk;
        }
        Ok(())
    }

    /// The host pointer the kernel layer finds for guest address `addr` through the page table,
    /// requiring the permissions in `need`; if there is no entry yet it is filled on demand first
    /// ([`Mm::fault_in`]). Does not handle copy-on-write (see [`Mm::for_each_page`]).
    pub fn translate(&self, addr: u64, need: u32) -> Option<NonNull<u8>> {
        self.mmu.translate(addr, need).or_else(|| {
            self.fault_in(addr, need)
                .then(|| self.mmu.translate(addr, need))?
        })
    }

    /// Reads a NUL-terminated string (without the NUL), at most `max` bytes; ENAMETOOLONG if
    /// longer.
    pub fn read_cstr(&self, addr: u64, max: usize) -> Result<Vec<u8>, Errno> {
        let mut out = Vec::new();
        let mut cur = addr;
        loop {
            let chunk = (PAGE_SIZE - cur % PAGE_SIZE) as usize;
            let host = self
                .translate(cur, prot::READ)
                .ok_or_else(|| self.miss(cur, prot::READ))?;
            // SAFETY: translate guarantees this page stays valid for the duration of this call
            let bytes = unsafe { std::slice::from_raw_parts(host.as_ptr(), chunk) };
            if let Some(n) = bytes.iter().position(|&b| b == 0) {
                out.extend_from_slice(&bytes[..n]);
                return if out.len() > max {
                    Err(Errno::ENAMETOOLONG)
                } else {
                    Ok(out)
                };
            }
            out.extend_from_slice(bytes);
            if out.len() > max {
                return Err(Errno::ENAMETOOLONG);
            }
            cur = cur.checked_add(chunk as u64).ok_or(Errno::EFAULT)?;
        }
    }

    /// The kernel itself writing into guest memory, such as loading a program or building the
    /// initial stack. Requires only that it be mapped, without checking permissions, so host
    /// memory is found by VMA: `PROT_NONE` pages are not in the page table. The part of a file
    /// mapping past the end of the file cannot be written.
    pub(crate) fn write_kernel(&mut self, addr: u64, data: &[u8]) -> Result<(), Errno> {
        // Write the VMA's own host memory directly: copy-on-write pages are first replaced by our
        // own, and file mappings sharing host memory with other address spaces first copy their
        // own
        let end = page_up(addr.saturating_add(data.len() as u64)).unwrap_or(u64::MAX);
        // The pages of a mapping read on demand are read first: the write keeps the rest of them
        if let Some(w) = self
            .fills
            .then(|| self.first_unread(addr, data.len() as u64, 0))
            .flatten()
        {
            return Err(request_fill(w));
        }
        // Verify the entire range lies within mapped contents before settling CoW, unsharing, or
        // mutating any bytes (e.g., an unaligned PTRACE_POKE straddling EOF must not leave a
        // partial write).
        let write_end = addr.checked_add(data.len() as u64).ok_or(Errno::EFAULT)?;
        let mut check = addr;
        while check < write_end {
            let (&s, v) = self
                .vmas
                .range(..=check)
                .next_back()
                .filter(|&(&s, v)| check < s + v.contents_len())
                .ok_or(Errno::EFAULT)?;
            check = s + v.contents_len();
        }
        self.cow_settle(addr & !(PAGE_SIZE - 1), end)?;
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        let shared: Vec<u64> = self
            .vmas
            .range(first..end)
            .filter(|(_, v)| v.cow)
            .map(|(&s, _)| s)
            .collect();
        for s in shared {
            self.unshare(s)?;
        }
        // A reservation (PROT_NONE, a tracer forcing a write): the pages written are split off and
        // given host memory
        let lo = addr & !(PAGE_SIZE - 1);
        if self
            .vmas
            .range(first..end)
            .any(|(&s, v)| v.reserved() && s + v.len > lo)
        {
            self.split_at(lo);
            self.split_at(end);
            let reserved: Vec<u64> = self
                .vmas
                .range(lo..end)
                .filter(|(_, v)| v.reserved())
                .map(|(&s, _)| s)
                .collect();
            for s in reserved {
                self.back_reserved(s, false)?;
            }
        }
        let mut done = 0;
        while done < data.len() {
            let cur = addr.checked_add(done as u64).ok_or(Errno::EFAULT)?;
            let (&s, v) = self
                .vmas
                .range(..=cur)
                .next_back()
                .filter(|&(&s, v)| cur < s + v.contents_len())
                .ok_or(Errno::EFAULT)?;
            let chunk = ((s + v.contents_len() - cur) as usize).min(data.len() - done);
            if let Some(t) = &v.pages {
                for page in
                    ((cur & !(PAGE_SIZE - 1))..cur + chunk as u64).step_by(PAGE_SIZE as usize)
                {
                    t.admit(v, page - s, true).map_err(|_| Errno::EFAULT)?;
                }
            }
            if v.backing == Backing::Shared
                && let Some(fill) = &v.fill
            {
                let at = v.offset() + cur - s;
                fill.track(at / PAGE_SIZE, (at + chunk as u64).div_ceil(PAGE_SIZE))?;
            }
            self.prepare_anon_write(s, v)?;
            v.written.set(true);
            self.exec_changed |= v.prot & prot::EXEC != 0;
            // Pages with contents in private anonymous memory must have entries
            // (Mm::touched_windows); PROT_NONE ones get permission 0
            if v.backing == Backing::Anonymous {
                let lo = cur & !(PAGE_SIZE - 1);
                let hi = page_up(cur + chunk as u64).unwrap_or(s + v.len);
                // SAFETY: [lo, hi) is inside this VMA, which holds the host memory
                let host = unsafe { v.host.add((lo - s) as usize) };
                unsafe { self.mmu.fill_shared(lo, host, hi - lo, v.prefill_prot()) }
                    .map_err(map_err)?;
            }
            // SAFETY: [cur, cur + chunk) is in the part of this VMA with contents, and it holds
            // the host memory
            unsafe {
                std::ptr::copy_nonoverlapping(
                    data[done..].as_ptr(),
                    v.host.as_ptr().add((cur - s) as usize),
                    chunk,
                )
            };
            done += chunk;
        }
        Ok(())
    }

    /// A tracer forcing a write (PTRACE_POKETEXT, `/proc/<pid>/mem`, Linux's `FOLL_FORCE`):
    /// private mappings without write permission can be written too (a program's code segment:
    /// setting breakpoints), by copying them into our own; shared mappings without write
    /// permission cannot. Translations of what was written are invalidated, and the threads using
    /// this address space flush their TLBs first; `current` is the writing thread (no effect when
    /// it is not in this address space).
    pub(crate) fn write_force(
        &mut self,
        addr: u64,
        data: &[u8],
        current: &Arc<TaskSync>,
    ) -> Result<(), Errno> {
        let end = addr.checked_add(data.len() as u64).ok_or(Errno::EFAULT)?;
        let mut cur = addr;
        while cur < end {
            let (&s, v) = self
                .vmas
                .range(..=cur)
                .next_back()
                .filter(|&(&s, v)| cur < s + v.len)
                .ok_or(Errno::EFAULT)?;
            if v.backing == Backing::Shared && v.prot & prot::WRITE == 0 {
                return Err(Errno::EFAULT);
            }
            cur = s + v.len;
        }
        self.write_kernel(addr, data)?;
        let page = addr & !(PAGE_SIZE - 1);
        self.invalidate_code(page, page_up(end).unwrap_or(u64::MAX) - page);
        self.sync(current);
        Ok(())
    }

    /// The key of the futex at `addr` (Linux's `get_futex_key`; `private` is an operation with
    /// `FUTEX_PRIVATE_FLAG`). A private operation's key is this address space and the address,
    /// whatever is mapped there or not (Linux only checks that the address is a user one, so a
    /// private wake on an unmapped address wakes nobody); None outside the address space. Other
    /// operations need a readable page (None when there is none): private memory is keyed the
    /// same way, shared anonymous memory by its host address and shared file mappings by file and
    /// offset, which every process mapping them sees alike.
    pub fn futex_key(&self, addr: u64, private: bool) -> Option<crate::futex::Key> {
        use crate::futex::Key;
        if private {
            return (addr.checked_add(4)? <= 1 << VA_BITS).then_some(Key::Private {
                mm: self.id,
                addr,
                shared: false,
            });
        }
        let host = self.translate(addr, prot::READ)?;
        let (&start, v) = self.vmas.range(..=addr).next_back()?;
        Some(match (v.backing, v.file_id) {
            (Backing::Shared, Some((dev, ino, offset))) if !private => Key::File {
                dev,
                ino,
                offset: offset + (addr - start),
            },
            (Backing::Shared, None) if !private => Key::Host(host.as_ptr() as usize),
            _ => Key::Private {
                mm: self.id,
                addr,
                shared: !private,
            },
        })
    }

    // ---- Memory syscalls ----

    /// Implements mmap(2). `file` is the host fd, the file offset, and whether the file was opened
    /// for writing.
    pub fn mmap(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
        file: Option<(i32, u64, bool)>,
    ) -> Result<u64, Errno> {
        self.map(addr, len, prot, flags, file, None)
    }

    /// mmap(2) of a file read on demand ([`Fill`]) from file offset `offset`: its pages get
    /// entries only once read.
    pub fn mmap_fill(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
        (fill, offset): (Rc<Fill>, u64),
    ) -> Result<u64, Errno> {
        let file = Some((fill.fd(), offset, fill.source.borrow().writable()));
        self.map(addr, len, prot, flags, file, Some(FileSource::Fuse(fill)))
    }

    /// Maps a range owned by the GPU backend directly into the guest page table.
    pub(crate) fn mmap_gpu(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
        mapping: Arc<dyn crate::gpu::Mapping>,
    ) -> Result<u64, Errno> {
        let len = page_up(len).filter(|&n| n != 0).ok_or(Errno::EINVAL)?;
        if len > mapping.size() as u64
            || !mapping
                .base()
                .as_ptr()
                .addr()
                .is_multiple_of(PAGE_SIZE as usize)
        {
            return Err(Errno::EINVAL);
        }
        let start = self.mapping_address(addr, len, flags)?;
        let host = mapping.base();
        let region = Arc::new(HostRegion {
            base: host,
            len: len as usize,
            anonymous: None,
            used_start: AtomicUsize::new(0),
            used_end: AtomicUsize::new(0),
            reserved: false,
            foreign: false,
            gpu: Some(mapping),
        });
        self.insert(start, len, len, prot, Backing::Shared, true, region, host)?;
        self.deny_exec(start, len);
        Ok(start)
    }

    fn mapping_address(&mut self, addr: u64, len: u64, flags: u32) -> Result<u64, Errno> {
        let fixed = flags & (flags::MAP_FIXED | flags::MAP_FIXED_NOREPLACE) != 0;
        Ok(if fixed {
            if !addr.is_multiple_of(PAGE_SIZE)
                || addr.checked_add(len).is_none_or(|e| e > 1 << VA_BITS)
            {
                return Err(Errno::EINVAL);
            }
            if !self.is_free(addr, len) {
                if flags & flags::MAP_FIXED_NOREPLACE != 0 {
                    return Err(Errno::EEXIST);
                }
                self.munmap(addr, len)?;
            }
            addr
        } else {
            // As with Linux's round_hint_to_min, a hint below mmap_min_addr is raised to it
            let hint = match addr & !(PAGE_SIZE - 1) {
                0 => 0,
                h => h.max(mmap_min()),
            };
            if hint != 0 && self.hint_fits(hint, len) {
                hint
            } else {
                self.find_free(len).ok_or(Errno::ENOMEM)?
            }
        })
    }

    pub(crate) fn map(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        flags: u32,
        file: Option<(i32, u64, bool)>,
        source: Option<FileSource>,
    ) -> Result<u64, Errno> {
        let pinned = matches!(source, Some(FileSource::PinnedStore | FileSource::Tmpfs(_)));
        let (fill, tmpfs) = match source {
            Some(FileSource::Fuse(fill)) => (Some(fill), None),
            Some(FileSource::Tmpfs(mapping)) => (None, Some(mapping)),
            None | Some(FileSource::PinnedStore) => (None, None),
        };
        let len = page_up(len).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let shared = flags & 3 == flags::MAP_SHARED;
        if !shared && flags & 3 != flags::MAP_PRIVATE {
            return Err(Errno::EINVAL);
        }
        let start = self.mapping_address(addr, len, flags)?;

        let st = file.and_then(|(fd, ..)| appine_hal::fstat(fd).ok());
        let file_id = st
            .as_ref()
            .zip(file)
            .map(|(s, (_, offset, _))| (s.st_dev, s.st_ino, offset));
        let content = match (&st, file_id) {
            (Some(s), Some((dev, ino, _))) if !shared && fill.is_none() && tmpfs.is_none() => {
                content::version(s, dev, ino)
            }
            _ => None,
        };
        #[allow(clippy::unnecessary_cast)]
        let bundled_libc = if !shared && prot & prot::EXEC != 0 && prot & prot::WRITE == 0 {
            file.zip(file_id).zip(content).and_then(
                |(((fd, _, _), (dev, ino, _)), (ctime, size))| {
                    crate::loader::bundled_libc(fd, (dev as u64, ino as u64, ctime, size))
                },
            )
        } else {
            None
        };
        // The host mapping is shared with other address spaces (FileMaps)
        let mut cached = false;
        let (backing, may_write, region, host) = match file {
            None => {
                // MAP_NORESERVE skips accounting for shared anonymous memory too (Linux's
                // shmem_acct_size checks VM_NORESERVE)
                let reserve = prot & prot::WRITE != 0 && flags & flags::MAP_NORESERVE == 0;
                // A grows-down mapping must grow downwards inside its host memory
                // ([`Mm::extend_down`]), not just be reserved
                let (region, host) = if shared || flags & flags::MAP_GROWSDOWN != 0 {
                    Self::new_anonymous(len, reserve)?
                } else {
                    Self::private_anonymous(len, prot, reserve)?
                };
                let backing = if shared {
                    Backing::Shared
                } else {
                    Backing::Anonymous
                };
                (backing, true, region, host)
            }
            Some((fd, offset, writable)) => {
                if !offset.is_multiple_of(PAGE_SIZE) {
                    return Err(Errno::EINVAL);
                }
                let host_len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
                let backing = if shared {
                    Backing::Shared
                } else {
                    Backing::PrivateFile
                };
                // A read-only private mapping with a trusted version: all address spaces share one
                // host mapping (FileMaps). Verified bundled musl maps its immutable memfd snapshot
                // under the snapshot's own (dev, ino) so it never aliases unverified mappings of
                // the original file.
                let key = if let Some(libc) = &bundled_libc {
                    let (dev, ino) = libc.snapshot_id();
                    Some([dev, ino, offset, len, 0, libc.size()])
                } else {
                    st.as_ref()
                        .zip(content)
                        .filter(|_| !shared && prot & prot::WRITE == 0)
                        .map(|(s, (ctime, size))| {
                            #[allow(clippy::unnecessary_cast)]
                            let (dev, ino) = (s.st_dev as u64, s.st_ino as u64);
                            [dev, ino, offset, len, ctime, size]
                        })
                };
                if let Some((region, host)) = key.as_ref().and_then(|k| self.files.get(k)) {
                    cached = true;
                    (backing, true, region, host)
                } else {
                    // Cached views can outlive every guest VMA. Use an independent open
                    // description so the cache cannot keep a store mapping's flock.
                    use std::os::fd::AsRawFd;
                    let (mapping, cache_key) = if let Some(libc) = &bundled_libc {
                        (libc.map(offset, host_len), key)
                    } else if key.is_some()
                        && let Ok(view) = std::fs::File::open(format!("/proc/self/fd/{fd}"))
                    {
                        (
                            appine_hal::map_file_read_only(view.as_raw_fd(), offset, host_len),
                            key,
                        )
                    } else {
                        (
                            appine_hal::map_file(fd, offset, host_len, shared, writable),
                            None,
                        )
                    };
                    let m = mapping.map_err(Errno)?;
                    let region = HostRegion::file(m.base, m.len);
                    if let Some(key) = cache_key {
                        self.files.insert(key, region.clone(), m.ptr);
                        cached = true;
                    }
                    (backing, !shared || writable, region, m.ptr)
                }
            }
        };
        if prot & prot::WRITE != 0 && !may_write {
            return Err(Errno::EACCES);
        }
        let file_len = match file {
            _ if fill.is_some() => 0,
            Some((_, offset, _)) => extent(st.as_ref().map_or(0, |s| s.st_size), offset, len),
            None => len,
        };
        let dup = match file {
            Some((fd, offset, _)) if shared || fill.is_none() => {
                let private_inode = file_id.filter(|_| !shared).map(|(dev, ino, _)| (dev, ino));
                // SAFETY: the mapping's input fd stays open for this call.
                let fd = unsafe { BorrowedFd::borrow_raw(fd) };
                Some((self.retain_file(fd, private_inode, pinned)?, offset))
            }
            _ => None,
        };
        let track = tmpfs.is_some()
            || backing == Backing::PrivateFile && fill.is_none() && !appine_hal::pagemap_readable();
        let mut v = self.new_vma(start, len, file_len, prot, backing, may_write, region, host);
        v.pages = track.then(|| FilePages::new(tmpfs, BTreeSet::new()));
        v.snapshot = bundled_libc.is_some();
        v.file_id = file_id;
        v.content = content;
        v.cow = cached;
        v.file = dup;
        v.locked |= flags & flags::MAP_LOCKED != 0;
        v.growsdown = backing == Backing::Anonymous && flags & flags::MAP_GROWSDOWN != 0;
        v.noreserve = flags & flags::MAP_NORESERVE != 0;
        v.accounted &= !v.noreserve;
        let has_fill = fill.is_some();
        v.fill = fill;
        self.insert_vma(start, v)?;
        if shared
            && !has_fill
            && let (Some((fd, _, true)), Some(s)) = (file, &st)
            && s.st_nlink > 0
        {
            content::writably_shared(fd, s.st_dev, s.st_ino);
        }
        self.fills |= has_fill;
        if let (Some(libc), Some((_, offset, _))) = (bundled_libc, file) {
            let before = self.memops.len();
            libc.register(offset, start, len, &mut self.memops);
            self.memops_dirty |= self.memops.len() != before;
        }
        Ok(start)
    }

    /// Reuse a private mapping's read descriptor across the fork family. Shared mappings keep
    /// their own descriptor so its access mode matches the file that was mapped.
    fn retain_file(
        &self,
        fd: BorrowedFd<'_>,
        private_inode: Option<(u64, u64)>,
        pinned: bool,
    ) -> Result<Rc<OwnedFd>, Errno> {
        if let Some(key) = private_inode
            && let Some(retained) = self
                .private_files
                .borrow()
                .get(&key)
                // An ELF segment can have retained this inode without a store mapping pin.
                .filter(|entry| !pinned || entry.pinned)
                .and_then(|entry| entry.fd.upgrade())
        {
            return Ok(retained);
        }
        let retained = Rc::new(
            fd.try_clone_to_owned()
                .map_err(|e| Errno(e.raw_os_error().unwrap_or(libc::EMFILE)))?,
        );
        if let Some(key) = private_inode {
            let mut files = self.private_files.borrow_mut();
            if files.len() == files.capacity() {
                files.retain(|_, entry| entry.fd.strong_count() > 0);
            }
            files.insert(
                key,
                PrivateFile {
                    fd: Rc::downgrade(&retained),
                    pinned,
                },
            );
        }
        Ok(retained)
    }

    /// Marks the mapping starting at `start` as growing downwards (a private anonymous mapping
    /// with `MAP_GROWSDOWN`).
    #[cfg(test)]
    pub fn set_growsdown(&mut self, start: u64) {
        if let Some(v) = self.vmas.get_mut(&start) {
            v.growsdown = true;
        }
    }

    /// Mappings starting in `[start, start + len)` may never become writable (shared mappings of
    /// /dev/zero opened read-only).
    pub fn deny_write(&mut self, start: u64, len: u64) {
        let mut changed_shared = false;
        for (_, v) in self.vmas.range_mut(start..start.saturating_add(len)) {
            changed_shared |= v.backing == Backing::Shared && v.may_write;
            v.may_write = false;
        }
        if changed_shared {
            self.note_shared_maps();
        }
    }

    /// Mappings starting in `[start, start + len)` may never become executable (files on a noexec
    /// mount).
    pub fn deny_exec(&mut self, start: u64, len: u64) {
        for (_, v) in self.vmas.range_mut(start..start.saturating_add(len)) {
            v.may_exec = false;
        }
    }

    /// mremap(`MREMAP_DONTUNMAP`): the contents move to a new address (`fixed`, or a newly found
    /// range), and a mapping with the same permissions, no longer locked, stays at the old address.
    /// Like Linux since 5.13 it supports every mapping, and the old address behaves as if its page
    /// table were dropped: a private anonymous mapping becomes empty; a shared mapping (file or
    /// anonymous) shares the same host memory with the new address, as if re-read from the file
    /// or the shared memory afterwards; a private file mapping is left empty, and the caller maps
    /// the file again from the returned [`Refill`].
    pub fn mremap_dontunmap(
        &mut self,
        old: u64,
        len: u64,
        fixed: Option<u64>,
    ) -> Result<(u64, Vec<Refill>), Errno> {
        let len = page_up(len).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        if !old.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        let end = old.checked_add(len).ok_or(Errno::EINVAL)?;
        // In 6.1's order (the syscall's vma_lookup, then mremap_to): a mapping at old (EFAULT),
        // the target (EINVAL), the map-count margin (ENOMEM), unmapping the target, and only then
        // vma_to_resize's rule that the range lies in one VMA ([`same_vma`], EFAULT); nothing is
        // split before these checks
        if !self.is_mapped(old) {
            return Err(Errno::EFAULT);
        }
        if let Some(d) = fixed {
            Self::check_target(old, len, d, len)?;
        }
        self.move_room(2)?;
        if let Some(d) = fixed {
            self.munmap(d, len)?;
        }
        if !self.in_one_vma(old, end) {
            return Err(Errno::EFAULT);
        }
        let dst = match fixed {
            Some(d) => d,
            None => self.find_free(len).ok_or(Errno::ENOMEM)?,
        };
        // Count the retained backing runs before splitting either endpoint.
        let (&first, mut prev) = self.vmas.range(..=old).next_back().unwrap();
        let mut bounds = vec![old];
        for (&s, v) in self.vmas.range(first + 1..end) {
            if !Self::same_remnant(prev, v) {
                bounds.push(s);
            }
            prev = v;
        }
        self.room_for(self.splits(&[old, end]) + bounds.len())?;
        bounds.push(end);
        self.split_at(old);
        self.split_at(end);
        let (mut remnants, mut refill) = (Vec::new(), Vec::new());
        for pair in bounds.windows(2) {
            let (s, stop) = (pair[0], pair[1]);
            let len = stop - s;
            let v = &self.vmas[&s];
            let mut remnant = v.clone();
            remnant.len = len;
            remnant.locked = false;
            match v.backing {
                Backing::Anonymous => {
                    (remnant.region, remnant.host) = Self::private_anonymous(
                        len,
                        v.prot,
                        v.prot & prot::WRITE != 0 && !v.noreserve,
                    )?;
                    remnant.file_len = len;
                    remnant.anon = 0;
                    remnant.anon_pgoff = s / PAGE_SIZE;
                    remnant.written.set(false);
                    remnant.has_anon_vma.set(false);
                }
                Backing::Shared => {
                    remnant.file_len = self.vmas.range(s..stop).map(|(_, v)| v.file_len).sum();
                }
                Backing::PrivateFile if v.fill.is_some() => {
                    (remnant.region, remnant.host) = Self::fill_host(v, v.offset(), len)?;
                    remnant.cow = false;
                    remnant.written.set(v.prot & prot::WRITE != 0);
                }
                Backing::PrivateFile => {
                    refill.push(Refill {
                        start: s,
                        len,
                        prot: v.prot,
                        ino: v.ino,
                        offset: v.offset(),
                        name: v.name.clone(),
                        mnt: v.mnt.as_ref().map(|m| m.0),
                        flags: VmaFlags::of(v),
                        file: v.file.as_ref().map(|(fd, _)| fd.clone()),
                        tmpfs: v.tmpfs().cloned(),
                        interp_open: v.interp_open.clone(),
                    });
                    continue;
                }
            }
            remnants.push((s, remnant));
        }
        self.move_range(old, len, dst)?;
        for (s, v) in remnants {
            // The preflight reserved these slots. A fresh anonymous remnant starts
            // without the source identity, including on a move of just part of a VMA.
            self.install_vma(s, v)?;
        }
        Ok((dst, refill))
    }

    /// Adjacent pieces of one Linux VMA can leave one remnant if it can represent both
    /// sets of pins and, for a shared alias, one continuous host span and accessible prefix.
    fn same_remnant(a: &Vma, b: &Vma) -> bool {
        if a.backing == Backing::Anonymous {
            return true;
        }
        let fd = |v: &Vma| v.file.as_ref().map(|(f, _)| Rc::as_ptr(f));
        if fd(a) != fd(b)
            || a.tmpfs().map(Rc::as_ptr) != b.tmpfs().map(Rc::as_ptr)
            || a.interp_open.as_ref().map(Rc::as_ptr) != b.interp_open.as_ref().map(Rc::as_ptr)
            || a.mnt.as_ref().map(|m| m.0) != b.mnt.as_ref().map(|m| m.0)
        {
            return false;
        }
        a.backing != Backing::Shared
            || Arc::ptr_eq(&a.region, &b.region)
                && a.host.as_ptr().wrapping_add(a.len as usize) == b.host.as_ptr()
                && a.shm == b.shm
                && (a.file_len == a.len || b.file_len == 0)
    }

    /// Implements mremap(2): `fixed` is the `MREMAP_FIXED` target address. When growing it first
    /// tries to extend in place, and otherwise moves to a new address (`may_move`): moving copies
    /// no data, it only maps the same host memory at the new address. Shared anonymous mappings
    /// retain their original backing extent. File mappings continue at the next file offset.
    #[cfg(test)]
    pub fn mremap(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        may_move: bool,
        fixed: Option<u64>,
    ) -> Result<u64, Errno> {
        self.mremap_limited(old, old_len, new_len, may_move, fixed, u64::MAX)
    }

    /// Like [`Mm::mremap`], also enforcing `memlock_limit` (`RLIMIT_MEMLOCK`, or `u64::MAX` with
    /// `CAP_IPC_LOCK`) when growing or duplicating a locked VMA (Linux 6.1's `vma_to_resize`
    /// returns `EAGAIN`).
    pub fn mremap_limited(
        &mut self,
        old: u64,
        old_len: u64,
        new_len: u64,
        may_move: bool,
        fixed: Option<u64>,
        memlock_limit: u64,
    ) -> Result<u64, Errno> {
        let old_len = page_up(old_len).ok_or(Errno::EINVAL)?;
        let new_len = page_up(new_len).filter(|&l| l != 0).ok_or(Errno::EINVAL)?;
        let old_end = old.checked_add(old_len).ok_or(Errno::EINVAL)?;
        if !old.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if old_len == 0 {
            return self.duplicate(old, new_len, may_move, fixed, memlock_limit);
        }
        // In Linux's order: a mapping at old (EFAULT), the target (EINVAL, then unmapped), the
        // shrunk tail unmapped, and only then the rule that the rest of the old range lies in one
        // VMA (EFAULT; adjacent VMAs are not merged here, so it is checked against the VMAs Linux
        // would have, [`same_vma`]). Shrinking in place only unmaps the tail
        if !self.is_mapped(old) {
            return Err(Errno::EFAULT);
        }
        let grow = new_len.saturating_sub(old_len);
        if let Some(dst) = fixed {
            Self::check_target(old, old_len, dst, new_len)?;
            // mremap_to's margin: unmapping the target and the shrunk tail may each split a VMA
            self.move_room(2)?;
            self.munmap(dst, new_len)?;
            if new_len < old_len {
                self.munmap(old + new_len, old_len - new_len)?;
            }
            let kept = old_len.min(new_len);
            if !self.in_one_vma(old, old + kept) {
                return Err(Errno::EFAULT);
            }
            let ext = if grow > 0 {
                let (&start, tail) = self.vmas.range(..old_end).next_back().unwrap();
                if tail.locked && !self.can_lock(grow, memlock_limit) {
                    return Err(Errno::EAGAIN);
                }
                let offset = old_end - start;
                Some(Self::extension(tail, offset, grow, Some(dst))?)
            } else {
                None
            };
            self.move_and_extend(old, kept, dst, ext)?;
            return Ok(dst);
        }
        if grow == 0 {
            if new_len < old_len {
                self.munmap(old + new_len, old_len - new_len)?;
            }
            return Ok(old);
        }
        if !self.in_one_vma(old, old_end) {
            return Err(Errno::EFAULT);
        }
        // [vvar] cannot grow, in place or moved (Linux's VM_DONTEXPAND, before looking for room)
        let (&start, tail) = self.vmas.range(..old_end).next_back().unwrap();
        if tail.foreign() {
            return Err(Errno::EFAULT);
        }
        if tail.locked && !self.can_lock(grow, memlock_limit) {
            return Err(Errno::EAGAIN);
        }
        let offset = old_end - start;
        if offset == tail.len
            && grow <= self.mmap_top.saturating_sub(old_end)
            && self.is_free(old_end, grow)
        {
            if self.grow_tail(start, grow)? {
                return Ok(old);
            }
            let ext = Self::extension(&self.vmas[&start], offset, grow, None)?;
            self.insert_extension(old_end, ext)?;
            return Ok(old);
        }
        if !may_move {
            return Err(Errno::ENOMEM);
        }
        let dst = self.find_free(new_len).ok_or(Errno::ENOMEM)?;
        let ext = Self::extension(tail, offset, grow, Some(dst))?;
        self.move_room(0)?;
        self.move_and_extend(old, old_len, dst, Some(ext))?;
        Ok(dst)
    }

    /// Reuse an existing region when growing into a free guest range. A private region
    /// must be exclusive even across address spaces, outstanding host advice and the graveyard.
    fn grow_tail(&mut self, start: u64, grow: u64) -> Result<bool, Errno> {
        let v = &self.vmas[&start];
        let len = v.len + grow;
        let end = start + v.len;
        let shared = v.backing == Backing::Shared
            && v.file.is_none()
            && v.fill.is_none()
            && !v.foreign()
            && v.region.gpu.is_none();
        let file_len = if v.reserved() {
            len
        } else if shared {
            len.min(v.host_available())
        } else if v.backing == Backing::Anonymous
            && len <= v.host_available()
            && Arc::strong_count(&v.region) == 1
        {
            len
        } else {
            return Ok(false);
        };
        let old_file_len = v.file_len;
        let added = file_len - old_file_len;
        let publish = shared && v.may_write;
        let v = self.vmas.get_mut(&start).unwrap();
        v.len = len;
        if publish {
            self.note_shared_maps();
        }
        let v = &self.vmas[&start];
        if !v.reserved() && added != 0 {
            // SAFETY: only a backed extension reaches here; the whole new slice is in the region.
            let host = unsafe { v.host.add(old_file_len as usize) };
            if !shared {
                // SAFETY: no other mapping, loan or unflushed translation can use this slice.
                unsafe { discard_host(host, added as usize) };
            }
            v.region.note_used(host, added as usize);
            if let Err(e) =
                Self::map_pages(&mut self.mmu, end, host, added, v.prefill_prot(), shared)
            {
                if v.prot & prot::EXEC != 0 {
                    self.code_ranges.push((end, added));
                    self.exec_changed = true;
                }
                self.vmas.get_mut(&start).unwrap().len -= grow;
                // map_pages removed partial entries; flush before reusing their range.
                self.shootdown();
                if publish {
                    self.note_shared_maps();
                }
                return Err(e);
            }
        }
        let v = self.vmas.get_mut(&start).unwrap();
        v.file_len = file_len;
        if v.prot & prot::EXEC != 0 {
            self.exec_changed = true;
            self.code_ranges.push((end, grow));
        }
        self.join_anon_vmas_at(end + grow);
        Ok(true)
    }

    fn move_and_extend(
        &mut self,
        old: u64,
        len: u64,
        dst: u64,
        ext: Option<Vma>,
    ) -> Result<(), Errno> {
        self.move_range(old, len, dst)?;
        if let Some(mut ext) = ext {
            let end = dst + len;
            let (_, tail) = self.vmas.range(..end).next_back().unwrap();
            ext.anon_pgoff = tail.anon_pgoff_at(tail.len);
            ext.has_anon_vma.set(tail.has_anon_vma.get());
            self.insert_extension(end, ext)?;
        }
        Ok(())
    }

    fn insert_extension(&mut self, start: u64, v: Vma) -> Result<(), Errno> {
        let len = v.len;
        let executable = v.prot & prot::EXEC != 0;
        self.insert_vma(start, v)?;
        if executable {
            self.code_ranges.push((start, len));
        }
        Ok(())
    }

    /// mremap_to's checks of a target address: page-aligned, inside the address space and not
    /// overlapping the old range (EINVAL).
    fn check_target(old: u64, old_len: u64, dst: u64, new_len: u64) -> Result<(), Errno> {
        if !dst.is_multiple_of(PAGE_SIZE)
            || dst.checked_add(new_len).is_none_or(|e| e > 1 << VA_BITS)
            || dst < old + old_len && old < dst + new_len
        {
            return Err(Errno::EINVAL);
        }
        Ok(())
    }

    /// The map-count margin Linux 6.1 keeps before moving (`move_vma`), with `extra` VMAs more for
    /// `mremap_to`'s unmapping: ENOMEM unless the address space stays more than three VMAs below
    /// `vm.max_map_count`, so a move never fails for room halfway, after its pieces left the old
    /// address.
    fn move_room(&self, extra: usize) -> Result<(), Errno> {
        if self.vmas.len() + extra >= MAX_MAP_COUNT.load(Ordering::Relaxed).saturating_sub(3) {
            return Err(Errno::ENOMEM);
        }
        Ok(())
    }

    /// mremap with an old length of 0, which Linux keeps for DOSEMU's "duplicate shm area": the same
    /// shared memory or file, from `old`'s offset for `new_len` bytes, mapped again at a new address
    /// while the original stays. In 6.1's order: no mapping at `old` is EFAULT; a `MREMAP_FIXED`
    /// target is validated and unmapped first; a private mapping is EINVAL (6.1 refuses to
    /// duplicate one); and without `may_move` it is ENOMEM, since nothing grows in place.
    fn duplicate(
        &mut self,
        old: u64,
        new_len: u64,
        may_move: bool,
        fixed: Option<u64>,
        memlock_limit: u64,
    ) -> Result<u64, Errno> {
        let (s, v) = self
            .vmas
            .range(..=old)
            .next_back()
            .filter(|&(&s, v)| old < s + v.len)
            .map(|(&s, v)| (s, v.clone()))
            .ok_or(Errno::EFAULT)?;
        if let Some(dst) = fixed {
            if !dst.is_multiple_of(PAGE_SIZE)
                || dst.checked_add(new_len).is_none_or(|e| e > 1 << VA_BITS)
                || dst < old && old < dst + new_len
            {
                return Err(Errno::EINVAL);
            }
            self.munmap(dst, new_len)?;
        }
        if v.backing != Backing::Shared || v.foreign() || v.region.gpu.is_some() {
            return Err(Errno::EINVAL);
        }
        let dst = match fixed {
            Some(d) => d,
            None if may_move => self.find_free(new_len).ok_or(Errno::ENOMEM)?,
            None => return Err(Errno::ENOMEM),
        };
        if v.locked && !self.can_lock(new_len, memlock_limit) {
            return Err(Errno::EAGAIN);
        }
        let copy = Self::extension(&v, old - s, new_len, Some(dst))?;
        self.insert_vma(dst, copy)?;
        Ok(dst)
    }

    /// Builds a grown or duplicated piece at the given offset in the original backing.
    /// Private file mappings need the host fd. A moved or duplicated SysV mapping takes
    /// its destination as the attachment base. In-place growth keeps the existing base.
    fn extension(
        template: &Vma,
        offset: u64,
        len: u64,
        destination: Option<u64>,
    ) -> Result<Vma, Errno> {
        if template.foreign() || template.region.gpu.is_some() {
            return Err(Errno::EFAULT);
        }
        // (host memory, host address, retained file descriptor, bytes with file contents)
        let (region, host, file, file_len) = match (&template.backing, &template.file) {
            // Read on demand: more of the same host file, its entries built as pages are read
            _ if template.fill.is_some() => {
                let (region, host) = Self::fill_host(template, template.offset() + offset, len)?;
                let file = template
                    .file
                    .as_ref()
                    .map(|(fd, o)| (fd.clone(), o + offset));
                (region, host, file, 0)
            }
            (Backing::Shared | Backing::PrivateFile, Some((fd, start))) => {
                let host_len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
                let file_offset = start + offset;
                let raw = std::os::fd::AsRawFd::as_raw_fd(&**fd);
                let m = appine_hal::map_file(
                    raw,
                    file_offset,
                    host_len,
                    template.backing == Backing::Shared,
                    template.may_write,
                )
                .map_err(Errno)?;
                let region = HostRegion::file(m.base, m.len);
                let file_len = file_extent(raw, file_offset, len);
                (region, m.ptr, Some((fd.clone(), file_offset)), file_len)
            }
            // Shared anonymous memory (including SysV segments) keeps its original extent.
            // The host pointer records the offset even in a tail with no accessible pages.
            (Backing::Shared, None) => {
                let start = template
                    .host
                    .addr()
                    .checked_add(offset as usize)
                    .ok_or(Errno::ENOMEM)?;
                start.checked_add(len as usize).ok_or(Errno::ENOMEM)?;
                let host = template.host.with_addr(start);
                let available = template.host_available().saturating_sub(offset);
                (template.region.clone(), host, None, len.min(available))
            }
            _ => {
                let reserve = template.prot & prot::WRITE != 0 && !template.noreserve;
                let (region, host) = if template.reserved() {
                    Self::private_anonymous(len, 0, false)?
                } else {
                    Self::new_anonymous(len, reserve)?
                };
                (region, host, None, len)
            }
        };
        Ok(Vma {
            snapshot: false,
            pages: template
                .pages
                .as_ref()
                .map(|p| FilePages::new(p.tmpfs.clone(), BTreeSet::new())),
            len,
            region,
            host,
            file_len,
            cow: false,
            file_id: template.file_id.map(|(d, i, o)| (d, i, o + offset)),
            content: None,
            file,
            shm: template
                .shm
                .map(|(id, base)| (id, destination.unwrap_or(base))),
            written: Cell::new(
                template.backing != Backing::Anonymous && template.prot & prot::WRITE != 0,
            ),
            anon_pgoff: template.anon_pgoff_at(offset),
            ..template.clone()
        })
    }

    /// Host memory for `len` bytes of on-demand VMA `v`'s file from `offset` ([`Fill`]): its host
    /// file mapped again, shared or privately as `v` is.
    fn fill_host(v: &Vma, offset: u64, len: u64) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        let fill = v.fill.as_ref().ok_or(Errno::EFAULT)?;
        let host_len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
        let shared = v.backing == Backing::Shared;
        let m = appine_hal::map_file(fill.fd(), offset, host_len, shared, v.may_write)
            .map_err(Errno)?;
        let region = HostRegion::file(m.base, m.len);
        Ok((region, m.ptr))
    }

    /// A private copy of on-demand VMA `v` ([`Fill`]) for fork or for [`Mm::unshare`]: its host file
    /// mapped privately again, with the pages `v` changed after reading them copied over (pages
    /// not read are still holes on both sides).
    fn fill_copy(v: &Vma) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        let (region, host) = Self::fill_host(v, v.offset(), v.len)?;
        let fill = v.fill.as_ref().unwrap();
        let first = v.offset() / PAGE_SIZE;
        let pages = v.contents_len() / PAGE_SIZE;
        for (a, b) in FillPages::intersections(&fill.materialized.borrow(), first, first + pages) {
            for p in a..b {
                let at = ((p - first) * PAGE_SIZE) as usize;
                // SAFETY: both pieces of host memory have v.len bytes, this page lies within the
                // file's contents, and they do not overlap
                unsafe {
                    let src =
                        std::slice::from_raw_parts(v.host.as_ptr().add(at), PAGE_SIZE as usize);
                    let dst =
                        std::slice::from_raw_parts_mut(host.as_ptr().add(at), PAGE_SIZE as usize);
                    if src != dst {
                        dst.copy_from_slice(src);
                    }
                }
            }
        }
        Ok((region, host))
    }

    /// Moves the mappings in `[old, old + len)` to `dst` as they are (the host memory stays put).
    fn move_range(&mut self, old: u64, len: u64, dst: u64) -> Result<(), Errno> {
        // Copy-on-write pages are recorded by guest address: each side copies before the move
        self.cow_settle(old, old + len)?;
        self.split_at(old);
        self.split_at(old + len);
        let starts: Vec<u64> = self.vmas.range(old..old + len).map(|(&s, _)| s).collect();
        // Publish destination ranges for any writable shared VMAs before `move_entries` makes
        // destination PTEs visible to concurrent threads on the no-BKL futex fast path, keeping
        // the old ranges present until all source PTEs have been removed.
        let moved_shared: Vec<(u64, u64)> = starts
            .iter()
            .filter_map(|&s| {
                let v = &self.vmas[&s];
                (v.backing == Backing::Shared && v.may_write).then(|| {
                    let new_start = dst + (s - old);
                    (new_start, new_start + v.len)
                })
            })
            .collect();
        if !moved_shared.is_empty() {
            self.shared_maps
                .write()
                .unwrap_or_else(PoisonError::into_inner)
                .extend(moved_shared.iter().copied());
        }
        // Retain every source VMA until all PTEs have moved. Reversing a partial move
        // reuses the original leaf tables (or restores a whole aligned superpage).
        if let Err(e) = self.mmu.move_entries(old, dst, len) {
            self.mmu
                .move_entries(dst, old, len)
                .expect("restore moved PTEs to their original tables");
            // A concurrent thread may have translated code at the temporary destination.
            for &s in &starts {
                let v = &self.vmas[&s];
                if v.prot & prot::EXEC != 0 {
                    self.code_ranges.push((dst + (s - old), v.len));
                    self.exec_changed = true;
                }
            }
            self.shootdown();
            if !moved_shared.is_empty() {
                self.note_shared_maps();
            }
            return Err(map_err(e));
        }
        let mut moved = Vec::with_capacity(starts.len());
        for s in starts {
            let mut v = self.vmas.remove(&s).unwrap();
            let new = dst + (s - old);
            if v.backing == Backing::Anonymous && !v.has_anon_vma.get() {
                v.anon_pgoff = new / PAGE_SIZE;
            }
            if v.prot & prot::EXEC != 0 {
                self.code_ranges.push((s, v.len));
                self.code_ranges.push((new, v.len));
            }
            if let Some((id, _)) = v.shm {
                v.shm = Some((id, dst));
            }
            moved.push((new, v));
        }
        // Keep the recorded vDSO address in sync when the vDSO moves (Linux's arch_remap), and
        // clear it if only part of the vDSO was moved out.
        if let Some((vdso, vdso_end)) = self.vdso_range() {
            if old <= vdso && vdso_end <= old + len {
                self.vdso = dst + (vdso - old);
            } else if old < vdso_end && vdso < old + len {
                self.vdso = 0;
            }
        }
        // The pieces only move, so they take no room under `vm.max_map_count` (beyond the
        // splits, which the callers' margins cover); existing entries were already moved by
        // `move_entries`, so an eager-prefill allocation failure must not drop the moved VMAs.
        for (s, v) in moved {
            self.place_moved_vma(s, v);
        }
        if !moved_shared.is_empty() {
            // Source PTEs have been removed and moved VMAs are now in `self.vmas`; drop the stale
            // source ranges.
            self.note_shared_maps();
        }
        self.dirty = true;
        Ok(())
    }

    /// remap_file_pages(2): emulated with mmap as on Linux since 4.0, replacing
    /// `[start, start + len)` with the same file's contents from `offset`. The range must lie in
    /// contiguous shared mappings of the same file with the same permissions.
    pub fn remap_file_pages(&mut self, start: u64, len: u64, offset: u64) -> Result<(), Errno> {
        let end = start
            .checked_add(len)
            .filter(|&e| e > start)
            .ok_or(Errno::EINVAL)?;
        let (&s, v) = self
            .vmas
            .range(..=start)
            .next_back()
            .filter(|(s, v)| **s + v.len > start)
            .ok_or(Errno::EINVAL)?;
        if v.backing != Backing::Shared {
            return Err(Errno::EINVAL);
        }
        let Some((fd, _)) = v.file.clone() else {
            return Err(Errno::EINVAL);
        };
        let (prot, may_write, may_exec, name, ino, mnt, locked) = (
            v.prot,
            v.may_write,
            v.may_exec,
            v.name.clone(),
            v.ino,
            v.mnt.as_ref().map(|m| m.0),
            v.locked,
        );
        // The same file: compared by the host (device, inode)
        let id = v.file_id.map(|(d, i, _)| (d, i));
        let mut at = s + v.len;
        while at < end {
            let next = self
                .vmas
                .get(&at)
                .filter(|n| {
                    n.backing == Backing::Shared
                        && n.file.is_some()
                        && n.file_id.map(|(d, i, _)| (d, i)) == id
                })
                .filter(|n| n.prot == prot && v.same_fill_source(n))
                .ok_or(Errno::EINVAL)?;
            at += next.len;
        }
        let raw = std::os::fd::AsRawFd::as_raw_fd(&*fd);
        let flags = flags::MAP_SHARED | flags::MAP_FIXED;
        // A FUSE remap keeps the daemon's page source and inode namespace.
        self.map(
            start,
            len,
            prot,
            flags,
            Some((raw, offset, may_write)),
            v.fill
                .clone()
                .map(FileSource::Fuse)
                .or_else(|| v.tmpfs().cloned().map(FileSource::Tmpfs)),
        )?;
        if !may_exec {
            self.deny_exec(start, len);
        }
        self.label(start, len, name, ino);
        if let Some(mnt) = mnt {
            self.set_mnt(start, len, mnt);
        }
        if locked {
            self.set_locked(start, len, true)?;
        }
        Ok(())
    }

    /// Implements brk(2): returns the new break, or the old one on failure. The heap is readable
    /// and writable, and executable too with `exec` (`READ_IMPLIES_EXEC`, Linux's
    /// `VM_DATA_DEFAULT_FLAGS`).
    #[cfg(test)]
    pub fn brk(&mut self, new: u64, exec: bool) -> u64 {
        self.brk_limited(new, exec, u64::MAX)
    }

    /// Like [`Mm::brk`], also enforcing `memlock_limit` (`RLIMIT_MEMLOCK`, or `u64::MAX` with
    /// `CAP_IPC_LOCK`) when `mlockall(MCL_FUTURE)` is active (Linux 6.1's `do_brk_flags` ->
    /// `mlock_future_check`).
    pub fn brk_limited(&mut self, new: u64, exec: bool, memlock_limit: u64) -> u64 {
        let heap = prot::READ | prot::WRITE | if exec { prot::EXEC } else { 0 };
        if new < self.brk_start {
            return self.brk;
        }
        let (Some(old_end), Some(new_end)) = (page_up(self.brk), page_up(new)) else {
            return self.brk;
        };
        if new_end > old_end {
            let grow = new_end - old_end;
            if self.lock_future && !self.can_lock(grow, memlock_limit) {
                return self.brk;
            }
            if !self.is_free(old_end, grow) {
                return self.brk;
            }
            let grown = self.grow_heap(old_end, grow, heap)
                || self.start_heap(old_end, grow, heap)
                || self.map_anonymous(old_end, grow, heap).is_ok();
            if !grown {
                return self.brk;
            }
        } else if new_end < old_end && self.munmap(new_end, old_end - new_end).is_err() {
            return self.brk;
        }
        self.brk = new;
        new
    }

    /// When the heap is not mapped yet, maps `len` bytes at `start` and reserves [`HEAP_RESERVE`]
    /// of host address space.
    fn start_heap(&mut self, start: u64, len: u64, heap: u32) -> bool {
        if start != page_up(self.brk_start).unwrap_or(0) || len > HEAP_RESERVE {
            return false;
        }
        let Ok((region, host)) = Self::new_anonymous_reserved(HEAP_RESERVE) else {
            return false;
        };
        self.insert(
            start,
            len,
            len,
            heap,
            Backing::Anonymous,
            true,
            region,
            host,
        )
        .is_ok()
    }

    /// Lengthens the heap VMA ending at `end` by `grow` bytes if its host memory has room after it
    /// and it has the heap's permissions `heap`.
    fn grow_heap(&mut self, end: u64, grow: u64, heap: u32) -> bool {
        let Some((&s, v)) = self.vmas.range(..end).next_back() else {
            return false;
        };
        let compatible = v.backing == Backing::Anonymous
            && v.accounted
            && !v.noreserve
            && !v.dontfork
            && !v.wipeonfork
            && !v.dontdump
            && !v.growsdown
            && v.may_write
            && v.may_exec
            && v.prot == heap
            && v.locked == self.lock_future
            && v.name.is_none();
        if s + v.len != end || !compatible {
            return false;
        }
        let used = v.host.as_ptr() as usize - v.region.base.as_ptr() as usize + v.len as usize;
        if used + grow as usize > v.region.len {
            return false;
        }
        // No other mapping may use the host range right after it (a part of the heap moved away by
        // mremap still belongs to the same host memory)
        let (lo, hi) = (v.host.as_ptr() as usize + v.len as usize, grow as usize);
        let taken = self.vmas.values().any(|o| {
            let at = o.host.as_ptr() as usize;
            Arc::ptr_eq(&o.region, &v.region) && at < lo + hi && lo < at + o.len as usize
        });
        if taken {
            return false;
        }
        // SAFETY: [lo, lo + hi) is inside this private anonymous memory and no other mapping uses
        // it
        let host = unsafe { NonNull::new_unchecked(lo as *mut u8) };
        v.region.note_used(host, hi);
        // Grown again after shrinking: what was written before must read as zero again
        unsafe { discard_host(host, hi) };
        if Self::map_pages(&mut self.mmu, end, host, grow, v.prefill_prot(), false).is_err() {
            return false;
        }
        let v = self.vmas.get_mut(&s).unwrap();
        v.len += grow;
        v.file_len += grow;
        self.join_anon_vmas_at(end + grow);
        if heap & prot::EXEC != 0 {
            self.exec_changed = true;
            self.code_ranges.push((end, grow));
        }
        true
    }

    /// shmat: maps shared memory segment `id` at `addr` (choosing a place itself when None). With
    /// `remap` it may replace existing mappings; otherwise the range must be free.
    pub fn attach_shm(
        &mut self,
        addr: Option<u64>,
        mem: &SharedMemory,
        prot: u32,
        remap: bool,
        id: crate::ipc::ShmKey,
    ) -> Result<u64, Errno> {
        let len = mem.len();
        let start = match addr {
            Some(a) => {
                if a.checked_add(len).is_none_or(|e| e > 1 << VA_BITS) {
                    return Err(Errno::EINVAL);
                }
                if !self.is_free(a, len) {
                    if !remap {
                        return Err(Errno::EINVAL);
                    }
                    self.munmap(a, len)?;
                }
                a
            }
            None => self.find_free(len).ok_or(Errno::ENOMEM)?,
        };
        let host = mem.region.base;
        self.insert(
            start,
            len,
            len,
            prot,
            Backing::Shared,
            true,
            mem.region.clone(),
            host,
        )?;
        self.vmas.get_mut(&start).unwrap().shm = Some((id, start));
        Ok(start)
    }

    /// shmdt: unmaps the shmat that starts at `addr` and returns its segment.
    pub fn detach_shm(&mut self, addr: u64) -> Result<crate::ipc::ShmKey, Errno> {
        let id = self
            .vmas
            .get(&addr)
            .and_then(|v| v.shm)
            .filter(|&(_, base)| base == addr)
            .map(|(id, _)| id)
            .ok_or(Errno::EINVAL)?;
        let parts: Vec<(u64, u64)> = self
            .vmas
            .range(addr..)
            .take_while(|(_, v)| v.shm == Some((id, addr)))
            .map(|(&s, v)| (s, v.len))
            .collect();
        for (s, len) in parts {
            self.munmap(s, len)?;
        }
        Ok(id)
    }

    /// How many times shared memory segment `id` is attached in this address space.
    pub fn shm_attachments(&self, id: crate::ipc::ShmKey) -> usize {
        let mut bases: Vec<u64> = self
            .vmas
            .values()
            .filter_map(|v| v.shm.filter(|&(i, _)| i == id).map(|(_, b)| b))
            .collect();
        bases.sort_unstable();
        bases.dedup();
        bases.len()
    }

    /// mprotect(2) without `PROT_GROWSDOWN` or `PROT_GROWSUP` ([`Mm::protect`]).
    #[cfg(test)]
    pub fn mprotect(&mut self, addr: u64, len: u64, prot: u32) -> Result<(), Errno> {
        self.protect(addr, len, prot, 0, false)
    }

    /// Implements mprotect(2) as Linux's do_mprotect_pkey does. The VMAs from the one holding
    /// `addr` are changed in turn, and an error at one leaves those before it changed: a gap is
    /// ENOMEM, a permission the VMA may never have (`may_write`, `may_exec`) EACCES. With
    /// `PROT_GROWSDOWN` in `grows` the range starts instead at the start of the Linux VMA
    /// ([`same_vma`]) it begins in, which must grow down (EINVAL); arm64 has no grows-up mappings,
    /// so `PROT_GROWSUP` is always EINVAL once the range is found. With `implies_exec`
    /// (`READ_IMPLIES_EXEC`) a readable request makes each VMA that may execute executable too.
    pub fn protect(
        &mut self,
        addr: u64,
        len: u64,
        prot: u32,
        grows: u32,
        implies_exec: bool,
    ) -> Result<(), Errno> {
        const PROT_GROWSDOWN: u32 = 0x0100_0000;
        if !addr.is_multiple_of(PAGE_SIZE) {
            return Err(Errno::EINVAL);
        }
        if len == 0 {
            return Ok(());
        }
        let end = page_up(len)
            .and_then(|l| addr.checked_add(l))
            .ok_or(Errno::ENOMEM)?;
        // The first VMA ending above addr
        let (first, v) = self
            .vmas
            .range(..=addr)
            .next_back()
            .filter(|&(&s, v)| s + v.len > addr)
            .or_else(|| self.vmas.range(addr..).next())
            .map(|(&s, v)| (s, v))
            .ok_or(Errno::ENOMEM)?;
        let (mut start, mut from) = (addr, first);
        if grows & PROT_GROWSDOWN != 0 {
            if first >= end {
                return Err(Errno::ENOMEM);
            }
            if !v.growsdown {
                return Err(Errno::EINVAL);
            }
            start = self.vma_start(first);
            from = start;
        } else if first > addr {
            return Err(Errno::ENOMEM);
        } else if grows != 0 {
            return Err(Errno::EINVAL);
        }
        // The parts to change, each with its permissions (READ_IMPLIES_EXEC adds execution only
        // where the VMA may execute, as do_mprotect_pkey does per VMA)
        let (mut stop, mut error, mut parts) = (start, None, Vec::<(u64, u64, u32)>::new());
        for (&s, v) in self.vmas.range(from..end) {
            if s > stop {
                error = Some(Errno::ENOMEM);
                break;
            }
            if prot & prot::WRITE != 0 && !v.may_write || prot & prot::EXEC != 0 && !v.may_exec {
                error = Some(Errno::EACCES);
                break;
            }
            let p = if implies_exec && prot & prot::READ != 0 && v.may_exec {
                prot | prot::EXEC
            } else {
                prot
            };
            let (a, b) = (s.max(start), (s + v.len).min(end));
            match parts.last_mut() {
                Some(last) if last.1 == a && last.2 == p => last.1 = b,
                _ => parts.push((a, b, p)),
            }
            stop = s + v.len;
        }
        if error.is_none() && stop < end {
            error = Some(Errno::ENOMEM);
        }
        for (a, b, p) in parts {
            if b > a {
                self.set_protection(a, b, p)?;
            }
        }
        error.map_or(Ok(()), Err)
    }

    /// Gives `[addr, end)`, which is fully mapped, permissions `prot`.
    fn set_protection(&mut self, addr: u64, end: u64, prot: u32) -> Result<(), Errno> {
        self.room_for(self.splits(&[addr, end]))?;
        self.split_at(addr);
        self.split_at(end);
        if prot & prot::WRITE != 0 {
            let shared: Vec<u64> = self
                .vmas
                .range(addr..end)
                .filter(|(_, v)| v.cow)
                .map(|(&s, _)| s)
                .collect();
            for s in shared {
                self.unshare(s)?;
            }
        }
        // A reservation (HostRegion::reserved) becomes accessible: give this part host memory
        if mmu_prot(prot) != 0 {
            let reserved: Vec<(u64, bool)> = self
                .vmas
                .range(addr..end)
                .filter(|(_, v)| v.reserved())
                .map(|(&s, v)| (s, prot & prot::WRITE != 0 && !v.noreserve))
                .collect();
            for (s, reserve) in reserved {
                self.back_reserved(s, reserve)?;
            }
        }
        for (&s, v) in self.vmas.range_mut(addr..end) {
            let (old, new) = (mmu_prot(v.prot), mmu_prot(prot));
            if v.pages.is_some() {
                if old != new {
                    self.mmu.unmap(s, v.len).map_err(map_err)?;
                    self.dirty = true;
                    Self::prefill_pages(
                        &mut self.mmu,
                        s,
                        v.host,
                        v.eager_len(),
                        new & !prot::WRITE,
                        true,
                    );
                }
            } else if old != 0 || new != 0 {
                let cow = self.cow.borrow();
                let pages = if v.backing == Backing::Anonymous {
                    Self::cow_pages(&cow, s, s + v.len)
                } else {
                    Vec::new()
                };
                // Establish the correct backing under the old permissions before exposing any
                // new permission, including when fork left a PROT_NONE borrower without a PTE.
                if new != 0 {
                    Self::cow_entries(&self.mmu, &cow, s, v, &pages, old & !prot::WRITE)?;
                }
                let effective = if v.backing == Backing::Anonymous && !v.written.get() {
                    new & !prot::WRITE
                } else {
                    new
                };
                if let Err(e) =
                    Self::protect_entries(&mut self.mmu, s, v, &pages, effective, old == 0)
                {
                    // A partial superpage demotion can fail after earlier leaves changed. Restore
                    // their permissions and invalidate translations gained during the attempt.
                    let old_eff = v.prefill_prot();
                    let base = if pages.is_empty() {
                        old_eff
                    } else {
                        old & !prot::WRITE
                    };
                    let _ = self.mmu.protect(s, v.len, base);
                    if old_eff != base {
                        let _ = Self::write_around(&mut self.mmu, s, v.len, &pages, old_eff);
                    }
                    self.dirty |= effective & !base != 0;
                    if (old | effective) & prot::EXEC != 0 && old != effective {
                        self.code_ranges.push((s, v.len));
                        self.exec_changed = true;
                    }
                    return Err(e);
                }
            }
            if (v.prot | prot) & prot::EXEC != 0 && v.prot != prot {
                self.code_ranges.push((s, v.len));
                self.exec_changed = true;
            }
            self.dirty |= old & !new != 0;
            v.accounted |= prot & prot::WRITE != 0 && v.backing != Backing::Shared && !v.noreserve;
            v.prot = prot;
            if v.backing != Backing::Anonymous && prot & prot::WRITE != 0 {
                v.written.set(true);
            }
        }
        for (&s, _) in self.vmas.range(addr..end) {
            self.join_anon_vmas_at(s);
        }
        self.join_anon_vmas_at(end);
        Ok(())
    }

    /// Change existing PTEs first. After leaving PROT_NONE, eager fill can populate holes
    /// because every CoW page already has its owner-backed entry, even if inaccessible.
    fn protect_entries(
        mmu: &mut Mmu,
        s: u64,
        v: &Vma,
        cow_pages: &[u64],
        new: u32,
        prefill: bool,
    ) -> Result<(), Errno> {
        let first = if cow_pages.is_empty() {
            new
        } else {
            new & !prot::WRITE
        };
        mmu.protect(s, v.len, first).map_err(map_err)?;
        if prefill && new != 0 {
            Self::prefill_pages(
                mmu,
                s,
                v.host,
                v.eager_len(),
                new,
                v.backing != Backing::Anonymous,
            );
        }
        if first != new {
            Self::write_around(mmu, s, v.len, cow_pages, new)?;
        }
        Ok(())
    }

    /// Returns the first VMA overlapping `[cursor, end)` (either containing `cursor` or starting
    /// within `[cursor, end)`), along with its start address.
    fn next_vma(&self, cursor: u64, end: u64) -> Option<(u64, &Vma)> {
        self.vmas
            .range(..=cursor)
            .next_back()
            .filter(|&(&s, v)| s + v.len > cursor)
            .or_else(|| self.vmas.range(cursor..end).next())
            .map(|(&s, v)| (s, v))
    }

    /// madvise(`MADV_REMOVE`): frees this part of shared mappings, which then read zeros. The
    /// host mapping is shared too, so the host punches the hole in the file or shared memory
    /// behind it (Linux punches one in the file); the parts of host pages at the ends (4 KB guest
    /// pages on a 16 KB host), or everything when the host refuses, are zeroed through the
    /// mapping instead, which keeps their storage. Walks mapped VMAs in order like Linux 6.1's
    /// `do_madvise`: unmapped gaps are skipped and reported as `ENOMEM` at the end, while a VMA
    /// error (`EINVAL` for locked, private anonymous or GPU mappings; `EACCES` for other private
    /// mappings or ones that cannot get write permission) stops immediately, leaving earlier
    /// mapped portions removed.
    pub(crate) fn remove(&mut self, addr: u64, len: u64) -> RemovePlan {
        let mut tmpfs = Vec::new();
        let mut fuse = Vec::new();
        let Some(end) = page_up(len).and_then(|l| addr.checked_add(l)) else {
            return RemovePlan {
                tmpfs,
                fuse,
                result: Err(Errno::ENOMEM),
            };
        };
        let mut cursor = addr;
        let mut has_gap = false;
        while cursor < end {
            let Some((s, v)) = self.next_vma(cursor, end) else {
                has_gap = true;
                break;
            };
            if cursor < s {
                has_gap = true;
                cursor = s;
            }
            if v.locked || v.backing == Backing::Anonymous || v.region.gpu.is_some() {
                return RemovePlan {
                    tmpfs,
                    fuse,
                    result: Err(Errno::EINVAL),
                };
            }
            if v.backing != Backing::Shared || !v.may_write {
                return RemovePlan {
                    tmpfs,
                    fuse,
                    result: Err(Errno::EACCES),
                };
            }
            let stop = end.min(s + v.len);
            if let Some(fill) = &v.fill {
                fuse.push((
                    fill.clone(),
                    v.offset() + (cursor - s),
                    v.offset() + (stop - s),
                ));
            } else {
                // The part past the end of the file must not be touched (the host would raise
                // SIGBUS)
                let to = stop.min(s + v.file_len);
                if cursor < to {
                    if let Some(mapping) = v.tmpfs() {
                        tmpfs.push(TmpfsRange {
                            mapping: mapping.clone(),
                            offset: v.offset() + cursor - s,
                            len: to - cursor,
                        });
                    } else {
                        // SAFETY: [cursor, to) is inside this VMA, which holds the host memory;
                        // for a shared mapping that can get write permission the host mapping is
                        // always writable and shared
                        unsafe {
                            remove_host(
                                v.host.as_ptr().add((cursor - s) as usize),
                                (to - cursor) as usize,
                            )
                        };
                    }
                }
            }
            cursor = stop;
        }
        RemovePlan {
            tmpfs,
            fuse,
            result: if has_gap { Err(Errno::ENOMEM) } else { Ok(()) },
        }
    }

    /// Walks mapped VMAs in `[addr, addr + len)` like Linux 6.1's `do_madvise`: returns `EINVAL`
    /// on the first VMA failing `allow` (overriding any earlier unmapped gap) and `ENOMEM` at the
    /// end if any gap existed.
    fn check_vmas(
        &self,
        addr: u64,
        len: u64,
        allow: impl Fn(u64, &Vma) -> bool,
    ) -> Result<(), Errno> {
        let end = addr.checked_add(len).ok_or(Errno::ENOMEM)?;
        let mut cursor = addr;
        let mut has_gap = false;
        while cursor < end {
            let Some((s, v)) = self.next_vma(cursor, end) else {
                has_gap = true;
                break;
            };
            if cursor < s {
                has_gap = true;
            }
            if !allow(s, v) {
                return Err(Errno::EINVAL);
            }
            cursor = end.min(s + v.len);
        }
        if has_gap { Err(Errno::ENOMEM) } else { Ok(()) }
    }

    /// `MADV_FREE`: refuses locked, non-private-anonymous, or `[vdso]` VMAs (`EINVAL`, matching
    /// Linux 6.1's `madvise_dontneed_free` + `madvise_free_single_vma`) and reports gaps as
    /// `ENOMEM`.
    pub(crate) fn check_free(&self, addr: u64, len: u64) -> Result<(), Errno> {
        self.check_vmas(addr, len, |s, v| {
            !v.locked && v.backing == Backing::Anonymous && (self.vdso == 0 || s != self.vdso)
        })
    }

    /// `MADV_COLD` and `MADV_PAGEOUT`: refuses locked, foreign (`[vvar]`), or GPU (`VM_PFNMAP`)
    /// VMAs (`EINVAL`, matching Linux 6.1's `can_madv_lru_vma`) and reports gaps as `ENOMEM`.
    pub(crate) fn check_lru(&self, addr: u64, len: u64) -> Result<(), Errno> {
        self.check_vmas(addr, len, |_, v| {
            !v.locked && !v.foreign() && v.region.gpu.is_none()
        })
    }

    /// Prefills soft page-table entries for read-only non-FUSE file mappings in `[addr, addr + len)`
    /// (`MADV_WILLNEED`), capped at [`FILE_PREFILL_MAX`] bytes per call.
    pub fn prefill_file_ptes(&self, addr: u64, len: u64) {
        let end = addr.saturating_add(len);
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        let mut budget = FILE_PREFILL_MAX;
        for (&s, v) in self
            .vmas
            .range(first..end)
            .filter(|&(&s, v)| s + v.len > addr)
        {
            if budget == 0
                || v.file_id.is_none()
                || v.tmpfs().is_some()
                || v.fill.is_some()
                || v.foreign()
                || v.region.gpu.is_some()
                || v.prot & prot::READ == 0
                || v.prot & prot::WRITE != 0
            {
                continue;
            }
            let from = addr.max(s) & !(PAGE_SIZE - 1);
            let to = page_up(end.min(s + v.file_len))
                .unwrap_or(s + v.file_len)
                .min(s + v.file_len);
            if from >= to {
                continue;
            }
            let span = (to - from).min(budget);
            // SAFETY: [from, from + span) is inside this VMA before EOF, which holds the host
            // memory.
            let host = unsafe { v.host.add((from - s) as usize) };
            if unsafe { self.mmu.fill_shared(from, host, span, mmu_prot(v.prot)) }.is_err() {
                break;
            }
            budget -= span;
        }
    }

    /// Builds a host-page-aligned [`AdviseRange`] for `[from, to)` inside VMA `v` at `s`.
    fn advise_slice(s: u64, v: &Vma, from: u64, to: u64) -> Option<AdviseRange> {
        let page = appine_hal::page_size();
        let reg_start = v.region.base.as_ptr() as usize;
        let reg_end = reg_start + v.region.len.next_multiple_of(page);
        let host_from = v.host.as_ptr() as usize + (from - s) as usize;
        let host_to = v.host.as_ptr() as usize + (to - s) as usize;
        let start = (host_from & !(page - 1)).max(reg_start);
        let stop = host_to.next_multiple_of(page).min(reg_end);
        (start < stop).then(|| AdviseRange {
            _region: v.region.clone(),
            ptr: NonNull::new(start as *mut u8).unwrap(),
            len: stop - start,
        })
    }

    /// Collects host-page-aligned slices of live host regions overlapping `[addr, addr + len)` for
    /// non-destructive `madvise(2)` hints executed after releasing the BKL.
    ///
    /// Skips reserved (`PROT_NONE`), foreign (`[vvar]`), GPU, and FUSE on-demand mappings, and
    /// clips ranges to `file_len` so pages past EOF are never advised. When `file_only` is true
    /// (`MADV_NORMAL`, `MADV_RANDOM`, `MADV_SEQUENTIAL`), only file-backed host mappings are
    /// included so anonymous and recycled host VMAs are never split; otherwise (`MADV_WILLNEED`),
    /// untouched anonymous VMAs are still skipped.
    pub fn advise_ranges(&self, addr: u64, len: u64, file_only: bool) -> Vec<AdviseRange> {
        let end = addr.saturating_add(len);
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        let mut out: Vec<AdviseRange> = Vec::new();
        for (&s, v) in self
            .vmas
            .range(first..end)
            .filter(|&(&s, v)| s + v.len > addr)
        {
            if v.reserved() || v.foreign() || v.region.gpu.is_some() || v.fill.is_some() {
                continue;
            }
            if file_only {
                if v.file_id.is_none() || v.region.anonymous.is_some() {
                    continue;
                }
            } else if v.backing == Backing::Anonymous && !v.written.get() {
                continue;
            }
            let from = addr.max(s);
            let to = end.min(s + v.file_len);
            if from >= to {
                continue;
            }
            let Some(range) = Self::advise_slice(s, v, from, to) else {
                continue;
            };
            let start = range.ptr.as_ptr() as usize;
            let stop = start + range.len;
            if let Some(last) = out.last_mut()
                && Arc::ptr_eq(&last._region, &range._region)
                && start >= last.ptr.as_ptr() as usize
                && start <= last.ptr.as_ptr() as usize + last.len
            {
                let new_end = (last.ptr.as_ptr() as usize + last.len).max(stop);
                last.len = new_end - last.ptr.as_ptr() as usize;
            } else {
                out.push(range);
            }
        }
        out
    }

    /// Faults one page of VMA `s` via [`Self::try_fault_in`] when absent, then touches its host
    /// backing for `MADV_POPULATE_READ` / `MADV_POPULATE_WRITE`.
    ///
    /// # Safety
    ///
    /// `[page, page + bytes)` must lie within backed, in-EOF host memory of VMA `s` (and be
    /// host-writable when `write` is true).
    unsafe fn fault_populate_page(
        &self,
        s: u64,
        page: u64,
        bytes: usize,
        need: u32,
        write: bool,
    ) -> Result<(), Errno> {
        if self.mmu.translate(page, need).is_none()
            && !self.try_fault_in(page, need).map_err(|_| Errno::EFAULT)?
        {
            return Err(Errno::EFAULT);
        }
        // SAFETY: guaranteed by the caller.
        unsafe { self.vmas[&s].populate_host((page - s) as usize, bytes, write) };
        Ok(())
    }

    /// Advances `madvise(MADV_POPULATE_READ | MADV_POPULATE_WRITE)` along `walk`, matching
    /// Linux 6.1's `do_madvise` + `madvise_populate`:
    /// - Skips unmapped gaps (`walk.has_gap`) so the caller reports `ENOMEM` at the end unless a
    ///   later VMA fails with `EINVAL` or `EFAULT`.
    /// - Refuses VMAs lacking the requested guest permission (`PROT_READ` / `PROT_WRITE`) or
    ///   special `[vvar]` / GPU mappings with `EINVAL`.
    /// - Refreshes stale file extents, faults tmpfs and software-tracked private files, yields for
    ///   unlocked FUSE fills or `>= 64 KB` regular-file `MADV_WILLNEED` warming, preserves CoW on
    ///   read while breaking CoW on write, installs missing soft PTEs, and stops with `EFAULT` at
    ///   the first page past EOF or failing allocation.
    pub(crate) fn populate_step(
        &mut self,
        walk: &mut PopulateWalk,
        write: bool,
    ) -> Result<PopulateStep, Errno> {
        const ADVISE_MIN: u64 = 64 * 1024;
        let need = if write { prot::WRITE } else { prot::READ };

        while walk.cursor < walk.end {
            let Some((s, v)) = self.next_vma(walk.cursor, walk.end) else {
                walk.has_gap = true;
                walk.cursor = walk.end;
                break;
            };
            if walk.cursor < s {
                walk.has_gap = true;
                walk.cursor = s;
            }
            if v.foreign() || v.region.gpu.is_some() || v.prot & need == 0 {
                return Err(Errno::EINVAL);
            }
            let stop = walk.end.min(s + v.len);

            // On-demand FUSE mapping: request unlocked fills for missing pages, fail past EOF,
            // install PTEs (including shared-write baselines), and touch host memory.
            if v.fill.is_some() {
                for page in (walk.cursor..stop).step_by(PAGE_SIZE as usize) {
                    let v = &self.vmas[&s];
                    if let Some((fill, fpage)) = v.unread(s, page) {
                        walk.cursor = page;
                        return Ok(PopulateStep::Fill(fill, fpage));
                    }
                    if page >= s + v.contents_len() {
                        return Err(Errno::EFAULT);
                    }
                    // SAFETY: `page` lies within `[s, s + v.contents_len())`, is already filled in
                    // the memfd, and is mapped writable on the host whenever `write` is true.
                    unsafe { self.fault_populate_page(s, page, PAGE_SIZE as usize, need, write)? };
                }
                walk.cursor = stop;
                continue;
            }

            // Non-FUSE mappings: refresh the host file extent when `walk.cursor` reaches recorded
            // EOF; if still past EOF (or past a shared-anonymous host region end), fail `EFAULT`.
            if walk.cursor >= s + v.file_len {
                if self.refresh_file_extent(walk.cursor) == Some(true) {
                    continue;
                }
                return Err(Errno::EFAULT);
            }
            let in_eof = stop.min(s + v.file_len);

            // Tmpfs mappings (read or write) and software-tracked private files (write): admit
            // each page through `try_fault_in` before touching host memory.
            if v.pages.as_ref().is_some_and(|t| t.tmpfs.is_some() || write) {
                for page in (walk.cursor..in_eof).step_by(PAGE_SIZE as usize) {
                    let bytes = (in_eof - page).min(PAGE_SIZE) as usize;
                    // SAFETY: `[page, page + bytes)` lies within `[s, s + v.file_len)` and is
                    // backed by a live host mapping (writable when `write` is true).
                    unsafe { self.fault_populate_page(s, page, bytes, need, write)? };
                }
                walk.cursor = in_eof;
                continue;
            }

            // Warm large regular file slices with host `MADV_WILLNEED` outside the BKL so disk
            // readahead does not stall other guest threads, then resume under the BKL to fault.
            if v.file_id.is_some()
                && v.region.anonymous.is_none()
                && walk.cursor >= walk.warmed_until
                && in_eof - walk.cursor >= ADVISE_MIN
                && let Some(range) = Self::advise_slice(s, v, walk.cursor, in_eof)
            {
                walk.warmed_until = walk.warmed_until.max(in_eof);
                return Ok(PopulateStep::Advise(range));
            }

            // Fault host pages and install missing soft page-table entries.
            let cursor = walk.cursor;
            if v.backing == Backing::Anonymous && write {
                self.cow_settle(cursor, in_eof)?;
                self.prepare_anon_write(s, v)?;
            }
            if v.backing == Backing::Anonymous && !write {
                self.fill_anon_non_cow(s, v, cursor, in_eof)
                    .map_err(map_err)?;
                // Read-populate without breaking CoW or setting `v.written`: touch borrowed pages
                // via the owner's host memory and non-borrowed runs via our own.
                let cow = self.cow.borrow();
                let mut cur = cursor;
                for (&page, b) in cow.borrowed.range(cursor..in_eof) {
                    if page > cur {
                        // SAFETY: `[cur, page)` lies inside this VMA's host memory.
                        unsafe {
                            v.populate_host((cur - s) as usize, (page - cur) as usize, false)
                        };
                    }
                    // SAFETY: `b.region` retains the borrowed host page.
                    unsafe { appine_hal::populate(b.host.as_ptr(), PAGE_SIZE as usize) };
                    cur = page + PAGE_SIZE;
                }
                if cur < in_eof {
                    // SAFETY: `[cur, in_eof)` lies inside this VMA's host memory.
                    unsafe { v.populate_host((cur - s) as usize, (in_eof - cur) as usize, false) };
                }
            } else {
                // SAFETY: `[cursor, in_eof)` lies within `[s, s + v.file_len)` and holds host memory.
                let host = unsafe { v.host.add((cursor - s) as usize) };
                unsafe {
                    self.mmu
                        .fill_shared(cursor, host, in_eof - cursor, v.prefill_prot())
                }
                .map_err(|_| Errno::ENOMEM)?;
                // SAFETY: `[cursor, in_eof)` lies within `[s, s + v.file_len)` and is backed by
                // live host memory (writable on the host whenever `write` is true: anonymous CoW
                // was just settled, writable private files are never `v.cow`, and writable shared
                // files are mapped RW).
                unsafe {
                    v.populate_host((cursor - s) as usize, (in_eof - cursor) as usize, write)
                };
            }

            walk.cursor = in_eof;
        }
        Ok(PopulateStep::Done)
    }

    /// Test helper wrapping [`Mm::discard_range`] for callers that expect no gap/error.
    #[cfg(test)]
    fn discard(&mut self, addr: u64, len: u64) -> Result<Vec<Reread>, Errno> {
        let (rereads, res) = self.discard_range(addr, len, false);
        res.map(|()| rereads)
    }

    /// madvise(`MADV_DONTNEED`, `MADV_DONTNEED_LOCKED`): anonymous memory goes back to the host
    /// (reading zero afterwards); the written pages of private file mappings go back to the file's
    /// contents (Linux drops their copies and reads the file again): whole host pages of a host
    /// file mapping through the host, the rest returned as [`Reread`]s for the caller to read from
    /// the file; shared mappings stay unchanged. Walks mapped VMAs in order like Linux 6.1's
    /// `do_madvise`: unmapped gaps are skipped and reported as `ENOMEM` at the end, while a
    /// foreign (`[vvar]`), GPU (`VM_PFNMAP`), or (unless `allow_locked`) locked VMA stops
    /// immediately with `EINVAL` (taking precedence over earlier gaps), still returning partial
    /// [`Reread`]s collected beforehand. `MADV_DONTNEED_LOCKED` discards pages without unlocking
    /// the VMA.
    pub(crate) fn discard_range(
        &mut self,
        addr: u64,
        len: u64,
        allow_locked: bool,
    ) -> (Vec<Reread>, Result<(), Errno>) {
        let mut rereads = Vec::new();
        let Some(len) = page_up(len) else {
            return (rereads, Err(Errno::EINVAL));
        };
        let Some(end) = addr.checked_add(len) else {
            return (rereads, Err(Errno::EINVAL));
        };
        let mut cursor = addr;
        let mut has_gap = false;
        while cursor < end {
            let Some((s, v)) = self.next_vma(cursor, end) else {
                has_gap = true;
                break;
            };
            if cursor < s {
                has_gap = true;
                cursor = s;
            }
            if (!allow_locked && v.locked) || v.foreign() || v.region.gpu.is_some() {
                return (rereads, Err(Errno::EINVAL));
            }
            let stop = end.min(s + v.len);
            if v.backing == Backing::Anonymous && !v.reserved() {
                let (exec, host) = (v.prot & prot::EXEC != 0, v.host);
                if exec {
                    self.code_ranges.push((cursor, stop - cursor));
                }
                // Borrowers still need lent pages, and borrowed pages are replaced by our own
                // (reading zero afterwards)
                if let Err(e) = self.cow_settle(cursor, stop) {
                    return (rereads, Err(e));
                }
                // SAFETY: [cursor, stop) is inside this VMA, and its host memory is the VMA's
                // private anonymous memory
                unsafe { discard_host(host.add((cursor - s) as usize), (stop - cursor) as usize) };
                // The vDSO comes back as the kernel's image, not zeros (on Linux a special
                // mapping whose pages fault back in; breakpoints written into it are gone)
                if s == self.vdso {
                    let image = self.vdso_image();
                    let (from, to) = (
                        (cursor - s) as usize,
                        ((stop - s) as usize).min(image.len()),
                    );
                    if from < to {
                        // SAFETY: [from, to) is inside this VMA's host memory, writable on the host
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                image[from..].as_ptr(),
                                host.add(from).as_ptr(),
                                to - from,
                            )
                        };
                    }
                } else if self.mmu.next_present(cursor, stop) < stop {
                    // Zap soft-MMU entries for discarded anonymous pages (as Linux's
                    // zap_page_range_single does on MADV_DONTNEED) so discarded pages are not
                    // scanned in touched_windows or mistaken for swapped-out pages when pagemap is
                    // unreadable.
                    if let Err(e) = self.mmu.unmap(cursor, stop - cursor).map_err(map_err) {
                        return (rereads, Err(e));
                    }
                    self.dirty = true;
                }
            } else if v.backing == Backing::PrivateFile && v.written.get() {
                // Only written pages differ from the file, and whole pages past the end of the
                // file have no entries. Fork marks every read-only private file VMA `cow` (even if
                // written before becoming read-only); unshare it first so discarding reverts only
                // this address space without corrupting the peer.
                let in_file = stop.min(s + page_up(v.contents_len()).unwrap_or(v.len));
                if cursor < in_file {
                    if v.cow
                        && let Err(e) = self.unshare(s)
                    {
                        return (rereads, Err(e));
                    }
                    let v = &self.vmas[&s];
                    if v.prot & prot::EXEC != 0 {
                        self.code_ranges.push((cursor, in_file - cursor));
                    }
                    // Read on demand: its host file holds what was read, which the rest of a host
                    // page is read back from
                    if let Some(fill) = &v.fill {
                        use std::os::unix::fs::FileExt;
                        // SAFETY: [cursor, in_file) is inside this VMA's host file mapping
                        let left = unsafe {
                            discard_file_host(
                                v.host.add((cursor - s) as usize),
                                (in_file - cursor) as usize,
                            )
                        };
                        let base = v.offset() + (cursor - s);
                        for (off, l) in left {
                            // SAFETY: this piece lies inside this VMA's own writable host memory
                            let dst = unsafe {
                                std::slice::from_raw_parts_mut(
                                    v.host.as_ptr().add((cursor - s) as usize + off),
                                    l,
                                )
                            };
                            if fill.host.read_exact_at(dst, base + off as u64).is_err() {
                                dst.fill(0);
                            }
                        }
                        cursor = stop;
                        continue;
                    }
                    if let Some(t) = &v.pages {
                        let lo = v.offset() + cursor - s;
                        let hi = v.offset() + in_file - s;
                        let grain = t.page_size();
                        t.copied
                            .borrow_mut()
                            .retain(|off| *off < lo || *off + grain > hi);
                        if let Err(e) = self.mmu.unmap(cursor, in_file - cursor).map_err(map_err) {
                            return (rereads, Err(e));
                        }
                        self.dirty = true;
                    }
                    let base = v.file_id.map_or(0, |f| f.2) + (cursor - s);
                    let reread = |a: u64, l: u64| Reread {
                        addr: a,
                        len: l,
                        ino: v.ino,
                        offset: base + (a - cursor),
                    };
                    if v.region.anonymous.is_none() {
                        // A host private file mapping: the host drops its copies of whole host
                        // pages
                        // SAFETY: [cursor, in_file) is inside this VMA's host file mapping
                        let left = unsafe {
                            discard_file_host(
                                v.host.add((cursor - s) as usize),
                                (in_file - cursor) as usize,
                            )
                        };
                        for (off, l) in left {
                            rereads.push(reread(cursor + off as u64, l as u64));
                        }
                    } else {
                        // Anonymous memory holding a copy of the file (copied before it became
                        // writable, or unshared above)
                        rereads.push(reread(cursor, in_file - cursor));
                    }
                }
            }
            cursor = stop;
        }
        let res = if has_gap { Err(Errno::ENOMEM) } else { Ok(()) };
        (rereads, res)
    }

    /// Stores `data` at `addr` in a private file mapping, from the file again after
    /// [`discard_range`](Self::discard_range) (its pages are never lent, so they are written in place).
    pub fn fill_private(&mut self, addr: u64, data: &[u8]) {
        let Some((&s, v)) = self.vmas.range(..=addr).next_back() else {
            return;
        };
        let end = addr.saturating_add(data.len() as u64);
        if v.backing != Backing::PrivateFile || v.cow || end > s + v.len {
            return;
        }
        if let Some(pages) = &v.pages
            && pages.tmpfs.is_none()
            && !data.is_empty()
        {
            let from = pages.page_start(v.offset() + addr - s);
            pages
                .copied
                .borrow_mut()
                .extend((from..v.offset() + end - s).step_by(pages.page_size() as usize));
        }
        // SAFETY: [addr, end) is inside this VMA's own writable host memory
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                v.host.as_ptr().add((addr - s) as usize),
                data.len(),
            );
        }
    }

    /// process_mrelease: every process using this address space is exiting, so its private memory
    /// goes back to the host now, as Linux's `__oom_reap_task_mm` unmaps the pages of every VMA
    /// that is anonymous or not shared, while the VMAs (and `/proc/<pid>/maps`) stay as they are.
    /// Written private anonymous memory reads zero afterwards; borrowed pages are returned without
    /// copying once their entries point at the VMA's own page. A failed remap keeps the loan.
    /// Lent pages stay for their borrowers. Written private file mappings revert to the file
    /// on whole host pages, or to zeros if copied into anonymous memory.
    /// On Linux a later fault anywhere in a reaped address space is `SIGBUS` (`MMF_UNSTABLE`), so
    /// what the dying threads would see is never relied on. Executable and `PROT_NONE`-reserved
    /// mappings are left alone: the former's translations would have to be invalidated (the vDSO
    /// among them), the latter hold nothing.
    pub fn release(&mut self) {
        let kept = |v: &Vma| v.prot & prot::EXEC != 0 || v.reserved();
        let remapped: Vec<u64> = self
            .cow
            .borrow()
            .borrowed
            .keys()
            .filter_map(|&page| {
                let (s, v) = self.anon_vma(page).filter(|(_, v)| !kept(v))?;
                let own = Self::own_page(s, v, page);
                // SAFETY: the VMA retains its own page, which will be discarded below.
                unsafe { cow_map_shared(&self.mmu, page, own, PAGE_SIZE, mmu_prot(v.prot)) }
                    .ok()?;
                Some(page)
            })
            .collect();
        let borrowed = &mut self.cow.get_mut().borrowed;
        let returned = remapped
            .into_iter()
            .filter_map(|page| borrowed.remove_entry(&page))
            .collect();
        // Threads still running guest code flush before the owners get their pages back
        self.give_back(returned);
        let lent = self.cow.borrow().lent.clone();
        for (&s, v) in self
            .vmas
            .iter()
            .filter(|(_, v)| !kept(v) && v.written.get())
        {
            match v.backing {
                Backing::Anonymous => Self::discard_unlent_in(s, v, &lent),
                // Only written pages differ from the file (a `cow` mapping never is), and whole
                // pages past its end have no entries
                Backing::PrivateFile if !v.cow => {
                    let len = page_up(v.contents_len()).unwrap_or(v.len).min(v.len) as usize;
                    // SAFETY: [host, host + len) is this VMA's own private host memory
                    unsafe {
                        if v.region.anonymous.is_none() {
                            let _ = discard_file_host(v.host, len);
                        } else {
                            discard_host(v.host, len);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    /// `MADV_DONTDUMP`, `MADV_DODUMP`: whether `[addr, addr + len)` is written to core files.
    /// Acts on mapped portions in order and returns `ENOMEM` at the end if any gap existed.
    pub fn set_dontdump(&mut self, addr: u64, len: u64, dontdump: bool) -> Result<(), Errno> {
        self.update_range(addr, len, |_| Ok(()), |v| v.dontdump = dontdump)
    }

    /// `MADV_WIPEONFORK`, `MADV_KEEPONFORK`: whether a forked child gets `[addr, addr + len)`
    /// zero-filled ([`Vma::wipeonfork`]). Wiping applies only to private anonymous memory
    /// (`EINVAL` stops at the offending VMA, taking precedence over earlier unmapped gaps).
    pub fn set_wipeonfork(&mut self, addr: u64, len: u64, wipe: bool) -> Result<(), Errno> {
        self.update_range(
            addr,
            len,
            |v| {
                if wipe && v.backing != Backing::Anonymous {
                    Err(Errno::EINVAL)
                } else {
                    Ok(())
                }
            },
            |v| v.wipeonfork = wipe,
        )
    }

    /// `MADV_DONTFORK`, `MADV_DOFORK`: whether a forked child gets `[addr, addr + len)` at all.
    /// Acts on mapped portions in order and returns `ENOMEM` at the end if any gap existed.
    pub fn set_dontfork(&mut self, addr: u64, len: u64, dontfork: bool) -> Result<(), Errno> {
        self.update_range(addr, len, |_| Ok(()), |v| v.dontfork = dontfork)
    }

    /// Walks mapped VMAs in `[addr, addr + len)` like Linux 6.1's `do_madvise`: validates each VMA
    /// slice, splits at its ends and applies `f`, skipping unmapped gaps (returning `ENOMEM` at
    /// the end if any gap existed) and stopping immediately on a VMA validation or split error.
    fn update_range(
        &mut self,
        addr: u64,
        len: u64,
        validate: impl Fn(&Vma) -> Result<(), Errno>,
        f: impl Fn(&mut Vma),
    ) -> Result<(), Errno> {
        let end = addr.checked_add(len).ok_or(Errno::ENOMEM)?;
        let mut cursor = addr;
        let mut has_gap = false;
        while cursor < end {
            let Some((s, v)) = self.next_vma(cursor, end) else {
                has_gap = true;
                break;
            };
            if cursor < s {
                has_gap = true;
                cursor = s;
            }
            validate(v)?;
            let stop = end.min(s + v.len);
            self.room_for(self.splits(&[cursor, stop]))?;
            self.split_at(cursor);
            self.split_at(stop);
            f(self.vmas.get_mut(&cursor).unwrap());
            self.join_anon_vmas_at(cursor);
            self.join_anon_vmas_at(stop);
            cursor = stop;
        }
        if has_gap { Err(Errno::ENOMEM) } else { Ok(()) }
    }

    /// Bytes already locked in `[addr, addr + len)` (mlock counts only the newly locked part).
    pub fn locked_in(&self, addr: u64, len: u64) -> u64 {
        let end = addr.saturating_add(len);
        self.vmas
            .iter()
            .filter(|&(&s, v)| v.locked && s < end && s + v.len > addr)
            .map(|(&s, v)| (s + v.len).min(end) - s.max(addr))
            .sum()
    }

    /// Bytes locked (VmLck in `/proc/<pid>/status`, `RLIMIT_MEMLOCK`).
    pub fn locked_bytes(&self) -> u64 {
        self.vmas.values().filter(|v| v.locked).map(|v| v.len).sum()
    }

    /// Whether locking `more` additional bytes stays within `limit` (`RLIMIT_MEMLOCK`).
    pub fn can_lock(&self, more: u64, limit: u64) -> bool {
        self.locked_bytes().saturating_add(more) <= limit
    }

    /// Whether the mapping containing `addr` is locked.
    pub fn is_locked_at(&self, addr: u64) -> bool {
        self.vmas
            .range(..=addr)
            .next_back()
            .is_some_and(|(&s, v)| addr < s + v.len && v.locked)
    }

    /// mlock, munlock: locks or unlocks contiguous mapped VMAs in `[addr, addr + len)` (widened to
    /// pages), matching Linux 6.1's `apply_vma_lock_flags`: stops at the first unmapped gap and
    /// returns `ENOMEM`, leaving earlier contiguous VMAs updated and VMAs after the gap untouched.
    pub fn set_locked(&mut self, addr: u64, len: u64, locked: bool) -> Result<(), Errno> {
        let start = addr & !(PAGE_SIZE - 1);
        let end = page_up(addr.checked_add(len).ok_or(Errno::ENOMEM)?).ok_or(Errno::ENOMEM)?;
        let mut cursor = start;
        while cursor < end {
            let Some((&s, v)) = self
                .vmas
                .range(..=cursor)
                .next_back()
                .filter(|&(&s, v)| s + v.len > cursor)
            else {
                return Err(Errno::ENOMEM);
            };
            let stop = end.min(s + v.len);
            self.room_for(self.splits(&[cursor, stop]))?;
            self.split_at(cursor);
            self.split_at(stop);
            self.vmas.get_mut(&cursor).unwrap().locked = locked;
            self.join_anon_vmas_at(cursor);
            self.join_anon_vmas_at(stop);
            cursor = stop;
        }
        Ok(())
    }

    /// mlockall, munlockall: locks or unlocks every mapping.
    pub fn set_all_locked(&mut self, locked: bool) {
        for v in self.vmas.values_mut() {
            v.locked = locked;
        }
        for &s in self.vmas.keys() {
            self.join_anon_vmas_at(s);
        }
    }

    /// Populates `[addr, addr + len)` for `mlock`/`mlock2` without `MLOCK_ONFAULT` (Linux 6.1's
    /// `__mm_populate(ignore_errors=false)`): stops immediately and returns `ENOMEM` when a
    /// `PROT_NONE` mapping is encountered (leaving earlier VMAs populated and later ones
    /// untouched).
    #[cfg(test)]
    pub fn populate_mlock(&self, addr: u64, len: u64) -> Result<(), Errno> {
        let mut cursor = addr;
        let end = addr.saturating_add(len);
        while cursor < end {
            match self.populate_mlock_step(&mut cursor, end, true)? {
                Some((_, _, stop)) => cursor = stop,
                None => break,
            }
        }
        Ok(())
    }

    /// The next unread FUSE `Fill` page at or after `cursor` within `[cursor, end)` regardless of
    /// guest permissions (Linux 6.1's `madvise_willneed` reads ahead into the page cache even on
    /// `PROT_NONE` file mappings). Returns `(guest_page_addr, vma_stop, fill, file_page)`.
    pub(crate) fn next_unread_fill(
        &self,
        cursor: u64,
        end: u64,
    ) -> Option<(u64, u64, Rc<Fill>, u64)> {
        if !self.fills || cursor >= end {
            return None;
        }
        let first = self
            .vmas
            .range(..=cursor)
            .next_back()
            .map_or(cursor, |(&s, _)| s);
        for (&s, v) in self
            .vmas
            .range(first..end)
            .filter(|&(&s, v)| s + v.len > cursor)
        {
            let Some(fill) = &v.fill else {
                continue;
            };
            let stop = end.min(s + v.len);
            let extent = if fill.size_stale.get() {
                v.len
            } else {
                v.contents_len()
            };
            let from = cursor.max(s);
            let to = stop.min(s + extent);
            if from >= to {
                continue;
            }
            let base_page = v.offset() / PAGE_SIZE;
            let lo = (from - s) / PAGE_SIZE;
            let hi = (to - s).div_ceil(PAGE_SIZE);
            if let Some(fpage) = fill.first_missing(base_page + lo, base_page + hi) {
                let guest_page = s + (fpage - base_page) * PAGE_SIZE;
                return Some((guest_page, stop, fill.clone(), fpage));
            }
        }
        None
    }

    /// Populates `[cursor, end)` for `mlock`/`mlock2`/`mlockall`/`MAP_POPULATE`/`remap_file_pages`,
    /// yielding `Ok(Some((fill, page, vma_stop)))` when a cold FUSE `Fill` page must be fetched
    /// outside the BKL. With `fail_on_none`, stops immediately and returns `ENOMEM` on `PROT_NONE`.
    pub(crate) fn populate_mlock_step(
        &self,
        cursor: &mut u64,
        end: u64,
        fail_on_none: bool,
    ) -> Result<Option<(Rc<Fill>, u64, u64)>, Errno> {
        let start = *cursor;
        let first = self
            .vmas
            .range(..=start)
            .next_back()
            .map_or(start, |(&s, _)| s);
        for (&s, v) in self
            .vmas
            .range(first..end)
            .filter(|&(&s, v)| s + v.len > start)
        {
            let from = (*cursor).max(s);
            let stop = end.min(s + v.len);
            if v.prot == 0 {
                if fail_on_none {
                    return Err(Errno::ENOMEM);
                }
                *cursor = stop;
                continue;
            }
            if v.fill.is_some() {
                let lo = from & !(PAGE_SIZE - 1);
                let hi = page_up(stop).unwrap_or(stop);
                let need = mmu_prot(v.prot);
                for page in (lo..hi).step_by(PAGE_SIZE as usize) {
                    if let Some((fill, fpage)) = v.unread(s, page) {
                        *cursor = page;
                        return Ok(Some((fill, fpage, stop)));
                    }
                    if page >= s + v.contents_len() {
                        break;
                    }
                    if self.mmu.next_present(page, page + PAGE_SIZE) != page {
                        let _ = self.try_fault_in(page, need);
                    }
                    // SAFETY: `page` lies within `[s, s + v.contents_len())` and is already filled.
                    unsafe { v.populate_host((page - s) as usize, PAGE_SIZE as usize, false) };
                }
                *cursor = stop;
                continue;
            }
            let to = end.min(s + v.file_len);
            if from >= to {
                *cursor = stop;
                continue;
            }
            let (lo, hi) = (from & !(PAGE_SIZE - 1), page_up(to).unwrap_or(to));
            if v.tmpfs().is_some() {
                for page in (lo..hi).step_by(PAGE_SIZE as usize) {
                    if self.mmu.next_present(page, page + PAGE_SIZE) != page {
                        self.try_fault_in(page, 0).map_err(|_| Errno::EFAULT)?;
                    }
                }
                *cursor = stop;
                continue;
            } else if v.backing == Backing::Anonymous {
                if v.prot & prot::WRITE == 0 {
                    // Read-only private anonymous memory: Linux 6.1 maps the shared zero page
                    // (not counted as RSS) and does not break CoW. Skipping host touches avoids
                    // inflating mincore RSS or double-counting borrowed CoW pages in smaps.
                    *cursor = stop;
                    continue;
                }
                if v.foreign() || v.region.gpu.is_some() || v.reserved() {
                    *cursor = stop;
                    continue;
                }
                // Writable private anonymous memory: Linux 6.1's populate_vma_page_range faults
                // with FOLL_WRITE, breaking CoW and allocating private host pages (not the zero
                // page) so RSS reflects the populated pages without double-counting borrowed pages.
                self.cow_settle(lo, hi)?;
                self.prepare_anon_write(s, v)?;
            }
            // Install entries before write-populating any host pages. Existing CoW entries
            // retain their translations.
            let write = v.backing == Backing::Anonymous;
            // SAFETY: [lo, hi) lies within the VMA's accessible host extent.
            let host = unsafe { v.host.add((lo - s) as usize) };
            unsafe { self.mmu.fill_shared(lo, host, hi - lo, v.prefill_prot()) }
                .map_err(map_err)?;
            // SAFETY: [from, to) is backed; write-populated anonymous pages have settled CoW.
            unsafe { v.populate_host((from - s) as usize, (to - from) as usize, write) };
            *cursor = stop;
        }
        *cursor = end;
        Ok(None)
    }

    /// File offsets intersecting shared FUSE VMAs for msync and address-space teardown.
    pub(crate) fn fuse_ranges(&self, addr: u64, len: u64) -> Vec<(Rc<Fill>, u64, u64)> {
        if !self.fills || len == 0 {
            return Vec::new();
        }
        let end = addr.saturating_add(len);
        self.vmas
            .range(..end)
            .filter_map(|(&s, v)| {
                let fill = v.fill.as_ref()?;
                (v.backing == Backing::Shared && s + v.len > addr).then(|| {
                    (
                        fill.clone(),
                        v.offset() + addr.saturating_sub(s),
                        v.offset() + v.len.min(end - s),
                    )
                })
            })
            .collect()
    }

    /// Returns the next mapped VMA slice overlapping `[cursor, end)` for Linux 6.1's per-VMA
    /// `msync(2)` loop. When `sync` is true (`MS_SYNC`), populates [`MsyncTarget`] for shared
    /// file mappings (retaining `Arc<HostRegion>` across the unlocked host `msync` call).
    pub(crate) fn next_msync(&self, cursor: u64, end: u64, sync: bool) -> MsyncStep {
        let Some((s, v)) = self.next_vma(cursor, end) else {
            return MsyncStep::Unmapped;
        };
        let start = cursor.max(s);
        let stop = end.min(s + v.len);
        let target = if sync && v.backing == Backing::Shared {
            if let Some(fill) = &v.fill {
                Some(MsyncTarget::Fuse(
                    fill.clone(),
                    v.offset() + (start - s),
                    v.offset() + (stop - s),
                ))
            } else if v.file_id.is_some() && !v.foreign() && v.region.gpu.is_none() && !v.reserved()
            {
                let page = appine_hal::page_size();
                let reg_start = v.region.base.as_ptr() as usize;
                let reg_end = reg_start + v.region.len.next_multiple_of(page);
                let host = v.host.as_ptr() as usize + (start - s) as usize;
                let hstart = (host & !(page - 1)).max(reg_start);
                let hstop = (host + (stop - start) as usize)
                    .next_multiple_of(page)
                    .min(reg_end);
                (hstart < hstop).then(|| {
                    MsyncTarget::Host(MsyncHost {
                        _region: v.region.clone(),
                        addr: hstart,
                        len: hstop - hstart,
                    })
                })
            } else {
                None
            }
        } else {
            None
        };
        MsyncStep::Vma {
            start,
            stop,
            locked: v.locked,
            target,
        }
    }

    /// Implements munmap(2).
    pub fn munmap(&mut self, addr: u64, len: u64) -> Result<(), Errno> {
        let len = page_up(len).ok_or(Errno::EINVAL)?;
        if !addr.is_multiple_of(PAGE_SIZE)
            || len == 0
            || addr.checked_add(len).is_none_or(|e| e > 1 << VA_BITS)
        {
            return Err(Errno::EINVAL);
        }
        let end = addr + len;
        // As on Linux, max_map_count applies only when one VMA is split into three
        let inside = |a: u64| {
            self.vmas
                .range(..a)
                .next_back()
                .filter(|(s, v)| **s + v.len > a)
        };
        if let (Some((s1, _)), Some((s2, _))) = (inside(addr), inside(end))
            && s1 == s2
        {
            self.room_for(1)?;
        }
        self.split_at(addr);
        self.split_at(end);
        let borrowed = self.cow_unmap(addr, end)?;
        // The page table unmaps page by page, so only VMAs that actually exist are handled: a guest
        // passing a length that covers the whole address space is still fast
        let doomed: Vec<(u64, u64)> = self
            .vmas
            .range(addr..end)
            .map(|(&s, v)| (s, v.len))
            .collect();
        let mut removed_shared = false;
        for (s, len) in doomed {
            let vma = self.vmas.remove(&s).unwrap();
            self.mmu.unmap(s, len).map_err(map_err)?;
            removed_shared |= vma.backing == Backing::Shared && vma.may_write;
            if vma.prot & prot::EXEC != 0 {
                self.exec_changed = true;
                self.code_ranges.push((s, len));
            }
            if vma.backing == Backing::Shared
                && vma.may_write
                && let Some(fill) = &vma.fill
            {
                self.unmapped_fills
                    .push((fill.clone(), vma.offset(), vma.offset() + len));
            }
            self.graveyard.push(vma.region);
            self.dirty = true;
        }
        if removed_shared {
            // All doomed PTEs are unmapped above; refresh `shared_maps` to drop torn-down ranges.
            self.note_shared_maps();
        }
        if let Some((vdso, vdso_end)) = self.vdso_range()
            && addr < vdso_end
            && vdso < end
        {
            self.vdso = 0;
        }
        self.give_back(borrowed);
        Ok(())
    }

    /// Fills `out` with 0/1 residency bytes for the next contiguous mapped chunk starting at
    /// page-aligned `addr` within `[addr, end)` (at most `PAGE_SIZE` pages, matching Linux 6.1's
    /// `do_mincore`), returning the guest address after the chunk or `ENOMEM` if `addr` is
    /// unmapped.
    pub(crate) fn residency_chunk(
        &self,
        addr: u64,
        end: u64,
        out: &mut Vec<u8>,
    ) -> Result<u64, Errno> {
        const MAX_PAGES: u64 = PAGE_SIZE;
        out.clear();
        let (&s, v) = self
            .vmas
            .range(..=addr)
            .next_back()
            .filter(|&(&s, v)| s + v.len > addr)
            .ok_or(Errno::ENOMEM)?;
        let stop = end
            .min(s + v.len)
            .min(addr.saturating_add(MAX_PAGES * PAGE_SIZE));
        let backed_end = stop.min(s + v.host_len());
        if addr < backed_end {
            // SAFETY: [addr, backed_end) lies inside the host region.
            let host = unsafe { v.host.as_ptr().add((addr - s) as usize) };
            out.extend(
                appine_hal::page_residency(host, (backed_end - addr) as usize)
                    .into_iter()
                    .map(u8::from),
            );
        }
        out.resize(((stop - addr) / PAGE_SIZE) as usize, 0);
        // Borrowed pages are in the owner's host memory.
        for (&page, _) in self.cow.borrow().borrowed.range(addr..stop) {
            out[((page - addr) / PAGE_SIZE) as usize] = 1;
        }
        Ok(stop)
    }

    /// Residency of `[addr, addr + len)` for core-dump sparseness and tests. The range must be
    /// fully mapped.
    pub fn residency(&self, addr: u64, len: u64) -> Result<Vec<bool>, Errno> {
        let end = page_up(addr.checked_add(len).ok_or(Errno::ENOMEM)?).ok_or(Errno::ENOMEM)?;
        self.check_mapped(addr, end - addr)?;
        let mut out = Vec::with_capacity(((end - addr) / PAGE_SIZE) as usize);
        let mut cursor = addr;
        while cursor < end {
            let (&s, v) = self.vmas.range(..=cursor).next_back().unwrap();
            let stop = end.min(s + v.len);
            let backed_end = stop.min(s + v.host_len());
            if cursor < backed_end {
                // SAFETY: [cursor, backed_end) lies inside the host region.
                let host = unsafe { v.host.as_ptr().add((cursor - s) as usize) };
                out.extend(appine_hal::page_residency(
                    host,
                    (backed_end - cursor) as usize,
                ));
            }
            out.resize(((stop - addr) / PAGE_SIZE) as usize, false);
            cursor = stop;
        }
        // Borrowed pages are in the owner's host memory
        for (&page, _) in self
            .cow
            .borrow()
            .borrowed
            .range(addr & !(PAGE_SIZE - 1)..end)
        {
            out[((page - (addr & !(PAGE_SIZE - 1))) / PAGE_SIZE) as usize] = true;
        }
        Ok(out)
    }

    // ---- fork ----

    /// fork: makes a new address space. Written private anonymous mappings are copy-on-write
    /// ([`Mm::lend`]); contents never written are all zero, so the child uses its own; writable
    /// private file mappings retain their file backing and inherit private copies page by page.
    /// Shared mappings and read-only private file mappings share host memory with the child.
    /// The caller first stops the other threads of the same address
    /// space outside guest code ([`Mm::quiesce`]).
    pub fn fork(&mut self) -> Result<Rc<RefCell<Mm>>, Errno> {
        if OVERCOMMIT_MEMORY.load(Ordering::Relaxed) != 1
            && self.commit_too_big(appine_hal::ram_and_swap())
        {
            return Err(Errno::ENOMEM);
        }
        // On failure the unpublished child drops before the regions backing its borrowed PTEs.
        let mut plan = LendingPlan::default();
        let shared = Mm::new().into_shared();
        let mut child = shared.borrow_mut();
        child.loans = self.loans.clone();
        child.files = self.files.clone();
        child.private_files = self.private_files.clone();
        child.brk_start = self.brk_start;
        child.brk = self.brk;
        child.vdso = self.vdso;
        child.vdso_svc = self.vdso_svc;
        child.code = self.code;
        child.data = self.data;
        child.args = self.args;
        child.env = self.env;
        // membarrier registrations last until execve (a new Mm), as Linux copies the mm's
        // membarrier_state at fork
        child.membarrier = self.membarrier;
        child.auxv = self.auxv.clone();
        child.exe = self.exe;
        child.exe_open = self.exe_open.clone();
        child.dbt_regs = self.dbt_regs;
        child.memops = self.memops.clone();
        child.mmap_top = self.mmap_top;
        child.fills = self.fills;
        child.start_stack = self.start_stack;
        child.stack_low = self.stack_low;
        let spare: BTreeMap<u64, u64> = self
            .vmas
            .iter()
            .filter(|(_, v)| v.growsdown && v.backing == Backing::Anonymous)
            .map(|(&s, _)| (s, self.spare_below(s)))
            .collect();
        let heap_start = page_up(self.brk_start).unwrap_or(0);
        let is_heap = |s: u64, v: &Vma| {
            s == heap_start && v.backing == Backing::Anonymous && v.len <= HEAP_RESERVE
        };
        // The child's own small mappings (data segment, .bss, malloc's small blocks) are carved
        // from one piece of host memory: a shell execs right after fork, and each mapping used to
        // cost one host mmap and one munmap. Large ones, the heap and grows-down ones still get a
        // piece each, so they can be returned to the host when unmapped
        let pieces: Vec<u64> = self
            .vmas
            .iter()
            .filter(|&(&s, v)| {
                !v.dontfork
                    && !v.growsdown
                    && !v.reserved()
                    && !is_heap(s, v)
                    && v.len <= FORK_PIECE_MAX
                    && v.backing == Backing::Anonymous
            })
            .map(|(&s, _)| s)
            .collect();
        let mut carved = Self::carve(&self.vmas, &pieces)?;
        // As Linux's anon_vma_fork, every child VMA with contents of its own (an anon_vma: a page
        // written since mapped) gets its own anon_vma: the pieces of one VMA keep sharing it, but
        // no longer join their neighbours. A private file mapping counts once a page holds a private copy
        // (the anon_vma belongs to the whole mapping when it is split, so all its pieces count)
        let mut anon = HashMap::new();
        let mut private = HashMap::new();
        let mut prev: Option<(u64, &Vma, u64)> = None;
        for (&s, v) in &self.vmas {
            let own = match v.backing {
                Backing::Shared => false,
                Backing::Anonymous => v.has_anon_vma.get() && !v.wipeonfork,
                Backing::PrivateFile => {
                    v.written.get()
                        && *private.entry(Arc::as_ptr(&v.region)).or_insert_with(|| {
                            let r = &v.region;
                            appine_hal::has_private_pages(r.base.as_ptr(), r.len).unwrap_or(true)
                        })
                }
            };
            let id = match prev {
                _ if !own => 0,
                Some((end, p, id)) if end == s && id != 0 && same_vma(p, v) => id,
                _ => ANON_IDS.fetch_add(1, Ordering::Relaxed),
            };
            anon.insert(s, id);
            prev = Some((s + v.len, v, id));
        }
        // Written private anonymous mappings are copy-on-write: map the child's own (all-zero)
        // host memory first, then lend to it
        let mut cow = Vec::new();
        for (&start, v) in self.vmas.iter_mut() {
            if v.dontfork {
                continue;
            }
            // A reservation has no contents, and the child's is a reservation too
            // (HostRegion::reserved)
            let share = v.reserved()
                || match v.backing {
                    Backing::Shared => true,
                    // Neither side can write, so the contents cannot diverge; whoever makes it
                    // writable copies its own
                    Backing::PrivateFile if v.prot & prot::WRITE == 0 && v.tmpfs().is_none() => {
                        v.cow = true;
                        true
                    }
                    _ => false,
                };
            let (region, host) = if share {
                (v.region.clone(), v.host)
            } else if v.backing == Backing::PrivateFile {
                Self::copy_private_file(v)?
            } else {
                // The heap still reserves host address space, so growing it in the child extends
                // the same VMA too
                let heap = is_heap(start, v);
                let below = spare.get(&start).copied().unwrap_or(0);
                let (region, host) = if let Some(piece) = carved.remove(&start) {
                    piece
                } else if heap {
                    spare::anonymous_reserved(HEAP_RESERVE)?
                } else if below > 0 {
                    // The host memory reserved below the stack is kept as well
                    let (region, base) = spare::anonymous_reserved(below + v.len)?;
                    // SAFETY: this host memory has below + v.len bytes
                    let host = unsafe { NonNull::new_unchecked(base.as_ptr().add(below as usize)) };
                    (region, host)
                } else {
                    // MAP_NORESERVE is still not accounted (the rule at mmap): ASan's shadow memory
                    // of more than ten TB
                    Self::new_anonymous(v.len, v.prot & prot::WRITE != 0 && !v.noreserve)?
                };
                if v.written.get() && !v.wipeonfork {
                    cow.push(start);
                }
                (region, host)
            };
            let id = anon[&start];
            let c = Vma {
                region,
                host,
                locked: false,
                cow: v.cow && share,
                pages: v.pages.as_ref().map(|p| p.detached(v.offset(), v.len)),
                written: Cell::new(v.written.get() && !v.wipeonfork),
                has_anon_vma: Cell::new(v.backing == Backing::Anonymous && id != 0),
                anon: id,
                ..v.clone()
            };
            child.insert_vma(start, c)?;
        }
        for start in cow {
            self.lend(start, &mut plan);
        }
        plan.map(self, &child)?;

        // Both lists are in address order. Publish all loans together now that the PTEs exist.
        let mut newly_lent = plan.lent.iter().peekable();
        let mut loans = self.loans.borrow_mut();
        loans.reserve(plan.lent.len());
        for (page, b) in &plan.borrowed {
            let key = b.host.as_ptr() as usize;
            let borrower = (child.me.clone(), *page);
            if newly_lent.next_if(|p| *p == page).is_some() {
                loans.insert(key, Loan::new(Some((self.me.clone(), *page)), borrower));
            } else {
                let loan = loans.get_mut(&key);
                debug_assert!(loan.is_some(), "lent page missing from loan table");
                if let Some(loan) = loan {
                    loan.lend(borrower);
                }
            }
        }
        drop(loans);
        self.dirty |= !plan.lent.is_empty();
        child.cow.get_mut().borrowed = plan.borrowed.into_iter().collect();
        self.cow
            .get_mut()
            .lent
            .append(&mut plan.lent.into_iter().collect());
        // `child.insert_vma` already populated `child.shared_maps` for every copied writable
        // shared VMA.
        drop(child);
        Ok(shared)
    }

    /// Before fork, like Linux's `dup_mmap`, checks every commit-accounted VMA (ever-writable private
    /// mappings without `MAP_NORESERVE`) against the commit estimate (`vm.overcommit_memory` is
    /// 0): if one exceeds `limit`, the total of memory and swap (in bytes, 0 if unknown), it is
    /// ENOMEM. In Appine every mmap is its own piece of host memory and VMAs cannot merge, while
    /// Linux merges adjacent ones with the same flags, so they are counted merged. LTP's fork14
    /// maps 1 GB more each time and forks: natively, fork fails once the merged one exceeds total
    /// memory, while Appine used to always succeed, with the child's page table growing ever
    /// larger (2 MB per GB in the soft-MMU).
    fn commit_too_big(&self, limit: u64) -> bool {
        if limit == 0 {
            return false;
        }
        // The start of the previous accounted VMA, the VMA, and the merged length
        let mut run: Option<(u64, &Vma, u64)> = None;
        for (&s, v) in &self.vmas {
            if !v.accounted || v.dontfork {
                run = None;
                continue;
            }
            let total = match run {
                Some((last_start, last, total))
                    if last_start + last.len == s && same_vma(last, v) =>
                {
                    total + v.len
                }
                _ => v.len,
            };
            if total > limit {
                return true;
            }
            run = Some((s, v, total));
        }
        false
    }

    /// Carves host memory for the child's small mappings at fork (starting at `pieces`): all from
    /// one piece, each aligned to host pages. The piece is not counted in the host commit
    /// (`MAP_NORESERVE`): no mapping exceeds [`FORK_PIECE_MAX`], and accounting only matters for a
    /// single request failing when it exceeds total memory. Returns each start's piece and its
    /// host address.
    fn carve(vmas: &BTreeMap<u64, Vma>, pieces: &[u64]) -> Result<Carved, Errno> {
        let page = appine_hal::page_size() as u64;
        let mut out = BTreeMap::new();
        let total: u64 = pieces
            .iter()
            .map(|s| vmas[s].len.next_multiple_of(page))
            .sum();
        if total == 0 {
            return Ok(out);
        }
        let (region, base) = spare::anonymous(total)?;
        let mut at = 0;
        for &s in pieces {
            // SAFETY: the pieces lie in order within this host memory, and at + len does not exceed
            // total
            let host = unsafe { NonNull::new_unchecked(base.as_ptr().add(at as usize)) };
            out.insert(s, (region.clone(), host));
            at += vmas[&s].len.next_multiple_of(page);
        }
        Ok(out)
    }

    /// Bytes still free below the host memory of VMA `start`, by which it can be lengthened
    /// downwards in place: parts of the same host memory taken by other VMAs (split off, or moved
    /// away by mremap) do not count.
    fn spare_below(&self, start: u64) -> u64 {
        let v = &self.vmas[&start];
        if v.reserved() {
            return 0;
        }
        let host = v.host.as_ptr() as usize;
        let low = self
            .vmas
            .values()
            .filter(|o| Arc::ptr_eq(&o.region, &v.region))
            .map(|o| o.host.as_ptr() as usize + o.len as usize)
            .filter(|&end| end <= host)
            .fold(v.region.base.as_ptr() as usize, usize::max);
        (host - low) as u64
    }

    // ---- Files ----

    /// Ranges of shared mappings (of files, anonymous, or System V shared memory) that can be
    /// written (writable now, or can be mprotected writable later): futexes there are not keyed
    /// by address space and address ([`Mm::futex_key`]), so the no-BKL futex, which handles only
    /// writable private pages (`syscall::fast`), must leave them to the locked path. Shared
    /// mappings of files opened read-only do not count: Go's toolchain reads files through them
    /// and also maps a telemetry counter file shared and writable in every process, hence
    /// tracking by range. New and moved ranges are published in [`Mm::insert_vma`] and
    /// [`Mm::move_range`] before their PTEs become visible in `self.mmu`, and pruned in
    /// [`Mm::munmap`], [`Mm::move_range`] and [`Mm::deny_write`] via [`Mm::note_shared_maps`]
    /// after the old PTEs are gone.
    pub fn shared_maps(&self) -> Arc<RwLock<Vec<(u64, u64)>>> {
        self.shared_maps.clone()
    }

    /// Recounts [`Mm::shared_maps`] from the current mappings.
    fn note_shared_maps(&self) {
        let mut ranges = self
            .shared_maps
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        *ranges = self
            .vmas
            .iter()
            .filter(|(_, v)| v.backing == Backing::Shared && v.may_write)
            .map(|(&s, v)| (s, s + v.len))
            .collect();
    }

    /// Whether a shared mapping that can get write permission points at host file (`dev`, `ino`)
    /// (checked before a memfd gets `F_SEAL_WRITE`).
    pub fn writably_maps(&self, dev: u64, ino: u64) -> bool {
        self.vmas.values().any(|v| {
            v.backing == Backing::Shared
                && v.may_write
                && v.file_id.is_some_and(|(d, i, _)| (d, i) == (dev, ino))
        })
    }

    /// Whether some mapping points at host file (`dev`, `ino`) (checked before a file's data is
    /// replaced by another file's, `syscall::fs::clone_range`).
    pub fn maps_file(&self, dev: u64, ino: u64) -> bool {
        self.vmas
            .values()
            .any(|v| v.file_id.is_some_and(|(d, i, _)| (d, i) == (dev, ino)))
    }

    /// A tmpfs hole no longer owns pages. Revoke all aliases before freeing its storage so
    /// the next touch must claim space again, including in other address spaces.
    pub(crate) fn punch_tmpfs(&mut self, ino: u64, offset: u64, end: u64) -> bool {
        let mut changed = false;
        for (&s, v) in &self.vmas {
            if v.tmpfs().is_none_or(|t| t.ino != ino) {
                continue;
            }
            let first = v.offset();
            let from = (offset & !(PAGE_SIZE - 1)).max(first);
            let to = end
                .next_multiple_of(PAGE_SIZE)
                .min(first + v.contents_len());
            if from >= to {
                continue;
            }
            let addr = s + (from - first);
            self.mmu
                .unmap(addr, to - from)
                .expect("valid tmpfs VMA range");
            if v.prot & prot::EXEC != 0 {
                self.code_ranges.push((addr, to - from));
            }
            changed = true;
        }
        self.dirty |= changed;
        changed
    }

    /// Drop translations of invalidated FUSE pages in every alias, including executable ones.
    pub(crate) fn invalidate_fill(&mut self, pages: &Rc<FillPages>, lo: u64, hi: u64) -> bool {
        let mut changed = false;
        for (&start, v) in &self.vmas {
            if !v.fill.as_ref().is_some_and(|f| Rc::ptr_eq(&f.pages, pages)) {
                continue;
            }
            let first = v.offset() / PAGE_SIZE;
            let from = lo.max(first);
            let to = hi.min(first + v.contents_len() / PAGE_SIZE);
            if from >= to {
                continue;
            }
            for (a, b) in pages.runs(from, to) {
                let addr = start + (a - first) * PAGE_SIZE;
                let len = (b - a) * PAGE_SIZE;
                let _ = self.mmu.unmap(addr, len);
                if v.prot & prot::EXEC != 0 {
                    self.code_ranges.push((addr, len));
                }
                changed = true;
            }
        }
        self.dirty |= changed;
        changed
    }

    /// Queue code-cache invalidation for executable mappings of `pages` overlapping `[lo, hi)`.
    pub(crate) fn invalidate_fill_code(&mut self, pages: &Rc<FillPages>, lo: u64, hi: u64) -> bool {
        let mut changed = false;
        for (&start, v) in &self.vmas {
            if v.prot & prot::EXEC == 0
                || !v.fill.as_ref().is_some_and(|f| Rc::ptr_eq(&f.pages, pages))
            {
                continue;
            }
            let first = v.offset() / PAGE_SIZE;
            let from = lo.max(first);
            let to = hi.min(first + v.contents_len() / PAGE_SIZE);
            if from >= to {
                continue;
            }
            let addr = start + (from - first) * PAGE_SIZE;
            let len = (to - from) * PAGE_SIZE;
            self.code_ranges.push((addr, len));
            changed = true;
        }
        self.dirty |= changed;
        changed
    }

    /// Host file (`dev`, `ino`) was truncated to `size` bytes: pages past the new end in the VMAs
    /// mapping it are removed from the page table, so later guest accesses get SIGBUS, as with
    /// truncate on Linux. Otherwise the host would get SIGBUS accessing the mapping past the end
    /// of the file, and the whole app would exit. Returns whether anything changed; if so a
    /// shootdown is needed ([`Mm::sync`]).
    pub fn file_truncated(&mut self, dev: u64, ino: u64, size: u64) -> bool {
        self.clip_file_mappings(size, |v| {
            let (dev_id, ino_id, offset) = v.file_id?;
            ((dev_id, ino_id) == (dev, ino)).then_some(offset)
        })
    }

    /// Remove pages beyond EOF from each selected VMA and invalidate any executable tail.
    fn clip_file_mappings(&mut self, size: u64, file_offset: impl Fn(&Vma) -> Option<u64>) -> bool {
        let mut changed = false;
        for (&start, v) in &mut self.vmas {
            let Some(offset) = file_offset(v) else {
                continue;
            };
            let extent = size
                .saturating_sub(offset)
                .next_multiple_of(PAGE_SIZE)
                .min(v.len);
            let old = v.contents_len();
            if extent >= old {
                continue;
            }
            // unmap fails only on invalid arguments, and this range comes from a VMA
            let _ = self.mmu.unmap(start + extent, old - extent);
            if v.prot & prot::EXEC != 0 {
                self.code_ranges.push((start + extent, old - extent));
            }
            if let Some(t) = &v.pages {
                t.copied.borrow_mut().retain(|at| *at < offset + extent);
            }
            if v.fill.is_none() {
                v.file_len = extent;
            }
            changed = true;
        }
        self.dirty |= changed;
        changed
    }

    // ---- Introspection ----

    /// All mappings, in address order; the stack, heap and vDSO are named the way Linux names
    /// them. The pieces of one Linux VMA ([`same_vma`]) are joined into one entry: every anonymous
    /// mmap is separate host memory, VMAs cannot be merged, and python has hundreds after running
    /// for a while.
    pub fn regions(&self) -> Vec<Region> {
        let stack = self.stack_range();
        let mut out: Vec<Region> = Vec::new();
        let mut last: Option<&Vma> = None;
        for (&s, v) in &self.vmas {
            let special: Option<&[u8]> = if stack.is_some_and(|(lo, hi)| (lo..hi).contains(&s)) {
                Some(b"[stack]")
            } else if s == self.vdso {
                Some(b"[vdso]")
            } else if v.foreign() {
                Some(b"[vvar]")
            } else if s >= self.brk_start && s < self.brk && self.brk_start != 0 {
                Some(b"[heap]")
            } else {
                None
            };
            let name = v.name.clone().or_else(|| special.map(Rc::from));
            match (out.last_mut(), last) {
                (Some(r), Some(l)) if r.end == s && same_vma(l, v) && r.name == name => {
                    r.end = s + v.len;
                }
                _ => out.push(Region {
                    start: s,
                    end: s + v.len,
                    prot: v.prot,
                    shared: v.backing == Backing::Shared && !v.foreign(),
                    name,
                    file: v.file_id.map(|(_, _, offset)| (offset, v.ino)),
                    locked: v.locked,
                    may_write: v.may_write,
                    may_exec: v.may_exec,
                    dontdump: v.dontdump,
                    wipeonfork: v.wipeonfork,
                    dontfork: v.dontfork,
                }),
            }
            last = Some(v);
        }
        out
    }

    /// Whether `[addr, end)` lies inside one Linux VMA ([`same_vma`]): the pieces from the one
    /// holding `addr` onwards are contiguous and one VMA on Linux.
    fn in_one_vma(&self, addr: u64, end: u64) -> bool {
        let Some((&s, v)) = self.vmas.range(..=addr).next_back() else {
            return false;
        };
        let (mut last, mut reach) = (v, s + v.len);
        if addr >= reach {
            return false;
        }
        for (&s, v) in self.vmas.range(reach..) {
            if reach >= end {
                break;
            }
            if s != reach || !same_vma(last, v) {
                return false;
            }
            (last, reach) = (v, s + v.len);
        }
        reach >= end
    }

    /// The start of the Linux VMA ([`same_vma`]) holding piece `start`.
    fn vma_start(&self, start: u64) -> u64 {
        let (mut low, mut above) = (start, &self.vmas[&start]);
        for (&s, v) in self.vmas.range(..start).rev() {
            if s + v.len != low || !same_vma(v, above) {
                break;
            }
            (low, above) = (s, v);
        }
        low
    }

    /// The range labelled `[stack]` in `/proc/<pid>/maps`: as on Linux, the mapping containing
    /// the initial stack pointer, plus the grows-down VMAs with the same permissions directly
    /// below it (the parts the stack grew by when host memory was not contiguous).
    fn stack_range(&self) -> Option<(u64, u64)> {
        let sp = self.start_stack;
        let (&s, v) = self
            .vmas
            .range(..=sp)
            .next_back()
            .filter(|&(&s, v)| sp != 0 && sp < s + v.len)?;
        let mut low = s;
        for (&b, o) in self.vmas.range(..s).rev() {
            if b + o.len != low || !o.growsdown || o.prot != v.prot {
                break;
            }
            low = b;
        }
        Some((low, s + v.len))
    }

    /// The resident 4K pages in `[addr, addr + len)` (smaps, the OOM killer's log). Linux counts
    /// the pages in the process's page table:
    /// - anonymous memory is counted by host residency, large on-demand mappings only over the
    ///   spans that may have contents ([`Mm::touched_windows`]), without allocating a per-page
    ///   array for a mapping of several TB;
    /// - a borrowed page counts when the owner's host page is resident (fork lends every page of a
    ///   small mapping, touched or not);
    /// - file mappings count the pages the host has mapped (pagemap), not those in the host page
    ///   cache, which readahead fills around every page touched; by residency if pagemap cannot be
    ///   read.
    pub fn resident_in(&self, addr: u64, len: u64) -> u64 {
        let end = addr.saturating_add(len);
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        let mut total = 0;
        for (&s, v) in self.vmas.range(first..end) {
            let (from, to) = (addr.max(s), end.min(s + v.host_len()));
            if from >= to
                || v.reserved()
                || v.foreign()
                || (v.backing == Backing::Anonymous && !v.written.get())
            {
                continue;
            }
            let ranges = if v.backing == Backing::Anonymous && v.len > EAGER_MAX {
                self.touched_windows(s)
            } else {
                vec![(from, to)]
            };
            let cow = (v.backing == Backing::Anonymous).then(|| self.cow.borrow());
            for (lo, hi) in ranges {
                let (lo, hi) = (lo.max(from), hi.min(to));
                if lo >= hi {
                    continue;
                }
                if let Some(cow) = &cow {
                    // Exclude borrowed pages from our own host memory scan so they are counted
                    // only once (via `cow.borrowed` below).
                    let mut cur = lo;
                    for page in cow.borrowed.range(lo..hi).map(|(&p, _)| p).chain([hi]) {
                        if page > cur {
                            let host = Self::own_page(s, v, cur).as_ptr();
                            total += appine_hal::resident_pages(host, (page - cur) as usize) as u64;
                        }
                        cur = page + PAGE_SIZE;
                    }
                } else {
                    let (host, n) = (Self::own_page(s, v, lo).as_ptr(), (hi - lo) as usize);
                    let mapped = (v.file_id.is_some())
                        .then(|| appine_hal::touched_pages(host, n))
                        .flatten();
                    total += match mapped {
                        Some(pages) => pages.iter().filter(|&&p| p).count() as u64,
                        None => appine_hal::resident_pages(host, n) as u64,
                    };
                }
            }
        }
        // Borrowed pages, in runs of contiguous host pages
        let cow = self.cow.borrow();
        let mut run: Option<(*const u8, usize)> = None;
        for b in cow.borrowed.range(addr..end).map(|(_, b)| b.host.as_ptr()) {
            run = match run {
                Some((start, n)) if start.wrapping_add(n) == b => {
                    Some((start, n + PAGE_SIZE as usize))
                }
                Some((start, n)) => {
                    total += appine_hal::resident_pages(start, n) as u64;
                    Some((b, PAGE_SIZE as usize))
                }
                None => Some((b, PAGE_SIZE as usize)),
            };
        }
        if let Some((start, n)) = run {
            total += appine_hal::resident_pages(start, n) as u64;
        }
        total
    }

    /// Pages in `[addr, end)` shared with other address spaces (lent or borrowed for
    /// copy-on-write): the page count, and the bytes after dividing each page among the address
    /// spaces sharing it. smaps counts them as shared dirty pages and Pss as only the divided
    /// share, as Linux does by mapcount; an orphan page with only one borrower left belongs to
    /// it alone and does not count.
    pub fn cow_shared(&self, addr: u64, end: u64) -> (u64, u64) {
        let c = self.cow.borrow();
        let loans = self.loans.borrow();
        let (mut pages, mut pss) = (0, 0);
        let mut count = |key: usize| {
            let users = loans.get(&key).map_or(1, Loan::users) as u64;
            if users > 1 {
                pages += 1;
                pss += PAGE_SIZE / users;
            }
        };
        for &page in c.lent.range(addr..end) {
            if let Some((s, v)) = self.anon_vma(page) {
                count(Self::own_page(s, v, page).as_ptr() as usize);
            }
        }
        for b in c.borrowed.range(addr..end).map(|(_, b)| b) {
            count(b.host.as_ptr() as usize);
        }
        (pages, pss)
    }

    /// The `/proc/<pid>/pagemap` entries of `pages` pages from `addr`: resident (bit 63), file
    /// page or shared memory (bit 61), private anonymous page mapped only once (bit 56). Like what
    /// an unprivileged process sees on Linux, no page frame numbers are given.
    pub fn pagemap(&self, addr: u64, pages: usize) -> Vec<u64> {
        const PRESENT: u64 = 1 << 63;
        const FILE: u64 = 1 << 61;
        const EXCLUSIVE: u64 = 1 << 56;
        let mut out = vec![0u64; pages];
        let end = addr.saturating_add(pages as u64 * PAGE_SIZE);
        let first = self
            .vmas
            .range(..=addr)
            .next_back()
            .map_or(addr, |(&s, _)| s);
        for (&s, v) in self.vmas.range(first..end) {
            let from = addr.max(s);
            let to = end.min(s + v.host_len());
            if from >= to || v.reserved() {
                continue;
            }
            let bits = if v.backing == Backing::Anonymous {
                PRESENT | EXCLUSIVE
            } else {
                PRESENT | FILE
            };
            // SAFETY: [from, to) is inside this VMA
            let host = unsafe { v.host.as_ptr().add((from - s) as usize) };
            let resident = appine_hal::page_residency(host, (to - from) as usize);
            let at = ((from - addr) / PAGE_SIZE) as usize;
            for (i, r) in resident.into_iter().enumerate() {
                if r {
                    out[at + i] = bits;
                }
            }
        }
        let cow = self.cow.borrow();
        // Borrowed pages are resident, but not mapped only once
        for (&page, _) in cow.borrowed.range(addr..end) {
            out[((page - addr) / PAGE_SIZE) as usize] = PRESENT;
        }
        // Lent pages are shared with borrowers, so they are not mapped exclusively
        for &page in cow.lent.range(addr..end) {
            let slot = &mut out[((page - addr) / PAGE_SIZE) as usize];
            if *slot & PRESENT != 0 {
                *slot &= !EXCLUSIVE;
            }
        }
        out
    }

    /// Total size of the mappings (bytes).
    pub fn size(&self) -> u64 {
        self.vmas.values().map(|v| v.len).sum()
    }

    /// Allocated soft-MMU page-table bytes (`VmPTE`, OOM `pgtables`, `memory.stat` `pagetables`).
    pub fn pgtables_bytes(&self) -> u64 {
        self.mmu.table_bytes()
    }

    /// Allocated soft-MMU page tables in 4 KiB pages (Linux's `mm_pgtables_bytes(mm) / PAGE_SIZE`).
    pub fn pgtables_pages(&self) -> u64 {
        self.mmu.table_pages()
    }

    /// Exact swapped 4 KiB pages in this address space from `/proc/self/pagemap` (bit 62).
    /// Returns `None` when `/proc/self/pagemap` cannot be read (e.g. SELinux-enforced Android).
    pub fn exact_swap_pages(&self) -> Option<u64> {
        if !appine_hal::pagemap_readable() {
            return None;
        }
        let mut total = 0u64;
        for (&s, v) in &self.vmas {
            let host_len = v.host_len();
            if v.reserved() || v.foreign() || host_len == 0 {
                continue;
            }
            let swappable = match v.backing {
                Backing::Anonymous | Backing::PrivateFile => v.written.get(),
                Backing::Shared => shmem_like(v),
            };
            if !swappable {
                continue;
            }
            if v.backing == Backing::Anonymous {
                let ranges = if v.len > EAGER_MAX {
                    self.touched_windows(s)
                } else {
                    vec![(s, s + host_len)]
                };
                let cow = self.cow.borrow();
                for (lo, hi) in ranges {
                    let mut cur = lo;
                    for page in cow.borrowed.range(lo..hi).map(|(&p, _)| p).chain([hi]) {
                        if page > cur {
                            let host = Self::own_page(s, v, cur).as_ptr();
                            total += appine_hal::swapped_pages(host, (page - cur) as usize)? as u64;
                        }
                        cur = page + PAGE_SIZE;
                    }
                }
            } else {
                total += appine_hal::swapped_pages(v.host.as_ptr(), host_len as usize)? as u64;
            }
        }
        for (host, len) in borrowed_host_runs(&self.cow.borrow()) {
            total += appine_hal::swapped_pages(host, len)? as u64;
        }
        Some(total)
    }

    /// Private anonymous 4 KiB pages that currently have a soft-MMU entry (or are CoW-borrowed)
    /// and that host `mincore` reports non-resident: an upper bound on how many private anonymous
    /// pages of this address space could be swapped out when `/proc/self/pagemap` is unreadable.
    ///
    /// Unmapped pages, reserved VMAs, never-written anonymous VMAs, file-backed VMAs and
    /// `MADV_DONTNEED`-discarded pages (whose soft-MMU entries are zapped by [`Mm::discard_range`])
    /// are excluded. Untouched pages inside a 2 MiB demand-filled span or <= 1 MiB eager mapping
    /// can still appear non-resident here, so callers must bound and scale this estimate by the
    /// host process's aggregate `VmSwap`.
    pub fn swappable_nonresident_pages(&self) -> u64 {
        let mut nonresident = 0u64;
        for (&s, v) in &self.vmas {
            let host_len = v.host_len();
            if v.backing != Backing::Anonymous
                || !v.written.get()
                || v.reserved()
                || v.foreign()
                || host_len == 0
            {
                continue;
            }
            let ranges = if v.len > EAGER_MAX {
                self.touched_windows(s)
            } else {
                vec![(s, s + host_len)]
            };
            let cow = self.cow.borrow();
            for (lo, hi) in ranges {
                let mut cur = self.mmu.next_present(lo, hi);
                while cur < hi {
                    let run_start = cur;
                    while cur < hi
                        && !cow.borrowed.contains_key(&cur)
                        && self.mmu.next_present(cur, cur + PAGE_SIZE) == cur
                    {
                        cur += PAGE_SIZE;
                    }
                    if cur > run_start {
                        let host = Self::own_page(s, v, run_start).as_ptr();
                        nonresident += nonresident_pages(host, (cur - run_start) as usize);
                    }
                    if cur < hi {
                        cur = self.mmu.next_present(cur + PAGE_SIZE, hi);
                    }
                }
            }
        }
        for (host, len) in borrowed_host_runs(&self.cow.borrow()) {
            nonresident += nonresident_pages(host, len);
        }
        nonresident
    }

    /// Bytes in grows-down mappings: the main stack and `MAP_GROWSDOWN` ones (Linux's `stack_vm`,
    /// VmStk).
    pub fn stack_bytes(&self) -> u64 {
        self.vmas
            .values()
            .filter(|v| v.growsdown)
            .map(|v| v.len)
            .sum()
    }

    /// Resident 4K pages in host memory. Anonymous mappings never written are skipped: reading them
    /// only maps the zero page, and Linux's RSS does not count the zero page either.
    ///
    /// Measured once at process exit and once at execve (`ru_maxrss`), so twice for every process
    /// the shell spawns:
    /// - mappings contiguous on the host (mostly the ones execve creates one after another) are
    ///   merged into one mincore;
    /// - when a file mapping has only host page-cache pages (private mappings never written,
    ///   shared mappings), how much is resident is a property of the file, independent of which
    ///   process maps it, while mincore looks up the page cache page by page: the result is cached
    ///   per piece of file for a while ([`FileResidency`]), so the code segments of programs and
    ///   libraries need not be checked every time.
    pub fn resident_pages(&self) -> u64 {
        self.rss_plan().measure()
    }

    /// A sample for the peak resident page count (`ru_maxrss`): not measured when there is little
    /// anonymous memory of its own ([`RssPlan::estimate`]). With `fresh` (execve right after fork,
    /// the usual way a shell spawns), counts only borrowed pages and cached file mappings, without
    /// measuring its own anonymous memory, which holds only the few pages written since fork.
    pub fn peak_resident_pages(&self, fresh: bool) -> u64 {
        let plan = self.rss_plan();
        if fresh { plan.fixed } else { plan.estimate() }
    }

    /// Resident pages split as Linux's RssAnon, RssFile and RssShmem (`/proc/<pid>/status`):
    /// private anonymous memory, borrowed pages and private file mappings that have been written
    /// count as anonymous, shared anonymous memory, SysV shm and memfds as shmem, other file
    /// mappings as file. Measured the way [`Mm::resident_pages`] measures, with no mincore
    /// merging across VMAs.
    pub fn resident_split(&self) -> (u64, u64, u64) {
        let (mut anon, mut file, mut shmem) = (self.cow.borrow().borrowed.len() as u64, 0, 0);
        let now = std::time::Instant::now();
        let mincore = |host: usize, len: u64| {
            appine_hal::resident_pages(host as *const u8, len as usize) as u64
        };
        for (&s, v) in &self.vmas {
            let host_len = v.host_len();
            let pages = match (v.backing, v.file_id) {
                _ if v.foreign() || host_len == 0 => continue,
                (Backing::Anonymous, _) if !v.written.get() => continue,
                (Backing::Anonymous, _) if v.len > EAGER_MAX => self
                    .touched_windows(s)
                    .into_iter()
                    .map(|(lo, hi)| mincore(Self::own_page(s, v, lo).as_ptr() as usize, hi - lo))
                    .sum(),
                (Backing::PrivateFile, Some(id)) | (Backing::Shared, Some(id))
                    if !(v.backing == Backing::PrivateFile && v.written.get()) =>
                {
                    FileResidency::get((id.0, id.1, id.2, v.len), now, || {
                        appine_hal::resident_pages(v.host.as_ptr(), v.len as usize) as u64
                    })
                }
                _ => mincore(v.host.as_ptr() as usize, host_len),
            };
            match v.backing {
                Backing::Anonymous => anon += pages,
                Backing::PrivateFile if v.written.get() => anon += pages,
                Backing::PrivateFile => file += pages,
                Backing::Shared if shmem_like(v) => shmem += pages,
                Backing::Shared => file += pages,
            }
        }
        (anon, file, shmem)
    }

    /// What [`Mm::resident_pages`] measures: pages known without mincore, and the host ranges to
    /// mincore.
    fn rss_plan(&self) -> RssPlan {
        self.plan(None)
    }

    /// [`Mm::rss_plan`], or with `counted` the part of a [`Usage`]: file pieces in `counted`
    /// already count for another address space and are skipped (those not in it are added), and
    /// borrowed pages become spans of the owner's host pages, which the union of the spans counts
    /// once with the owner's own and other borrowers'.
    fn plan(&self, mut counted: Option<&mut std::collections::HashSet<FilePiece>>) -> RssPlan {
        let mut total = 0;
        let mut spans = Vec::with_capacity(self.vmas.len());
        let cow = self.cow.borrow();
        if counted.is_none() {
            // Borrowed pages are counted, like copy-on-write pages on Linux
            total = cow.borrowed.len() as u64;
        } else {
            // In runs of contiguous host pages
            let mut run: Option<(usize, usize)> = None;
            for b in cow.borrowed.values().map(|b| b.host.as_ptr() as usize) {
                run = match run {
                    Some((start, n)) if start + n == b => Some((start, n + PAGE_SIZE as usize)),
                    Some(r) => {
                        spans.push(r);
                        Some((b, PAGE_SIZE as usize))
                    }
                    None => Some((b, PAGE_SIZE as usize)),
                };
            }
            spans.extend(run);
        }
        drop(cow);
        let now = std::time::Instant::now();
        for (&s, v) in &self.vmas {
            let host_len = v.host_len();
            if v.foreign() || host_len == 0 {
                continue;
            }
            let page_cache = match v.backing {
                Backing::Anonymous if !v.written.get() => continue,
                Backing::Anonymous => false,
                Backing::PrivateFile => !v.written.get(),
                Backing::Shared => true,
            };
            // Large on-demand mappings are measured only over the spans that may have contents
            // (Mm::touched_windows): mincore over ASan's shadow memory of more than ten TB page
            // by page would need a result array of several GB
            if v.backing == Backing::Anonymous && v.len > EAGER_MAX {
                for (lo, hi) in self.touched_windows(s) {
                    let host = Self::own_page(s, v, lo).as_ptr() as usize;
                    spans.push((host, (hi - lo) as usize));
                }
                continue;
            }
            let span = (v.host.as_ptr() as usize, host_len as usize);
            match v.file_id {
                Some((dev, ino, offset)) if page_cache => {
                    let piece = (dev, ino, offset, v.len);
                    if counted.as_mut().is_none_or(|c| c.insert(piece)) {
                        total += FileResidency::get(piece, now, || {
                            appine_hal::resident_pages(v.host.as_ptr(), span.1) as u64
                        });
                    }
                }
                _ => spans.push(span),
            }
        }
        spans.sort_unstable();
        RssPlan {
            fixed: total,
            spans,
        }
    }

    /// The mappings a core dump writes (`crate::coredump`), one entry per VMA. How much is written
    /// follows Linux's `vma_dump_size` and `coredump_filter` (`filter`, the bits of
    /// [`dump_filter`]): the vDSO is always written whole; shared mappings depend on whether they
    /// are anonymous (including memfd and SysV shared memory) or file-backed; written private
    /// anonymous VMAs include all their pieces once they acquire an anon_vma; private file mappings that have been writable are written whole (data segments),
    /// otherwise only the first page of an ELF file, so a debugger can tell what is mapped.
    pub fn dump_regions(&self, filter: u32) -> Vec<DumpRegion> {
        use dump_filter::*;
        self.vmas
            .iter()
            .map(|(&s, v)| {
                let offset = v.file_id.map(|(_, _, off)| off);
                let mut check_elf = false;
                let size = if s == self.vdso {
                    v.len
                } else if v.dontdump || v.foreign() {
                    0
                } else {
                    match v.backing {
                        Backing::Shared => {
                            let bit = if shmem_like(v) {
                                ANON_SHARED
                            } else {
                                MAPPED_SHARED
                            };
                            if filter & bit != 0 { v.len } else { 0 }
                        }
                        Backing::Anonymous
                            if filter & ANON_PRIVATE != 0 && v.has_anon_vma.get() =>
                        {
                            v.len
                        }
                        Backing::Anonymous => 0,
                        Backing::PrivateFile
                            if filter & ANON_PRIVATE != 0
                                && (v.written.get() || v.prot & prot::WRITE != 0) =>
                        {
                            v.len
                        }
                        Backing::PrivateFile if filter & MAPPED_PRIVATE != 0 => v.len,
                        Backing::PrivateFile
                            if filter & ELF_HEADERS != 0
                                && offset == Some(0)
                                && v.prot & prot::READ != 0
                                && (v.contents_len() >= PAGE_SIZE
                                    || v.fill.as_ref().is_some_and(|f| f.size_stale.get())) =>
                        {
                            check_elf = true;
                            PAGE_SIZE
                        }
                        Backing::PrivateFile => 0,
                    }
                };
                DumpRegion {
                    start: s,
                    end: s + v.len,
                    prot: v.prot,
                    size,
                    check_elf,
                    sparse: v.backing != Backing::PrivateFile && v.fill.is_none(),
                    file: offset
                        .map(|off| (off, v.name.clone().unwrap_or_else(|| Rc::from(&b""[..])))),
                }
            })
            .collect()
    }

    /// Reads one page for a core dump (Linux's `get_dump_page`) without checking permissions:
    /// `PROT_NONE` pages are not in the page table, so host memory is read by VMA. Pages borrowed
    /// for copy-on-write read the owner's through the page table. Pages past the end of the file
    /// (the host raises SIGBUS as soon as they are touched) and unreadable pages return false and
    /// leave holes in the core file.
    pub fn dump_page(&self, addr: u64, buf: &mut [u8]) -> bool {
        let Some((&s, v)) = self
            .vmas
            .range(..=addr)
            .next_back()
            .filter(|&(&s, v)| addr < s + v.contents_len().min(v.len))
        else {
            return false;
        };
        let n = buf.len().min((s + v.contents_len() - addr) as usize);
        let host = if self
            .cow
            .borrow()
            .borrowed
            .contains_key(&(addr & !(PAGE_SIZE - 1)))
        {
            match self.mmu.translate(addr, prot::READ) {
                Some(host) => host.as_ptr(),
                None => return false,
            }
        } else {
            // SAFETY: addr is in the part of this VMA with file contents, and it holds the host
            // memory
            unsafe { v.host.as_ptr().add((addr - s) as usize) }
        };
        // SAFETY: [host, host + n) does not cross this page
        unsafe { std::ptr::copy_nonoverlapping(host, buf.as_mut_ptr(), n) };
        buf[n..].fill(0);
        true
    }

    /// Test hook ([`crate::bug`]): points the page of `addr` at an inaccessible host page in the
    /// page table, so a guest access makes the engine fault on the host. That host page belongs to
    /// no VMA and is leaked on purpose.
    #[cfg(any(debug_assertions, feature = "test-hooks"))]
    pub fn break_page(&mut self, addr: u64) -> Result<(), Errno> {
        let host = appine_hal::map_inaccessible(PAGE_SIZE as usize).map_err(Errno)?;
        let page = addr & !(PAGE_SIZE - 1);
        // SAFETY: accessing this host page is exactly the bug being simulated; it is never freed
        unsafe {
            self.mmu
                .map(page, host, PAGE_SIZE, prot::READ | prot::WRITE)
        }
        .map_err(map_err)
    }

    // ---- VMAs, host backing and page-table population ----

    /// Whether `[start, start + len)` is entirely free.
    fn is_free(&self, start: u64, len: u64) -> bool {
        // The last VMA starting before the end of the range must not reach into the range
        self.vmas
            .range(..start + len)
            .next_back()
            .is_none_or(|(&s, v)| s + v.len <= start)
    }

    /// Whether an mmap hint can be used as it is: the range is free, below the top of the mmap area,
    /// and clear of the guard gap below a grows-down mapping above it (Linux's `vm_start_gap`).
    fn hint_fits(&self, hint: u64, len: u64) -> bool {
        let Some(end) = hint.checked_add(len).filter(|&e| e <= self.mmap_top) else {
            return false;
        };
        self.is_free(hint, len)
            && self
                .vmas
                .range(end..)
                .next()
                .is_none_or(|(&s, v)| !v.growsdown || s - end >= STACK_GUARD_GAP)
    }

    /// Finds a free range of length `len`, top down, leaving the guard gap below grows-down
    /// mappings free as Linux's `vm_unmapped_area` does. Mappings of at least one 2 MiB leaf span
    /// are 2 MiB-aligned when space permits (like Linux's THP alignment) so their interior and head
    /// pages form L2 superpages in the soft-MMU.
    pub fn find_free(&self, len: u64) -> Option<u64> {
        let search = |align: u64| -> Option<u64> {
            let mask = align - 1;
            let mut top = self.mmap_top;
            for (&s, v) in self.vmas.range(..self.mmap_top).rev() {
                let end = s + v.len;
                if end <= top && top - end >= len {
                    let cand = (top - len) & !mask;
                    if cand >= end {
                        return Some(cand);
                    }
                }
                let low = if v.growsdown {
                    s.saturating_sub(STACK_GUARD_GAP)
                } else {
                    s
                };
                top = top.min(low);
            }
            if top >= mmap_min().saturating_add(len) {
                let cand = (top - len) & !mask;
                if cand >= mmap_min() {
                    return Some(cand);
                }
            }
            None
        };
        if len >= LEAF_SPAN
            && let Some(addr) = search(LEAF_SPAN)
        {
            return Some(addr);
        }
        search(PAGE_SIZE)
    }

    /// Host memory for a new private anonymous mapping: a `PROT_NONE` one is only a reservation
    /// and takes no host address space ([`HostRegion::reserved`]); the rest as
    /// [`Mm::new_anonymous`].
    fn private_anonymous(
        len: u64,
        prot: u32,
        reserve: bool,
    ) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        if mmu_prot(prot) == 0 {
            let region = HostRegion::reserved();
            let host = region.base;
            return Ok((region, host));
        }
        Self::new_anonymous(len, reserve)
    }

    /// Gives reserved VMA `start` ([`HostRegion::reserved`]) its own host memory (all zero), after
    /// which it behaves like an ordinary private anonymous mapping. It has no entries, so the page
    /// table needs no change. Reservations are often hundreds of GB, so the caller first splits off
    /// the piece it needs. `reserve` is whether it is counted in the host commit
    /// ([`Mm::new_anonymous`]).
    fn back_reserved(&mut self, start: u64, reserve: bool) -> Result<(), Errno> {
        let v = &self.vmas[&start];
        if !v.reserved() {
            return Ok(());
        }
        let (region, host) = Self::new_anonymous(v.len, reserve)?;
        let v = self.vmas.get_mut(&start).unwrap();
        v.region = region;
        v.host = host;
        Ok(())
    }

    /// Recreate a private file view, copying only pages already detached from the backing file.
    fn copy_private_file(v: &Vma) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        use std::os::fd::AsRawFd;
        if v.fill.is_some() {
            return Self::fill_copy(v);
        }
        if v.snapshot {
            let (region, host) =
                Self::new_anonymous(v.len, v.prot & prot::WRITE != 0 && !v.noreserve)?;
            // SAFETY: the snapshot cannot shrink and the new mapping covers its whole extent.
            unsafe {
                copy_nonzero_pages(v.host.as_ptr(), host.as_ptr(), v.file_len as usize, None)
            };
            return Ok((region, host));
        }
        let (fd, offset) = v.file.as_ref().ok_or(Errno::EFAULT)?;
        let raw = fd.as_raw_fd();
        let mapped =
            appine_hal::map_file(raw, *offset, v.len as usize, false, true).map_err(Errno)?;
        let region = HostRegion::file(mapped.base, mapped.len);
        let len = v.file_len.min(file_extent(raw, *offset, v.len));
        let copy = |delta: u64| {
            // SAFETY: both views cover this page before rounded EOF, and the destination is private.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    v.host.as_ptr().add(delta as usize),
                    mapped.ptr.as_ptr().add(delta as usize),
                    PAGE_SIZE as usize,
                )
            };
        };
        if let Some(pages) = &v.pages {
            let grain = pages.page_size();
            let end = *offset + len;
            for &at in pages.copied.borrow().range(pages.page_start(*offset)..end) {
                for page in (at.max(*offset)..(at + grain).min(end)).step_by(PAGE_SIZE as usize) {
                    copy(page - offset);
                }
            }
        } else if v.written.get() {
            for start in (0..len).step_by(WINDOW_MAX as usize) {
                let size = (len - start).min(WINDOW_MAX) as usize;
                let pages =
                    appine_hal::private_pages(v.host.as_ptr().wrapping_add(start as usize), size)
                        .ok_or(Errno::EIO)?;
                for (index, private) in pages.into_iter().enumerate() {
                    if private {
                        copy(start + index as u64 * PAGE_SIZE);
                    }
                }
            }
        }
        Ok((region, mapped.ptr))
    }

    /// Gives a private file mapping that shares host memory with other address spaces a copy of
    /// its own.
    fn unshare(&mut self, start: u64) -> Result<(), Errno> {
        let v = &self.vmas[&start];
        let (region, host) = Self::copy_private_file(v)?;
        // The old entries point at the shared piece, so remove them first (map_pages leaves
        // existing entries alone); pages past the end of the file still stay out of the page
        // table
        let (eager, p) = (v.eager_len(), v.prefill_prot());
        self.mmu.unmap(start, v.len).map_err(map_err)?;
        Self::map_pages(&mut self.mmu, start, host, eager, p, true)?;
        let v = self.vmas.get_mut(&start).unwrap();
        let old = std::mem::replace(&mut v.region, region);
        v.pages = v.pages.as_ref().map(|p| p.detached(v.offset(), v.len));
        v.host = host;
        v.cow = false;
        // Other threads' TLBs may still hold stale translations: release only after the shootdown
        self.graveyard.push(old);
        self.dirty = true;
        Ok(())
    }

    /// New anonymous host memory. Host memory is always readable and writable (the page table
    /// carries the guest permissions), so the caller decides `reserve` by Linux's commit rules:
    /// only writable private mappings are accounted, while `MAP_NORESERVE`, read-only and
    /// `PROT_NONE` ones are not. V8 reserves 8 GB of `PROT_NONE` for every wasm memory, which
    /// would fail outright on hosts with little memory if it were accounted.
    fn new_anonymous(len: u64, reserve: bool) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        Self::new_anonymous_with(len, reserve, true)
    }

    /// Like [`Mm::new_anonymous`] with `MAP_NORESERVE`, for oversized address-space reservations
    /// (stacks, heap) that only map a small slice up front: starts with an empty used range so
    /// [`recycled::put`] discards only the slice ever mapped or grown into.
    fn new_anonymous_reserved(len: u64) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        Self::new_anonymous_with(len, false, false)
    }

    fn new_anonymous_with(
        len: u64,
        reserve: bool,
        full: bool,
    ) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        let host_len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
        let base = match recycled::take(host_len, reserve) {
            Some(base) => base,
            None => appine_hal::map_anonymous(host_len, reserve).map_err(|_| Errno::ENOMEM)?,
        };
        Ok((HostRegion::anonymous(base, host_len, reserve, full), base))
    }

    /// Maps a piece of host memory at `[start, start + len)`; the caller guarantees the range is
    /// free. For file mappings `file_len` is the number of bytes before the end of the file
    /// ([`Vma::file_len`]), and only that part gets entries: when a small file is mapped
    /// executable over a large range, the page table is only as large as the file.
    #[allow(clippy::too_many_arguments)]
    fn insert(
        &mut self,
        start: u64,
        len: u64,
        file_len: u64,
        prot: u32,
        backing: Backing,
        may_write: bool,
        region: Arc<HostRegion>,
        host: NonNull<u8>,
    ) -> Result<(), Errno> {
        let vma = self.new_vma(start, len, file_len, prot, backing, may_write, region, host);
        self.insert_vma(start, vma)
    }

    #[allow(clippy::too_many_arguments)]
    fn new_vma(
        &self,
        start: u64,
        len: u64,
        file_len: u64,
        prot: u32,
        backing: Backing,
        may_write: bool,
        region: Arc<HostRegion>,
        host: NonNull<u8>,
    ) -> Vma {
        Vma {
            len,
            prot,
            backing,
            may_write,
            may_exec: true,
            region,
            name: None,
            ino: 0,
            mnt: None,
            host,
            file_len,
            cow: false,
            interp_open: None,
            file_id: None,
            content: None,
            file: None,
            shm: None,
            locked: self.lock_future,
            written: Cell::new(backing != Backing::Anonymous && prot & prot::WRITE != 0),
            growsdown: false,
            dontdump: false,
            wipeonfork: false,
            dontfork: false,
            noreserve: false,
            anon: 0,
            accounted: backing != Backing::Shared && prot & prot::WRITE != 0,
            anon_pgoff: start / PAGE_SIZE,
            has_anon_vma: Cell::new(false),
            fill: None,
            pages: None,
            snapshot: false,
        }
    }

    /// Puts a whole VMA at `start`; the caller guarantees the range is free.
    fn insert_vma(&mut self, start: u64, v: Vma) -> Result<(), Errno> {
        self.room_for(1)?;
        let end = start + v.len;
        self.install_vma(start, v)?;
        self.join_anon_vmas_at(start);
        self.join_anon_vmas_at(end);
        Ok(())
    }

    /// Install a mapping after its VMA slot has been checked.
    fn install_vma(&mut self, start: u64, v: Vma) -> Result<(), Errno> {
        let shared_writable = v.backing == Backing::Shared && v.may_write;
        // Publish writable shared ranges before installing PTEs so concurrent threads on the
        // no-BKL futex fast path never observe a writable PTE before `shared_maps` sees it.
        let prev_shared_len = if shared_writable {
            let mut ranges = self
                .shared_maps
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let prev = ranges.len();
            ranges.push((start, start + v.len));
            Some(prev)
        } else {
            None
        };
        v.region.note_used(v.host, v.file_len as usize);
        let file = v.backing != Backing::Anonymous;
        if let Err(e) = Self::map_pages(
            &mut self.mmu,
            start,
            v.host,
            v.eager_len(),
            v.prefill_prot(),
            file,
        ) {
            // Retain the backing until sync has flushed translations of any partial fill.
            if v.prot & prot::EXEC != 0 {
                self.code_ranges.push((start, v.len));
                self.exec_changed = true;
            }
            self.graveyard.push(v.region);
            self.dirty = true;
            if let Some(prev) = prev_shared_len {
                self.shootdown();
                // `map_pages` already unmapped any partial PTEs; roll back the tentative range.
                self.shared_maps
                    .write()
                    .unwrap_or_else(PoisonError::into_inner)
                    .truncate(prev);
            }
            return Err(e);
        }
        self.exec_changed |= v.prot & prot::EXEC != 0;
        self.vmas.insert(start, v);
        Ok(())
    }

    /// [`Mm::insert_vma`] without the `vm.max_map_count` check, for a VMA whose entries were
    /// already moved by [`Mmu::move_entries`]: best-effort prefill so an allocation failure never
    /// drops the moved VMA or its existing entries.
    fn place_moved_vma(&mut self, start: u64, v: Vma) {
        v.region.note_used(v.host, v.file_len as usize);
        let file = v.backing != Backing::Anonymous;
        Self::prefill_pages(
            &mut self.mmu,
            start,
            v.host,
            v.eager_len(),
            v.prefill_prot(),
            file,
        );
        self.exec_changed |= v.prot & prot::EXEC != 0;
        let end = start + v.len;
        self.vmas.insert(start, v);
        self.join_anon_vmas_at(start);
        self.join_anon_vmas_at(end);
    }

    /// The range check of msync(2): the range must be fully mapped.
    pub fn check_mapped(&self, addr: u64, len: u64) -> Result<(), Errno> {
        let end = page_up(len)
            .and_then(|l| addr.checked_add(l))
            .ok_or(Errno::ENOMEM)?;
        let mut cursor = addr;
        while cursor < end {
            let (&s, v) = self
                .vmas
                .range(..=cursor)
                .next_back()
                .filter(|&(&s, v)| s + v.len > cursor)
                .ok_or(Errno::ENOMEM)?;
            cursor = s + v.len;
        }
        Ok(())
    }

    /// How many more VMAs splitting at these addresses makes.
    fn splits(&self, addrs: &[u64]) -> usize {
        addrs
            .iter()
            .filter(|&&a| {
                self.vmas
                    .range(..a)
                    .next_back()
                    .is_some_and(|(&s, v)| s + v.len > a)
            })
            .count()
    }

    /// Splits the VMA that spans `addr` into two at `addr`.
    fn split_at(&mut self, addr: u64) {
        let Some((&s, v)) = self.vmas.range(..addr).next_back() else {
            return;
        };
        if s + v.len <= addr {
            return;
        }
        let mut tail = v.clone();
        let head_len = addr - s;
        tail.len -= head_len;
        tail.anon_pgoff = v.anon_pgoff_at(head_len);
        tail.file_len = v.file_len.saturating_sub(head_len);
        if let Some(f) = &mut tail.file_id {
            f.2 += head_len;
        }
        if let Some(f) = &mut tail.file {
            f.1 += head_len;
        }
        // Reservations and shared anonymous tails can have offsets beyond the host region.
        tail.host = NonNull::new(tail.host.as_ptr().wrapping_add(head_len as usize)).unwrap();
        let head = self.vmas.get_mut(&s).unwrap();
        if let Some(pages) = &head.pages
            && pages.tmpfs.is_some()
        {
            let upper = pages.copied.borrow_mut().split_off(&tail.offset());
            tail.pages = Some(FilePages::new(pages.tmpfs.clone(), upper));
        }
        head.len = head_len;
        head.file_len = head.file_len.min(head_len);
        self.vmas.insert(addr, tail);
    }

    /// Whether there is room for `more` more VMAs (`vm.max_map_count`).
    fn room_for(&self, more: usize) -> Result<(), Errno> {
        if self.vmas.len() + more > MAX_MAP_COUNT.load(Ordering::Relaxed) {
            return Err(Errno::ENOMEM);
        }
        Ok(())
    }

    /// Puts part of a VMA into the page table: builds entries for the VMA's own host memory
    /// `[host, host + len)` at `[start, start + len)`, leaving existing entries alone (those
    /// changed by copy-on-write, or kept by mprotect with permission 0). `PROT_NONE` gets none:
    /// writing entries page by page for the large address ranges V8 and the JVM reserve takes a
    /// lot of memory (16 MB for 8 GB), so they are added when mprotect grants permissions
    /// ([`Mm::mprotect`]). Neither does anything over [`EAGER_MAX`], which is filled on demand at
    /// access ([`Mm::fault_in`]), except executable mappings that are not private anonymous
    /// (`file`: file mappings, shared anonymous memory, SysV shm), which are built anyway: when
    /// translations are shared, guest instruction words are checked against the page table (the
    /// DBT's recheck), and blocks without entries must be parked and restored page by page on
    /// first execution. For a file mapping their size is bounded by the file size.
    fn fill_eager(
        mmu: &mut Mmu,
        start: u64,
        host: NonNull<u8>,
        len: u64,
        prot: u32,
        file: bool,
    ) -> Result<(), appine_engine::MapError> {
        if mmu_prot(prot) == 0 || len == 0 {
            return Ok(());
        }
        if len > EAGER_MAX && !(file && prot & prot::EXEC != 0) {
            return Ok(());
        }
        // SAFETY: the VMA holds the host memory, which lives at least as long as the mapping in
        // the page table
        unsafe { mmu.fill_shared(start, host, len, mmu_prot(prot)) }
    }

    fn map_pages(
        mmu: &mut Mmu,
        start: u64,
        host: NonNull<u8>,
        len: u64,
        prot: u32,
        file: bool,
    ) -> Result<(), Errno> {
        if let Err(e) = Self::fill_eager(mmu, start, host, len, prot, file) {
            let _ = mmu.unmap(start, len);
            return Err(map_err(e));
        }
        Ok(())
    }

    /// Best-effort eager entry fill for a VMA that already exists or already had its entries moved:
    /// leaves existing entries (such as prot-0 entries holding contents) intact on allocation
    /// failure, letting any unfilled pages fault in on demand ([`Mm::fault_in`]).
    fn prefill_pages(
        mmu: &mut Mmu,
        start: u64,
        host: NonNull<u8>,
        len: u64,
        prot: u32,
        file: bool,
    ) {
        let _ = Self::fill_eager(mmu, start, host, len, prot, file);
    }

    /// The ranges (guest addresses) of private anonymous VMA `start` that may have contents and may
    /// be resident, sorted by address, each at most [`WINDOW_MAX`]: fork's lending
    /// ([`Mm::lend`]) and resident-memory measurement look only at these, so a mapping of several
    /// TB with only a few pages touched need not be checked page by page.
    ///
    /// It rests on this rule: every page of private anonymous memory with contents has an entry.
    /// Guest accesses and kernel-layer reads and writes through the page table fill the entries
    /// first ([`Mm::fault_in`]); the kernel layer writing host memory directly
    /// ([`Mm::write_kernel`]) or populating it ([`Mm::populate`]) fills them too; mprotect to
    /// `PROT_NONE` keeps the entries with permissions cleared; mremap moves the entries along
    /// ([`Mm::move_range`]). Copy-on-write pages count as well (borrowed pages in a `PROT_NONE`
    /// VMA have no entries). So the result is the runs of leaf tables (2 MB) that have entries.
    fn touched_windows(&self, start: u64) -> Vec<(u64, u64)> {
        let v = &self.vmas[&start];
        let end = start + v.len;
        let cow = self.cow.borrow();
        let mut lent = cow.lent.range(start..end).copied().peekable();
        let mut borrowed = cow.borrowed.range(start..end).map(|(&p, _)| p).peekable();
        // The next page to look at: the earliest that has an entry or is copy-on-write
        let mut next = |from: u64| {
            while lent.next_if(|&p| p < from).is_some() {}
            while borrowed.next_if(|&p| p < from).is_some() {}
            let pte = self.mmu.next_present(from, end);
            pte.min(lent.peek().copied().unwrap_or(end))
                .min(borrowed.peek().copied().unwrap_or(end))
        };
        let mut out: Vec<(u64, u64)> = Vec::new();
        let mut at = start;
        while at < end {
            let page = next(at);
            if page >= end {
                break;
            }
            let lo = (page & !(LEAF_SPAN - 1)).max(start);
            let hi = ((page | (LEAF_SPAN - 1)) + 1).min(end);
            match out.last_mut() {
                Some((s, e)) if *e == lo && hi - *s <= WINDOW_MAX => *e = hi,
                _ => out.push((lo, hi)),
            }
            at = hi;
        }
        out
    }
}

impl Default for Mm {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Mm {
    fn drop(&mut self) {
        if let Some(group) = self.code_group.take() {
            let remaining = group.members.get() - 1;
            group.members.set(remaining);
            group.claims.borrow_mut().retain(|c| c.0 != self.code_tag);
            // Record the group's registered file sources only when the last member drops and the
            // shared DbtSpace returns to the pool, so an exiting member never clobbers the space's
            // sources for surviving members or drops ranges registered by other members.
            if remaining == 0 {
                group.space.set_sources(&group.file_sources());
            }
        } else if let Some(cs) = &self.code_space {
            cs.space.set_sources(&self.code_sources());
        }
        self.release_cow();
        // SAFETY: self.mmu is not used afterwards
        let mmu = unsafe { ManuallyDrop::take(&mut self.mmu) };
        // While holding the BKL, release it after the BKL is released (release_unmapped)
        if let Some(mmu) = UNMAPPED.with_borrow_mut(|u| match u {
            Some(u) => {
                u.mmus.push(mmu);
                None
            }
            None => Some(mmu),
        }) {
            drop(mmu);
        }
    }
}

impl Mm {
    /// When the address space is destroyed: returns borrowed pages and leaves lent pages with the
    /// borrowers.
    fn release_cow(&mut self) {
        let cow = std::mem::take(self.cow.get_mut());
        // No thread uses this address space any more (exit, execve), so no TLB flush is needed
        // before returning borrowed pages
        self.return_loans(
            cow.borrowed.into_iter().map(|(page, b)| (page, b.host)),
            true,
        );
        if cow.lent.is_empty() {
            return;
        }
        // Lent pages become orphans
        {
            let mut loans = self.loans.borrow_mut();
            for &page in &cow.lent {
                if let Some((s, v)) = self.anon_vma(page)
                    && let Some(loan) =
                        loans.get_mut(&(Self::own_page(s, v, page).as_ptr() as usize))
                {
                    loan.owner = None;
                }
            }
        }
        self.discard_unlent(&cow.lent);
    }
}

// ---- Consistency and code (the kernel/mmu map) ----

/// Ranges invalidated in the last few code generations.
#[derive(Default)]
pub struct CodeLog {
    /// (code generation, start, length), in increasing generation order.
    entries: VecDeque<(u64, u64, u64)>,
}

impl CodeLog {
    /// Number of generations kept; threads further behind flush the whole translation cache. The
    /// JVM issues `ic ivau` over a run of cache lines for every compiled method it installs, and
    /// with only 64 kept, GC and compiler threads waking from a short sleep almost always had to
    /// flush everything: a Maven build flushed 2400 times and used 30% more user CPU time.
    const GENERATIONS: u64 = 4096;

    fn push(&mut self, generation: u64, ranges: &[(u64, u64)]) {
        self.entries
            .extend(ranges.iter().map(|&(start, len)| (generation, start, len)));
        while self
            .entries
            .front()
            .is_some_and(|e| e.0 + Self::GENERATIONS <= generation)
        {
            self.entries.pop_front();
        }
    }

    /// Ranges invalidated after generation `seen` up to `now`; None when the log no longer covers
    /// them.
    pub fn since(&self, seen: u64, now: u64) -> Option<Vec<(u64, u64)>> {
        if self.entries.front().is_none_or(|e| e.0 > seen + 1) {
            return None;
        }
        // Generations increase: binary-search the start and look only at the entries missed (the
        // whole log has tens of thousands of entries under the JVM)
        let first = self.entries.partition_point(|e| e.0 <= seen);
        Some(
            self.entries
                .range(first..)
                .take_while(|e| e.0 <= now)
                .map(|e| (e.1, e.2))
                .collect(),
        )
    }
}

/// Generations users check before re-entering guest code ([`Mm::sync`]).
pub struct Generations {
    /// TLB shootdown generation.
    pub tlb: Arc<AtomicU64>,
    /// Code generation: when it changes, Tier 1 translations are invalidated according to `log`.
    pub code: Arc<AtomicU64>,
    /// Ranges invalidated in each code generation.
    pub log: Arc<Mutex<CodeLog>>,
    /// The Tier 1 translations were replaced (the address space left its shared group,
    /// [`CodeGroup`]): users switch to the new ones before re-entering guest code.
    pub space: Arc<AtomicU64>,
}

/// An address space's Tier 1 translations, shared by the threads of that address space
/// ([`Mm::code_space`]).
pub struct CodeSpace {
    pub space: Arc<appine_engine::DbtSpace>,
    /// This address space's tag in its translation-sharing group ([`CodeGroup`]); 0 outside a
    /// group.
    pub tag: u16,
    /// The code generation up to which the code-change log has been applied: the first thread to
    /// see a new generation invalidates once for all.
    pub seen: Mutex<u64>,
}

/// Tier 1 translations shared by several address spaces of the same program
/// ([`Mm::code_space`]). With one set per process, four cc1 compiling in parallel took 35–40 MB of
/// code cache each, and 20 idle python3 processes 4 MB each.
///
/// A translation depends only on the pc and the instruction words, so when several address spaces
/// map the same code at the same addresses, the blocks are valid for all of them. A member's
/// trusted executable mappings (private file mappings never written that have a version, and the
/// vDSO) must agree with what the group has registered: one address range can only be the same
/// piece of the same version of a file (Appine has no ASLR, so processes of the same program map
/// at the same addresses). Blocks in registered mappings are shared by all members; other
/// executable memory (JIT output, code that was written) is private to a member: the engine keeps
/// blocks there apart by member tag ([`appine_engine::DbtSpace::share`]), private ranges may not
/// overlap registered ones, and registered ones may not overlap ranges private to other members
/// ([`CodeGroup::admit`]). Each node process has its own JIT code, while V8's interpreter, its
/// builtins and ICU, which live in the node program file, are still shared. The check runs after
/// every syscall ([`Mm::sync`]): a member that no longer fits leaves the group and switches to
/// translations of its own; when it is the only member left the group is closed and it keeps the
/// existing translations. So no other member ever runs a block valid only for it. A member that
/// unmaps its own mappings invalidates as usual, and other members only have to translate again.
///
/// Accessed only while holding the BKL.
pub struct CodeGroup {
    /// The program (the executable's inode, the same as the pool key).
    key: u64,
    space: Arc<appine_engine::DbtSpace>,
    members: Cell<usize>,
    /// Executable mappings members have mapped; one identity is registered per address range
    /// ([`CodeGroup::extend`]).
    ranges: RefCell<Vec<appine_engine::DbtSource>>,
    /// Executable memory private to a member, `(tag, start, end)` ([`CodeGroup::admit`]).
    claims: RefCell<Vec<(u16, u64, u64)>>,
    /// Known libc memop entry PCs inside `ranges` published to `space`.
    memops: RefCell<Vec<appine_engine::DbtMemop>>,
    /// No longer accepts new members.
    closed: Cell<bool>,
    /// Has had more than one member: blocks outside the registered ranges have been invalidated.
    shared: Cell<bool>,
}

impl CodeGroup {
    /// The most mappings registered (python's extension modules take one each).
    const MAX_RANGES: usize = 256;

    /// Sentinel [`appine_engine::DbtSource::id`] for an unmodified vDSO mapping.
    const VDSO_ID: [u64; 5] = [u64::MAX; 5];

    /// All executable mappings of member `tag`: the trusted `layout` and the private `private`
    /// ([`Mm::exec_split`]). layout must agree with what is registered ([`CodeGroup::extend`])
    /// and not overlap ranges private to other members, and private must not overlap registered
    /// ranges: if so, registers layout, installs this member's private ranges and returns true;
    /// otherwise changes nothing.
    fn admit(&self, tag: u16, layout: &[appine_engine::DbtSource], private: &[(u64, u64)]) -> bool {
        let overlap = |start: u64, end: u64, s: u64, e: u64| start < e && s < end;
        let ranges = self.ranges.borrow();
        if private.iter().any(|&(s, e)| {
            ranges
                .iter()
                .any(|r| overlap(r.start, r.start + r.len, s, e))
        }) {
            return false;
        }
        let before = ranges.len();
        drop(ranges);
        let mut claims = self.claims.borrow_mut();
        if layout.iter().any(|l| {
            claims
                .iter()
                .any(|&(t, s, e)| t != tag && overlap(l.start, l.start + l.len, s, e))
        }) || !self.extend(layout)
        {
            return false;
        }
        claims.retain(|c| c.0 != tag);
        claims.extend(private.iter().map(|&(s, e)| (tag, s, e)));
        let ranges = self.ranges.borrow();
        if ranges.len() != before {
            self.space.share(&ranges);
        }
        true
    }

    /// Registers `layout` (all of an address space's executable mappings): returns false and
    /// changes nothing if it conflicts with what is registered or does not fit. Two overlapping
    /// pieces agree when they are the same version of the same file with the same address minus
    /// file offset: the dynamic linker first maps the span of the whole file and then maps the
    /// later segments over it, so a library's executable mappings come long first, then short.
    fn extend(&self, layout: &[appine_engine::DbtSource]) -> bool {
        let mut ranges = self.ranges.borrow_mut();
        let mut new = Vec::new();
        for s in layout {
            let mut covered = false;
            for r in ranges.iter() {
                if r.start < s.start + s.len && s.start < r.start + r.len {
                    if !Self::same_file(r, s) {
                        return false;
                    }
                    covered |= r.start <= s.start && s.start + s.len <= r.start + r.len;
                }
            }
            if !covered {
                new.push(*s);
            }
        }
        if ranges.len() + new.len() > Self::MAX_RANGES {
            return false;
        }
        ranges.extend(new);
        true
    }

    /// The mappings in `layout` that agree with what is registered (every overlapping registration
    /// is the same piece of file): the group's blocks there are valid for this address space.
    fn consistent(&self, layout: &[appine_engine::DbtSource]) -> Vec<appine_engine::DbtSource> {
        let ranges = self.ranges.borrow();
        layout
            .iter()
            .filter(|s| {
                ranges.iter().all(|r| {
                    !(r.start < s.start + s.len && s.start < r.start + r.len)
                        || Self::same_file(r, s)
                })
            })
            .copied()
            .collect()
    }

    /// Two overlapping trusted mappings are the same version of the same file with the same
    /// address minus file offset.
    fn same_file(r: &appine_engine::DbtSource, s: &appine_engine::DbtSource) -> bool {
        let (ri, si) = (r.id, s.id);
        (ri[0], ri[1], ri[3], ri[4]) == (si[0], si[1], si[3], si[4])
            && r.start.wrapping_sub(ri[2]) == s.start.wrapping_sub(si[2])
    }

    /// File-backed registered sources to record on `space` when the last member drops and the
    /// translation space returns to the pool (excludes [`Self::VDSO_ID`], which
    /// [`Mm::code_sources`] never emits).
    fn file_sources(&self) -> Vec<appine_engine::DbtSource> {
        self.ranges
            .borrow()
            .iter()
            .filter(|r| r.id != Self::VDSO_ID)
            .take(appine_engine::DbtSpace::SOURCES)
            .copied()
            .collect()
    }
}

/// The groups ([`CodeGroup`]) that can be joined, kept in Kernel.
pub type CodeGroups = RefCell<Vec<Weak<CodeGroup>>>;

// ---- Copy-on-write ----

/// A handle to an address space ([`Mm::into_shared`]): during copy-on-write the address spaces of
/// one fork family find each other through it.
type MmRef = Weak<RefCell<Mm>>;

/// A lent host page.
struct Loan {
    /// The owner and the page's guest address there; None after the owner's address space is
    /// destroyed (an orphan page).
    owner: Option<(MmRef, u64)>,
    /// The borrowers and the page's guest address in each. There is usually only one (the forked
    /// child), stored without a separate allocation: a big process's fork makes a record for every
    /// page.
    first: Option<(MmRef, u64)>,
    others: Vec<(MmRef, u64)>,
}

impl Loan {
    fn new(owner: Option<(MmRef, u64)>, borrower: (MmRef, u64)) -> Loan {
        Loan {
            owner,
            first: Some(borrower),
            others: Vec::new(),
        }
    }

    fn lend(&mut self, borrower: (MmRef, u64)) {
        match self.first {
            None => self.first = Some(borrower),
            Some(_) => self.others.push(borrower),
        }
    }

    /// Removes borrower `mm` (where the page is at `page`); returns whether other borrowers remain.
    fn give_back(&mut self, mm: &MmRef, page: u64) -> bool {
        let it = |(m, a): &(MmRef, u64)| *a == page && m.ptr_eq(mm);
        if self.first.as_ref().is_some_and(it) {
            self.first = self.others.pop();
        } else {
            self.others.retain(|b| !it(b));
        }
        self.first.is_some()
    }

    fn retain_borrowers(&mut self, mut keep: impl FnMut(&(MmRef, u64)) -> bool) {
        self.first = self.first.take().filter(&mut keep);
        self.others.retain(keep);
        if self.first.is_none() {
            self.first = self.others.pop();
        }
    }

    /// Number of address spaces mapping this page (Linux's mapcount): the owner (if still there)
    /// and the borrowers.
    fn users(&self) -> usize {
        usize::from(self.owner.is_some()) + usize::from(self.first.is_some()) + self.others.len()
    }
}

/// Hash of host page addresses: dropping the low bits of a page-aligned address and multiplying
/// by an odd constant spreads them well enough. The default SipHash took over 10% of a big
/// process's fork.
#[derive(Default, Clone, Copy)]
struct PageHasher(u64);

impl std::hash::Hasher for PageHasher {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.0 = (self.0.rotate_left(8) ^ u64::from(b)).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
    }

    fn write_usize(&mut self, n: usize) {
        self.0 = (n as u64 >> 12).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }

    fn finish(&self) -> u64 {
        self.0
    }
}

/// The loan records shared by one fork family, keyed by host page address.
type Loans = Rc<RefCell<HashMap<usize, Loan, std::hash::BuildHasherDefault<PageHasher>>>>;

/// A contiguous run in the page table: the start of its VMA, the guest address, the host address
/// and the length. Pages are joined into runs before their entries are changed page by page. Runs
/// never cross VMAs: the VMAs an mprotect split off, or the host memory of two adjacent mmaps, may
/// be contiguous while their permissions differ.
#[derive(Default)]
struct Runs {
    runs: Vec<(u64, u64, NonNull<u8>, u64)>,
}

impl Runs {
    fn push(&mut self, vma: u64, page: u64, host: NonNull<u8>) {
        if let Some((v, g, h, len)) = self.runs.last_mut()
            && *v == vma
            && *g + *len == page
            && h.as_ptr().wrapping_add(*len as usize) == host.as_ptr()
        {
            *len += PAGE_SIZE;
            return;
        }
        self.runs.push((vma, page, host, PAGE_SIZE));
    }
}

/// A borrowed page.
struct Borrowed {
    host: NonNull<u8>,
    /// Holds that host memory, so it is not released when the owner unmaps it or is destroyed.
    region: Arc<HostRegion>,
}

/// The copy-on-write pages of an address space (guest addresses). Only in private anonymous
/// mappings.
#[derive(Default)]
struct Cow {
    /// Lent pages: their entries have no write permission.
    lent: BTreeSet<u64>,
    /// Borrowed pages: their entries point at the owner's host page, without write permission.
    borrowed: BTreeMap<u64, Borrowed>,
}

#[cfg(test)]
thread_local! {
    /// One-based countdown to a single simulated page-table allocation failure.
    static COW_MAP_FAIL: Cell<usize> = const { Cell::new(0) };
}

/// # Safety
/// The host range must satisfy the lifetime and alignment requirements of [`Mmu::map_shared`].
#[inline]
unsafe fn cow_map_shared(
    mmu: &Mmu,
    gva: u64,
    host: NonNull<u8>,
    len: u64,
    prot: u32,
) -> Result<(), MapError> {
    #[cfg(test)]
    if COW_MAP_FAIL.with(|n| n.replace(n.get().saturating_sub(1)) == 1) {
        return Err(MapError::OutOfMemory);
    }
    unsafe { mmu.map_shared(gva, host, len, prot) }
}

#[derive(Default)]
struct LendingPlan {
    borrowed: Vec<(u64, Borrowed)>,
    lent: Vec<u64>,
    child_runs: Runs,
    parent_runs: Runs,
}

impl LendingPlan {
    fn map(&self, parent: &Mm, child: &Mm) -> Result<(), Errno> {
        for &(s, page, host, len) in &self.child_runs.runs {
            // SAFETY: borrowed holds the regions until the child takes them or drops.
            unsafe { cow_map_shared(&child.mmu, page, host, len, Mm::read_only(&parent.vmas[&s])) }
                .map_err(|_| Errno::ENOMEM)?;
        }
        let runs = &self.parent_runs.runs;
        for (i, &(s, page, host, len)) in runs.iter().enumerate() {
            let ro = Mm::read_only(&parent.vmas[&s]);
            // SAFETY: these runs contain only pages owned by the parent VMA.
            if unsafe { cow_map_shared(&parent.mmu, page, host, len, ro) }.is_err() {
                // The failed run may have changed a prefix before reaching the next leaf.
                for &(s, page, _, len) in &runs[..=i] {
                    let full = mmu_prot(parent.vmas[&s].prot);
                    let _ = parent.mmu.protect_shared(page, len, full);
                }
                return Err(Errno::ENOMEM);
            }
        }
        Ok(())
    }
}

/// Copy-on-write (module docs, the kernel/cow map). Done through shared borrows: when the kernel
/// writes into guest memory it has only `&Mm`, and an owner recalling pages must also change its
/// borrowers' page tables.
impl Mm {
    /// Plan lending the written pages of one private anonymous VMA. The child borrows
    /// any pages we borrowed ourselves directly from their original owner.
    fn lend(&self, start: u64, plan: &mut LendingPlan) {
        let v = &self.vmas[&start];
        let end = start + v.len;
        // Look only at the spans that may have contents (Mm::touched_windows): untouched parts of
        // large on-demand mappings have no entries, so a mapping of several TB need not be walked
        // page by page. A page the host never touched is zero, and the child can use its own.
        // Small mappings are mostly touched, so pagemap is not read for them (one pread, over 30%
        // of fork's hold time) and everything is lent
        let small = v.len <= LEND_ALL_MAX;
        let windows = if small {
            vec![(start, end)]
        } else {
            self.touched_windows(start)
        };
        let ro = Self::read_only(v);
        let cow = self.cow.borrow();
        // Pages we borrowed and pages already lent are merged with the page-by-page walk in address
        // order instead of a lookup per page; they all lie in windows
        let mut mine = cow.borrowed.range(start..end).peekable();
        let mut out = cow.lent.range(start..end).peekable();
        for (lo, hi) in windows {
            let touched = (!small)
                .then(|| {
                    let host = Self::own_page(start, v, lo);
                    appine_hal::touched_pages(host.as_ptr(), (hi - lo) as usize)
                })
                .flatten();
            for (i, page) in (lo..hi).step_by(PAGE_SIZE as usize).enumerate() {
                let (host, region) = if let Some((_, b)) = mine.next_if(|&(&p, _)| p == page) {
                    (b.host, b.region.clone())
                } else {
                    let already_lent = out.next_if(|&&p| p == page).is_some();
                    if !already_lent && touched.as_ref().is_some_and(|t| !t[i]) {
                        continue;
                    }
                    let host = Self::own_page(start, v, page);
                    if !already_lent {
                        plan.lent.push(page);
                        if ro != 0 {
                            plan.parent_runs.push(start, page, host);
                        }
                    }
                    (host, v.region.clone())
                };
                if ro != 0 {
                    plan.child_runs.push(start, page, host);
                }
                plan.borrowed.push((page, Borrowed { host, region }));
            }
        }
    }

    /// Called before writing to `page` (a write fault, the kernel writing guest memory): a borrowed
    /// page is copied into our own, and borrowers of a lent page each copy theirs first. Returns
    /// true if the entry is now writable; false if the VMA is not writable or the page is not
    /// copy-on-write.
    pub fn cow_break(&self, page: u64) -> bool {
        let page = page & !(PAGE_SIZE - 1);
        if self
            .anon_vma(page)
            .is_none_or(|(_, v)| v.prot & prot::WRITE == 0)
        {
            return false;
        }
        let (borrowed, lent) = {
            let c = self.cow.borrow();
            (c.borrowed.contains_key(&page), c.lent.contains(&page))
        };
        if borrowed {
            return self.materialize(page, true).is_ok();
        }
        lent && self.recall(page).is_ok() && self.mmu.translate(page, prot::WRITE).is_some()
    }

    /// Pages in `[start, end)` stop being copy-on-write, keeping their contents in our own host
    /// memory: lent pages are recalled first, and borrowed ones are copied (before mremap moves,
    /// discarding, or the kernel writing host memory directly).
    fn cow_settle(&self, start: u64, end: u64) -> Result<(), Errno> {
        let (lent, borrowed): (Vec<u64>, Vec<u64>) = {
            let c = self.cow.borrow();
            (
                c.lent.range(start..end).copied().collect(),
                c.borrowed.range(start..end).map(|(&p, _)| p).collect(),
            )
        };
        for page in lent {
            self.recall(page)?;
        }
        for page in borrowed {
            self.materialize(page, true)?;
        }
        Ok(())
    }

    /// `[start, end)` is about to be unmapped: lent pages are recalled first; borrowed ones are
    /// taken out of the records and returned with [`Mm::give_back`] after the caller has changed
    /// the entries and flushed the TLB (their contents are no longer wanted, so no copy).
    fn cow_unmap(&self, start: u64, end: u64) -> Result<Vec<(u64, Borrowed)>, Errno> {
        let lent: Vec<u64> = self.cow.borrow().lent.range(start..end).copied().collect();
        for page in lent {
            self.recall(page)?;
        }
        let mut c = self.cow.borrow_mut();
        let pages: Vec<u64> = c.borrowed.range(start..end).map(|(&p, _)| p).collect();
        Ok(pages
            .into_iter()
            .map(|p| (p, c.borrowed.remove(&p).unwrap()))
            .collect())
    }

    /// Returns the pages [`Mm::cow_unmap`] took.
    fn give_back(&self, pages: Vec<(u64, Borrowed)>) {
        if pages.is_empty() {
            return;
        }
        self.shootdown();
        self.return_loans(pages.into_iter().map(|(page, b)| (page, b.host)), true);
    }

    /// The copy-on-write pages (lent and borrowed) in `[start, end)`, in order: for mprotect
    /// ([`Mm::set_protection`]).
    fn cow_pages(c: &Cow, start: u64, end: u64) -> Vec<u64> {
        let mut pages: Vec<u64> = c.lent.range(start..end).copied().collect();
        pages.extend(c.borrowed.range(start..end).map(|(&p, _)| p));
        pages.sort_unstable();
        pages.dedup();
        pages
    }

    /// Fill only unshared anonymous runs. A single empty leaf can still become a superpage.
    fn fill_anon_non_cow(&self, s: u64, v: &Vma, lo: u64, hi: u64) -> Result<(), MapError> {
        let pages = Self::cow_pages(&self.cow.borrow(), lo, hi);
        for (from, len) in Self::non_cow_runs(lo, hi, &pages) {
            let host = Self::own_page(s, v, from);
            // SAFETY: the VMA holds the whole run and every page uses its own backing.
            unsafe { self.mmu.fill_shared(from, host, len, v.prefill_prot()) }?;
        }
        Ok(())
    }

    /// Install each CoW entry with the old non-writable permissions before mprotect grants access.
    fn cow_entries(
        mmu: &Mmu,
        c: &Cow,
        s: u64,
        v: &Vma,
        pages: &[u64],
        prot: u32,
    ) -> Result<(), Errno> {
        for &page in pages {
            let host = match c.borrowed.get(&page) {
                Some(b) => b.host,
                None => Self::own_page(s, v, page),
            };
            // SAFETY: the host page belongs to this VMA, or b.region holds the borrowed one
            unsafe { cow_map_shared(mmu, page, host, PAGE_SIZE, prot) }.map_err(map_err)?;
        }
        Ok(())
    }

    /// Then the other pages of VMA `[s, s + len)`, around copy-on-write `pages` (in order), get
    /// page-table permissions `prot`, which include write permission.
    fn write_around(
        mmu: &mut Mmu,
        s: u64,
        len: u64,
        pages: &[u64],
        prot: u32,
    ) -> Result<(), Errno> {
        for (from, len) in Self::non_cow_runs(s, s + len, pages) {
            mmu.protect(from, len, prot).map_err(map_err)?;
        }
        Ok(())
    }

    fn non_cow_runs(mut from: u64, end: u64, pages: &[u64]) -> impl Iterator<Item = (u64, u64)> {
        pages.iter().copied().chain([end]).filter_map(move |page| {
            let start = from;
            from = page + PAGE_SIZE;
            (start < page).then(|| (start, page - start))
        })
    }

    /// When the address space is destroyed: pages of private anonymous memory that are not lent go
    /// back to the host. Lent pages stay with the borrowers, which hold that host memory, and are
    /// released only when the last borrower returns them; one piece of host memory may have been
    /// split into several VMAs, so each is checked (contents never written are all zero and
    /// untouched by the host, so those need no check).
    fn discard_unlent(&self, lent: &BTreeSet<u64>) {
        for (&s, v) in self
            .vmas
            .iter()
            .filter(|(_, v)| v.backing == Backing::Anonymous && v.written.get())
        {
            Self::discard_unlent_in(s, v, lent);
        }
    }

    /// The pages of private anonymous VMA `v` (at `s`) that are not in `lent` go back to the host.
    fn discard_unlent_in(s: u64, v: &Vma, lent: &BTreeSet<u64>) {
        let end = s + v.len;
        let mut cursor = s;
        for page in lent.range(s..end).copied().chain([end]) {
            if page > cursor {
                // SAFETY: [cursor, page) is inside this private anonymous VMA, whose contents
                // nobody needs any more
                unsafe { discard_host(Self::own_page(s, v, cursor), (page - cursor) as usize) };
            }
            cursor = page + PAGE_SIZE;
        }
    }

    /// Before the owner changes lent page `page`: every borrower copies its own, then write
    /// permission is restored.
    fn recall(&self, page: u64) -> Result<(), Errno> {
        let Some((s, v)) = self.anon_vma(page) else {
            self.cow.borrow_mut().lent.remove(&page);
            return Ok(());
        };
        let key = Self::own_page(s, v, page).as_ptr() as usize;
        let loan = self.loans.borrow_mut().remove(&key);
        if let Some(mut loan) = loan {
            // Reuse the loan's borrower list so retaining failed borrowers needs no allocation.
            let mut error = None;
            loan.retain_borrowers(|(borrower, addr)| {
                if let Some(mm) = borrower.upgrade()
                    && let Err(e) = mm.borrow().materialize(*addr, false)
                {
                    error = Some(e);
                    return true;
                }
                false
            });
            if let Some(e) = error {
                self.loans.borrow_mut().insert(key, loan);
                return Err(e);
            }
        }
        self.repossess(&[page]);
        Ok(())
    }

    /// Replaces borrowed page `page` with our own copy: copies it to the matching place in our own
    /// VMA and points the entry there. With `notify`, if this returns the last borrow, the owner
    /// gets write permission back; not needed when the owner itself is recalling.
    fn materialize(&self, page: u64, notify: bool) -> Result<(), Errno> {
        let mut cow = self.cow.borrow_mut();
        let Some(b) = cow.borrowed.get(&page) else {
            return Ok(());
        };
        let (s, v) = self.anon_vma(page).expect("borrowed page missing its VMA");
        let own = Self::own_page(s, v, page);
        // SAFETY: both sides are a whole page, and b.region holds the borrowed page.
        unsafe { std::ptr::copy_nonoverlapping(b.host.as_ptr(), own.as_ptr(), PAGE_SIZE as usize) };
        // Even PROT_NONE must retain a PTE for these contents before the loan is returned.
        // SAFETY: the host page belongs to this VMA.
        unsafe { cow_map_shared(&self.mmu, page, own, PAGE_SIZE, mmu_prot(v.prot)) }
            .map_err(|_| Errno::ENOMEM)?;
        let b = cow.borrowed.remove(&page).unwrap();
        drop(cow);
        // Threads' TLBs may still point at the borrowed page: return it only after flushing, since
        // the owner may write it right after
        self.shootdown();
        self.return_loan(b.host, page, notify);
        Ok(())
    }

    /// Returns borrowed host page `host` (at guest address `page` here).
    fn return_loan(&self, host: NonNull<u8>, page: u64, notify: bool) {
        self.return_loans([(page, host)], notify);
    }

    /// Returns a batch of borrowed pages (guest addresses here, the owner's host pages). With
    /// `notify`, pages whose last borrow is returned get write permission back at the owner,
    /// handled together per owner.
    fn return_loans(&self, pages: impl IntoIterator<Item = (u64, NonNull<u8>)>, notify: bool) {
        let mut owners: Vec<(MmRef, Vec<u64>)> = Vec::new();
        {
            let mut loans = self.loans.borrow_mut();
            for (page, host) in pages {
                let key = host.as_ptr() as usize;
                let Some(loan) = loans.get_mut(&key) else {
                    continue;
                };
                if loan.give_back(&self.me, page) {
                    continue;
                }
                if let Some((owner, addr)) = loans.remove(&key).and_then(|l| l.owner)
                    && notify
                {
                    match owners.iter_mut().find(|(o, _)| o.ptr_eq(&owner)) {
                        Some((_, addrs)) => addrs.push(addr),
                        None => owners.push((owner, vec![addr])),
                    }
                }
            }
        }
        // `recall` passes `notify = false` and calls `repossess` itself, so `owners` is populated
        // only by borrower-side returns (`materialize(_, true)`, `give_back`, `Drop`). An address
        // space never borrows from itself and CoW never mutably borrows two address spaces at
        // once, so borrowing `owner` always succeeds and `owner.cow.lent` never leaks a loan-less
        // entry.
        for (owner, addrs) in owners {
            if let Some(owner) = owner.upgrade() {
                owner.borrow().repossess(&addrs);
            }
        }
    }

    /// These lent pages have no borrowers left: restore write permission (only adding
    /// permissions, so no TLB flush is needed).
    fn repossess(&self, pages: &[u64]) {
        let mut runs = Runs::default();
        {
            let mut c = self.cow.borrow_mut();
            for &page in pages {
                if c.lent.remove(&page)
                    && let Some((s, v)) = self.anon_vma(page)
                {
                    runs.push(s, page, Self::own_page(s, v, page));
                }
            }
        }
        for (s, page, _, len) in runs.runs {
            // All loans are gone. If demotion fails, the next write fault retries in try_fault_in.
            let _ = self
                .mmu
                .protect_shared(page, len, mmu_prot(self.vmas[&s].prot));
        }
    }

    /// The immediate shootdown after a page-table entry is re-pointed: bump the generation first so
    /// users flush their TLBs before re-entering guest code; kick those running guest code and wait
    /// for them to leave (the approach of [`Mm::sync`], but the caller uses that page right after).
    /// It does not hold users back: one entering guest code after the wait has passed it runs with
    /// a flushed TLB while the caller still holds the BKL, so every step the caller takes must leave
    /// the page table valid for guest code.
    fn shootdown(&self) {
        if self.users.is_empty() {
            return;
        }
        // Pairs with the user's "mark, then read the generation": either it reads the new
        // generation, or this side sees it running
        self.generation.fetch_add(1, Ordering::SeqCst);
        for u in &self.users {
            if u.in_guest.load(Ordering::SeqCst) {
                // SAFETY: a thread unregisters from users (holding the BKL) before destroying its
                // Cpu
                unsafe { u.kicker.kick() };
            }
        }
        // Every user found in guest code is waited for, also one that entered after the kicks
        // above (its TLB may predate the bump). Such a user was not kicked and may run guest code for as long as it likes, such as a
        // spin on a thread that waits for the BKL held here (LTP shmctl05): kick it too
        for u in &self.users {
            while u.in_guest.load(Ordering::SeqCst) {
                // SAFETY: as above
                unsafe { u.kicker.kick() };
                std::thread::yield_now();
            }
        }
    }

    /// The private anonymous VMA containing page `page`, and its start.
    fn anon_vma(&self, page: u64) -> Option<(u64, &Vma)> {
        let (&s, v) = self.vmas.range(..=page).next_back()?;
        (page < s + v.len && v.backing == Backing::Anonymous).then_some((s, v))
    }

    /// The host page of page `page` in its own VMA.
    fn own_page(s: u64, v: &Vma, page: u64) -> NonNull<u8> {
        // SAFETY: page is inside this VMA, so the offset stays within the host mapping
        unsafe { v.host.add((page - s) as usize) }
    }

    /// The page-table permission of a copy-on-write page: no write permission.
    fn read_only(v: &Vma) -> u32 {
        mmu_prot(v.prot) & !prot::WRITE
    }
}

// ---- Introspection ----

/// One line of `/proc/<pid>/maps`.
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
    pub shared: bool,
    pub name: Option<Rc<[u8]>>,
    /// File mappings: the file offset of the start and the file's inode.
    pub file: Option<(u64, u64)>,
    /// Locked by mlock.
    pub locked: bool,
    /// Write permission can be granted (smaps `mw`).
    pub may_write: bool,
    /// Execute permission can be granted (smaps `me`).
    pub may_exec: bool,
    /// `MADV_DONTDUMP` (smaps `dd`).
    pub dontdump: bool,
    /// `MADV_WIPEONFORK` (smaps `wf`).
    pub wipeonfork: bool,
    /// `MADV_DONTFORK` (smaps `dc`).
    pub dontfork: bool,
}

/// One sample of resident memory ([`Mm::rss_plan`]).
/// A shared mapping of anonymous memory (shared anonymous, SysV shm, memfd, a deleted file):
/// Linux's shmem, as core dumps' `ANON_SHARED` and status's RssShmem count it.
fn shmem_like(v: &Vma) -> bool {
    v.backing == Backing::Shared
        && (v.file_id.is_none()
            || v.shm.is_some()
            || v.name
                .as_deref()
                .is_some_and(|n| n.starts_with(b"/memfd:") || n.ends_with(b" (deleted)")))
}

/// Contiguous owner host pages in guest page order, for per-Mm swap accounting.
fn borrowed_host_runs(cow: &Cow) -> impl Iterator<Item = (*const u8, usize)> + '_ {
    let mut pages = cow
        .borrowed
        .values()
        .map(|b| b.host.as_ptr().cast_const())
        .peekable();
    std::iter::from_fn(move || {
        let start = pages.next()?;
        let mut len = PAGE_SIZE as usize;
        while pages.next_if_eq(&start.wrapping_add(len)).is_some() {
            len += PAGE_SIZE as usize;
        }
        Some((start, len))
    })
}

fn nonresident_pages(host: *const u8, len: usize) -> u64 {
    (len as u64 / PAGE_SIZE).saturating_sub(appine_hal::resident_pages(host, len) as u64)
}

/// The resident memory of several address spaces together (a child cgroup's `memory.current`):
/// memory they share counts once, as Linux charges a page to one cgroup. Shared anonymous memory,
/// SysV shm, read-only private file mappings and pages lent for copy-on-write are the same host
/// pages in every address space using them, so the spans' union measures each once; file
/// mappings measured from the page cache count once per piece of file (device, inode, offset,
/// length), so overlapping but different pieces of one file count separately.
#[derive(Default)]
pub struct Usage {
    fixed: u64,
    spans: Vec<(usize, usize)>,
    counted: std::collections::HashSet<FilePiece>,
}

impl Usage {
    /// Adds address space `mm`; one used by several processes is to be added once.
    pub fn add(&mut self, mm: &Mm) {
        let plan = mm.plan(Some(&mut self.counted));
        self.fixed += plan.fixed;
        self.spans.extend(plan.spans);
    }

    /// Resident 4K pages of everything added.
    pub fn pages(mut self) -> u64 {
        self.spans.sort_unstable();
        // The union of the host ranges: overlapping ones merge, contiguous ones are merged by
        // the measurement
        let mut union: Vec<(usize, usize)> = Vec::with_capacity(self.spans.len());
        for (start, len) in self.spans {
            match union.last_mut() {
                Some((s, l)) if start < *s + *l => *l = (*l).max(start + len - *s),
                _ => union.push((start, len)),
            }
        }
        RssPlan {
            fixed: self.fixed,
            spans: union,
        }
        .measure()
    }
}

/// A piece of a file mapping as [`FileResidency`] caches it: device, inode, file offset, length.
type FilePiece = (u64, u64, u64, u64);

struct RssPlan {
    /// 4K pages known without mincore: borrowed pages and cached file mappings.
    fixed: u64,
    /// Host ranges to mincore, sorted by start.
    spans: Vec<(usize, usize)>,
}

impl RssPlan {
    /// When the spans to measure total at most this many pages they are not measured but counted as
    /// fully resident ([`RssPlan::estimate`]).
    const SMALL: usize = 256;

    /// Estimate used for the peak resident page count: when the spans to mincore total at most 1
    /// MB, count them as fully resident, overcounting by at most 1 MB. A short-lived process like
    /// `/bin/true` would measure 8 spans totalling 45 pages at exit and find 12, yet take 4 mincore
    /// calls while holding the BKL (and wait for the host mmap_lock). Processes that allocated a
    /// lot of memory are measured as usual.
    fn estimate(&self) -> u64 {
        let pages: usize = self.spans.iter().map(|&(_, len)| len.div_ceil(4096)).sum();
        if pages <= Self::SMALL {
            self.fixed + pages as u64
        } else {
            self.measure()
        }
    }

    /// Resident 4K pages. Spans that are contiguous on the host are merged into one mincore.
    fn measure(&self) -> u64 {
        let mut total = self.fixed;
        let mut rest = &self.spans[..];
        while let Some(&(start, mut len)) = rest.first() {
            let n = rest[1..]
                .iter()
                .take_while(|&&(s, l)| {
                    let next = s == start + len;
                    len += if next { l } else { 0 };
                    next
                })
                .count();
            total += appine_hal::resident_pages(start as *const u8, len) as u64;
            rest = &rest[1 + n..];
        }
        total
    }
}

/// Cache of the resident page counts of file mappings ([`Mm::resident_pages`]), keyed by (device,
/// inode, file offset, length).
struct FileResidency;

impl FileResidency {
    /// How long a cached result is used: a file's pages in the page cache change slowly.
    const TTL: std::time::Duration = std::time::Duration::from_secs(1);
    /// The most spans cached; the cache is cleared when it is full.
    const MAX: usize = 1024;

    fn get(
        key: (u64, u64, u64, u64),
        now: std::time::Instant,
        measure: impl FnOnce() -> u64,
    ) -> u64 {
        type Map = HashMap<(u64, u64, u64, u64), (u64, std::time::Instant)>;
        static CACHE: Mutex<Option<Map>> = Mutex::new(None);
        let mut cache = CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let map = cache.get_or_insert_with(HashMap::new);
        if let Some(&(n, at)) = map.get(&key)
            && now.duration_since(at) < Self::TTL
        {
            return n;
        }
        if map.len() >= Self::MAX {
            map.clear();
        }
        let n = measure();
        map.insert(key, (n, now));
        n
    }
}

/// One mapping in a core dump ([`Mm::dump_regions`]).
pub struct DumpRegion {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
    /// Bytes from the start written to the core file.
    pub size: u64,
    /// Pages not resident in host memory were never touched (anonymous, shared memory) and are
    /// written as holes; untouched pages of private file mappings are file contents and must be
    /// read.
    pub sparse: bool,
    /// Include this page only if its contents start with the ELF magic.
    pub check_elf: bool,
    /// File mappings: the file offset of the start and the path (`NT_FILE`).
    pub file: Option<(u64, Rc<[u8]>)>,
}

/// Bits of `/proc/<pid>/coredump_filter` (Linux's `MMF_DUMP_*`); the default is
/// [`dump_filter::DEFAULT`].
pub mod dump_filter {
    pub const ANON_PRIVATE: u32 = 1;
    pub const ANON_SHARED: u32 = 2;
    pub const MAPPED_PRIVATE: u32 = 4;
    pub const MAPPED_SHARED: u32 = 8;
    pub const ELF_HEADERS: u32 = 16;
    /// Private and shared anonymous mappings, ELF headers, private huge pages.
    pub const DEFAULT: u32 = 0x33;
}

// ---- Host backing ----

/// The "host address" of a reserved ([`HostRegion::reserved`]) VMA: guest offsets are counted from
/// here only for arithmetic (splitting VMAs), never for access. Bit 55 is set, so it falls in the
/// host kernel's half (arm64 TBI ignores only the top 8 bits), and an access by mistake is a host
/// segmentation fault that cannot reach other memory.
const RESERVED_HOST: usize = 0x00f0_0000_0000_0000;

/// A piece of host memory held by an [`Mm`]. Shared through `Arc`: the host mappings of read-only
/// file mappings are shared by all address spaces ([`FileMaps`]), and execve also gets them while
/// building a new address space without the BKL.
struct HostRegion {
    base: NonNull<u8>,
    len: usize,
    /// Private anonymous memory ([`Mm::new_anonymous`], [`spare`]) and whether it is
    /// commit-accounted: kept for reuse when returned ([`recycled`]).
    anonymous: Option<bool>,
    /// Sub-range `[used_start, used_end)` (byte offsets from `base`) of a private anonymous region
    /// that was exposed to any VMA. Oversized reservations (stacks, heaps) start empty (`len..0`)
    /// and widen monotonically on mapping or in-place growth so [`recycled::put`] discards only
    /// what could have been touched.
    used_start: AtomicUsize,
    used_end: AtomicUsize,
    /// No host memory ([`HostRegion::reserved`]).
    reserved: bool,
    /// Host memory the kernel layer does not own and only reads: the host's vvar page
    /// ([`Mm::map_vvar`]). Never unmapped or reused, and not counted as anyone's memory.
    foreign: bool,
    gpu: Option<Arc<dyn crate::gpu::Mapping>>,
}

impl HostRegion {
    fn anonymous(base: NonNull<u8>, len: usize, reserve: bool, full: bool) -> Arc<HostRegion> {
        let (used_start, used_end) = if full { (0, len) } else { (len, 0) };
        Arc::new(HostRegion {
            base,
            len,
            anonymous: Some(reserve),
            used_start: AtomicUsize::new(used_start),
            used_end: AtomicUsize::new(used_end),
            reserved: false,
            foreign: false,
            gpu: None,
        })
    }

    fn file(base: NonNull<u8>, len: usize) -> Arc<HostRegion> {
        Arc::new(HostRegion {
            base,
            len,
            anonymous: None,
            used_start: AtomicUsize::new(0),
            used_end: AtomicUsize::new(0),
            reserved: false,
            foreign: false,
            gpu: None,
        })
    }

    /// A private anonymous mapping that has been `PROT_NONE` and empty since it was created takes
    /// neither host memory nor host address space. All guest processes live in one host process,
    /// and on devices whose host user address space is only 39 bits (512 GB; every 4K-page GKI
    /// kernel) each Chromium process reserves tens of GB (PartitionAlloc's pools) and a renderer 1
    /// TB more (V8's sandbox), which together do not fit. Such a VMA has no entries, so the guest
    /// cannot reach it; it gets its own host memory only when it becomes accessible (mprotect) or
    /// the kernel writes into it (ptrace) ([`Mm::back_reserved`]).
    fn reserved() -> Arc<HostRegion> {
        Arc::new(HostRegion {
            base: NonNull::new(RESERVED_HOST as *mut u8).unwrap(),
            len: 0,
            anonymous: None,
            used_start: AtomicUsize::new(0),
            used_end: AtomicUsize::new(0),
            reserved: true,
            foreign: false,
            gpu: None,
        })
    }

    /// Records that `[host, host + len)` inside this region may be accessed.
    fn note_used(&self, host: NonNull<u8>, len: usize) {
        if self.anonymous.is_none() || len == 0 {
            return;
        }
        let start = (host.as_ptr() as usize)
            .checked_sub(self.base.as_ptr() as usize)
            .expect("host pointer before region base");
        let end = start.checked_add(len).expect("host slice overflow");
        debug_assert!(end <= self.len);
        self.used_start.fetch_min(start, Ordering::Relaxed);
        self.used_end
            .fetch_max(end.min(self.len), Ordering::Relaxed);
    }

    /// Returns the tracked `[start, end)` byte offsets inside this region, or `(0, 0)` when
    /// nothing was exposed.
    fn used_range(&mut self) -> (usize, usize) {
        let start = *self.used_start.get_mut();
        let end = *self.used_end.get_mut();
        if start < end { (start, end) } else { (0, 0) }
    }
}

// SAFETY: it is only a host address range, used only when it is released (Drop)
unsafe impl Send for HostRegion {}
unsafe impl Sync for HostRegion {}

impl Drop for HostRegion {
    fn drop(&mut self) {
        if self.reserved || self.foreign || self.gpu.is_some() {
            return;
        }
        let (base, len, anonymous) = (self.base, self.len, self.anonymous);
        if let Some(reserve) = anonymous {
            let (used_start, used_end) = self.used_range();
            let deferred = UNMAPPED.with_borrow_mut(|u| {
                u.as_mut()
                    .map(|u| u.anonymous.push((base, len, reserve, used_start, used_end)))
            });
            if deferred.is_some() {
                UNMAPPING.fetch_add(len, Ordering::Relaxed);
            } else {
                // SAFETY: this private anonymous host memory belongs to this HostRegion and is no
                // longer used by anyone
                unsafe { recycled::put(base, len, reserve, used_start, used_end) }
            }
            return;
        }
        let deferred =
            UNMAPPED.with_borrow_mut(|u| u.as_mut().map(|u| u.regions.push((base, len))));
        if deferred.is_some() {
            UNMAPPING.fetch_add(len, Ordering::Relaxed);
        } else {
            // SAFETY: this host memory belongs to this HostRegion and is no longer used by anyone
            unsafe { appine_hal::unmap(base, len) }
        }
    }
}

/// Host memory that can be mapped into several address spaces (a System V shared memory segment).
#[derive(Clone)]
pub(crate) struct SharedMemory {
    region: Arc<HostRegion>,
}

impl SharedMemory {
    /// Creates zeroed memory, its length rounded up to a page.
    pub fn new(len: u64) -> Result<SharedMemory, Errno> {
        let len = page_up(len).ok_or(Errno::ENOMEM)?;
        let (region, _) = Mm::new_anonymous(len, true)?;
        Ok(SharedMemory { region })
    }

    /// Length (a multiple of the page size).
    pub fn len(&self) -> u64 {
        self.region.len as u64
    }
}

/// Host mappings of read-only private file mappings (the code segments of programs and libraries),
/// shared by all address spaces in the kernel: mapping the same piece of the same version
/// ([`content::version`]) of a file again reuses one directly, with its host page tables intact,
/// so there is no re-mapping or page fault, and no teardown at exit (once each for the program's
/// and the dynamic linker's code segments every time the shell spawns a process). VMAs using one
/// are marked `cow`, like parent and child sharing host memory after fork, and copy their own
/// before writing. On the host it is a read-only mapping, so a place that forgets to copy fails
/// outright instead of silently changing someone else's code.
#[derive(Clone, Default)]
pub(crate) struct FileMaps(Arc<Mutex<Vec<FileMap>>>);

impl FileMaps {
    /// The most pieces kept. They take only host address space; the pages are in the page cache
    /// and can be reclaimed when host memory is short.
    const MAX: usize = 128;

    fn get(&self, key: &[u64; 6]) -> Option<(Arc<HostRegion>, NonNull<u8>)> {
        let mut maps = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let next = maps.iter().map(|m| m.used).max().unwrap_or(0) + 1;
        let m = maps.iter_mut().find(|m| m.key == *key)?;
        m.used = next;
        Some((m.region.clone(), m.host))
    }

    fn insert(&self, key: [u64; 6], region: Arc<HostRegion>, host: NonNull<u8>) {
        let mut maps = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let used = maps.iter().map(|m| m.used).max().unwrap_or(0) + 1;
        if maps.len() >= Self::MAX
            && let Some(old) = (0..maps.len()).min_by_key(|&i| maps[i].used)
        {
            maps.swap_remove(old);
        }
        maps.push(FileMap {
            key,
            region,
            host,
            used,
        });
    }

    /// Drops everything (when host memory is short). Mappings still in use are held by the VMAs
    /// using them and are unaffected.
    pub fn clear(&self) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

struct FileMap {
    /// (device, inode, file offset, length, ctime, size).
    key: [u64; 6],
    region: Arc<HostRegion>,
    host: NonNull<u8>,
    /// Sequence number of the most recent use; when full, the least recently used is dropped.
    used: u64,
}

// SAFETY: host points into host memory that region holds
unsafe impl Send for FileMap {}

/// The version of a host file's contents ([`content::version`]), None when there is no trusted
/// version.
pub(crate) fn content_version(st: &libc::stat, dev: u64, ino: u64) -> Option<(u64, u64)> {
    content::version(st, dev, ino)
}

/// Drops any `WRITABLY_SHARED` tracking for a host object that has just been unlinked.
///
/// Once the host object's link count reaches zero, [`content::version`] rejects it unconditionally
/// via `st_nlink == 0`, so forgetting `(dev, ino)` here never re-trusts open descriptors or active
/// mappings of the deleted file while allowing a later file that reuses `(dev, ino)` to share
/// through [`FileMaps`] and [`CodeGroup`].
pub(crate) fn forget_writably_shared(dev: u64, ino: u64) {
    content::forget(dev, ino);
}

/// Telling whether two file mappings have the same contents ([`Mm::code_sources`]).
mod content {
    use std::collections::HashSet;
    use std::os::fd::RawFd;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    /// Linked host files `(device, inode)` that have had a writable shared mapping: contents
    /// written through a shared mapping do not necessarily change ctime (a page that stays dirty
    /// no longer goes through `page_mkwrite`), so ctime is no longer trusted for such files until
    /// their host object is unlinked ([`forget`]).
    static WRITABLY_SHARED: Mutex<Option<HashSet<(u64, u64)>>> = Mutex::new(None);

    fn lock() -> MutexGuard<'static, Option<HashSet<(u64, u64)>>> {
        WRITABLY_SHARED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// File (`dev`, `ino`) got a writable shared mapping.
    ///
    /// Re-checks `fstat(fd)` under the lock so a concurrent object unlink (`unlink_at` followed by
    /// [`forget`]) cannot leave a stale `(dev, ino)` behind once `st_nlink == 0`.
    pub(super) fn writably_shared(fd: RawFd, dev: u64, ino: u64) {
        let mut set = lock();
        if appine_hal::fstat(fd).is_ok_and(|st| st.st_nlink > 0) {
            set.get_or_insert_with(HashSet::new).insert((dev, ino));
        }
    }

    /// Removes (`dev`, `ino`) after its host object has been unlinked.
    pub(super) fn forget(dev: u64, ino: u64) {
        if let Some(s) = lock().as_mut() {
            s.remove(&(dev, ino));
        }
    }

    #[cfg(test)]
    pub(super) fn contains(dev: u64, ino: u64) -> bool {
        lock().as_ref().is_some_and(|s| s.contains(&(dev, ino)))
    }

    /// The version of a host file's contents: ctime (nanoseconds) and size. Every change to the
    /// contents (write, truncate, fallocate…) sets ctime to the current time on the host, and
    /// utimensat cannot set it back, so two equal versions mean no change in between. Host
    /// timestamps come from a coarse clock, and when ctime is too close to now a change right
    /// after may get the same ctime, so no version is given then; nor for unlinked host files
    /// (`st_nlink == 0`, including memfds and deleted objects) or files that have had a writable
    /// shared mapping.
    #[allow(clippy::unnecessary_cast)]
    pub(super) fn version(st: &libc::stat, dev: u64, ino: u64) -> Option<(u64, u64)> {
        if st.st_nlink == 0 {
            return None;
        }
        const RACY_NS: i128 = 2_000_000_000;
        let ctime = st.st_ctime as i128 * 1_000_000_000 + st.st_ctime_nsec as i128;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_nanos() as i128;
        if ctime + RACY_NS > now {
            return None;
        }
        if lock().as_ref().is_some_and(|s| s.contains(&(dev, ino))) {
            return None;
        }
        Some((ctime as u64, st.st_size as u64))
    }
}

/// What [`Mm::carve`] carves: each VMA's start → its piece of host memory and its host address.
type Carved = BTreeMap<u64, (Arc<HostRegion>, NonNull<u8>)>;

/// Several pieces of the anonymous host memory fork needs (the address space reserved for the heap
/// and the stack, the pieces small mappings are carved from) are mapped in advance, and fork takes
/// them directly while holding the BKL. A program forking repeatedly always wants the same few
/// lengths, and a used piece is replaced after the BKL is released ([`refill`](spare::refill)):
/// host mmap used to take 40% of fork's hold time, and four processes spawning at once had less
/// total throughput than one.
pub(crate) mod spare {
    use std::ptr::NonNull;
    use std::sync::{Arc, Mutex, PoisonError};

    use super::HostRegion;
    use crate::errno::Errno;

    /// The most pieces kept per length.
    const PER_LEN: usize = 2;
    /// The most lengths remembered.
    const LENS: usize = 8;

    struct Spares {
        /// (length, start): `MAP_NORESERVE` anonymous host memory, never touched.
        maps: Vec<(usize, usize)>,
        /// Lengths to replace, most recently used last.
        wanted: Vec<usize>,
    }

    static SPARES: Mutex<Spares> = Mutex::new(Spares {
        maps: Vec::new(),
        wanted: Vec::new(),
    });

    /// `len` bytes of zeroed anonymous host memory, not commit-accounted (`MAP_NORESERVE`): a piece
    /// mapped in advance if there is one, otherwise mapped on the spot.
    pub(super) fn anonymous(len: u64) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        anonymous_with(len, true)
    }

    /// Like [`anonymous`], starting with an empty used range for oversized stack/heap reservations.
    pub(super) fn anonymous_reserved(len: u64) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        anonymous_with(len, false)
    }

    fn anonymous_with(len: u64, full: bool) -> Result<(Arc<HostRegion>, NonNull<u8>), Errno> {
        let host_len = usize::try_from(len).map_err(|_| Errno::ENOMEM)?;
        let found = {
            let mut s = SPARES.lock().unwrap_or_else(PoisonError::into_inner);
            s.wanted.retain(|&l| l != host_len);
            s.wanted.push(host_len);
            if s.wanted.len() > LENS {
                let old = s.wanted.remove(0);
                // Also return the pieces kept for a length no longer wanted
                s.maps.retain(|&(l, base)| {
                    if l == old {
                        // SAFETY: host memory mapped in advance and never used
                        unsafe { appine_hal::unmap(NonNull::new(base as *mut u8).unwrap(), l) };
                    }
                    l != old
                });
            }
            s.maps
                .iter()
                .position(|&(l, _)| l == host_len)
                .map(|i| s.maps.swap_remove(i).1)
        };
        let base = match found
            .and_then(|b| NonNull::new(b as *mut u8))
            .or_else(|| super::recycled::take(host_len, false))
        {
            Some(base) => base,
            None => appine_hal::map_anonymous(host_len, false).map_err(|_| Errno::ENOMEM)?,
        };
        Ok((HostRegion::anonymous(base, host_len, false, full), base))
    }

    /// Replaces the pieces used. Called after the BKL is released.
    pub(crate) fn refill() {
        loop {
            let need = {
                let s = SPARES.lock().unwrap_or_else(PoisonError::into_inner);
                s.wanted
                    .iter()
                    .copied()
                    .find(|&l| s.maps.iter().filter(|m| m.0 == l).count() < PER_LEN)
            };
            let Some(len) = need else {
                return;
            };
            let Ok(base) = appine_hal::map_anonymous(len, false) else {
                return;
            };
            let mut s = SPARES.lock().unwrap_or_else(PoisonError::into_inner);
            if s.wanted.contains(&len) && s.maps.iter().filter(|m| m.0 == len).count() < PER_LEN {
                s.maps.push((len, base.as_ptr() as usize));
            } else {
                drop(s);
                // SAFETY: just mapped and never used
                unsafe { appine_hal::unmap(base, len) };
            }
        }
    }
}

/// Things freed while holding the BKL and returned after it is released.
#[derive(Default)]
struct Unmapped {
    /// Host memory: (start, length).
    regions: Vec<(NonNull<u8>, usize)>,
    /// Private anonymous host memory kept for reuse ([`recycled`]): (start, length,
    /// commit-accounted, used start, used end).
    anonymous: Vec<(NonNull<u8>, usize, bool, usize, usize)>,
    /// Page tables of destroyed address spaces: freeing the intermediate tables one by one takes
    /// several microseconds.
    mmus: Vec<Mmu>,
}

thread_local! {
    /// Host memory freed while holding the BKL, returned to the host only after the BKL is released
    /// ([`release_unmapped`]); None when the BKL is not held, which returns it on the spot.
    #[allow(clippy::missing_const_for_thread_local)] // already const; Android clippy misfires
    static UNMAPPED: std::cell::RefCell<Option<Unmapped>> = const { std::cell::RefCell::new(None) };
}

/// Bytes freed but not yet returned to the host: the OOM killer waits for them to be returned
/// before it measures.
pub(crate) static UNMAPPING: AtomicUsize = AtomicUsize::new(0);

/// Starts holding the BKL: host memory freed from now on is returned after the BKL is released
/// ([`release_unmapped`]).
pub(crate) fn defer_unmaps() {
    UNMAPPED.with_borrow_mut(|u| {
        u.get_or_insert_with(Unmapped::default);
    });
}

/// The BKL was released: return the host memory freed while it was held. Process exit and execve
/// free ten or twenty mappings at once, and the host takes tens of microseconds to tear down page
/// tables and flush TLBs; threads waiting for the BKL (the shell waiting to reap it, the process
/// at the other end of a pipe) need not wait for that too. Contiguous pieces are returned
/// together, saving TLB flushes.
pub(crate) fn release_unmapped() {
    let Some(Unmapped {
        regions: mut list,
        anonymous,
        mmus,
    }) = UNMAPPED.with_borrow_mut(Option::take)
    else {
        return;
    };
    // Free the page tables first, then return the host memory they point at
    drop(mmus);
    let reused: usize = anonymous.iter().map(|&(_, len, _, _, _)| len).sum();
    for (base, len, reserve, used_start, used_end) in anonymous {
        // SAFETY: private anonymous host memory recorded when its HostRegion was dropped, and no
        // longer used by anyone
        unsafe { recycled::put(base, len, reserve, used_start, used_end) };
    }
    UNMAPPING.fetch_sub(reused, Ordering::Release);
    if list.is_empty() {
        return;
    }
    list.sort_unstable_by_key(|&(base, _)| base);
    let total: usize = list.iter().map(|&(_, len)| len).sum();
    let mut run = list[0];
    for &(base, len) in &list[1..] {
        // SAFETY: both are returned host memory; on the host the previous piece ends exactly at
        // base (when host pages are larger than 4K the length rounds up, and pieces that do not
        // adjoin cannot be equal by chance)
        if unsafe { run.0.add(run.1) } == base {
            run.1 += len;
        } else {
            unsafe { appine_hal::unmap(run.0, run.1) };
            run = (base, len);
        }
    }
    unsafe { appine_hal::unmap(run.0, run.1) };
    UNMAPPING.fetch_sub(total, Ordering::Release);
}

/// Private anonymous host memory kept for reuse after it is returned ([`HostRegion::anonymous`]).
/// All guest processes live in one host process, and every host mmap and munmap takes that one
/// process's mmap_lock for write (natively each process has its own): musl's malloc and gcc's
/// garbage collector map and unmap blocks of the same sizes over and over, more than a hundred
/// thousand times when `xargs -P4` compiles Lua, each time waiting on the host mmap while holding
/// the BKL. Returning only discards the contents (`MADV_DONTNEED`, which takes the lock only for
/// read), and the next request of the same size and the same commit accounting takes it directly.
mod recycled {
    use std::collections::HashMap;
    use std::ptr::NonNull;
    use std::sync::Mutex;

    /// The most host address space kept: the pages have gone back to the host, so it costs only
    /// address space and a little page table.
    const MAX_BYTES: usize = 256 << 20;
    /// The most ranges kept per size.
    const MAX_EACH: usize = 32;
    /// Strict upper bound on the host-page-aligned discard span accepted for reuse: below one 2 MB
    /// arm64 4K-page PMD so `MADV_DONTNEED` never zaps a full PMD (which triggers a Linux
    /// 6.18-7.x arm64 minor page-fault livelock on subsequent reuse when empty PTE tables are
    /// reclaimed). Regions whose used span reaches this limit are unmapped instead of recycled.
    pub(super) const MAX_DISCARD: usize = 2 << 20;

    struct Cache {
        /// (length, commit-accounted) → starts.
        free: HashMap<(usize, bool), Vec<usize>>,
        bytes: usize,
    }

    static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

    /// Takes a kept piece of private anonymous host memory whose contents are zero.
    pub(super) fn take(len: usize, reserve: bool) -> Option<NonNull<u8>> {
        let mut cache = CACHE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let c = cache.as_mut()?;
        let base = c.free.get_mut(&(len, reserve))?.pop()?;
        c.bytes -= len;
        NonNull::new(base as *mut u8)
    }

    /// Returns a piece of private anonymous host memory: discards its used sub-range
    /// `[used_start, used_end)` and keeps it for reuse when that discard stays below
    /// [`MAX_DISCARD`], or returns it to the host otherwise.
    ///
    /// # Safety
    ///
    /// The host memory was allocated by [`appine_hal::map_anonymous`], nobody uses it any more,
    /// and no byte outside `[used_start, used_end)` was modified since it was zeroed.
    pub(super) unsafe fn put(
        base: NonNull<u8>,
        len: usize,
        reserve: bool,
        used_start: usize,
        used_end: usize,
    ) {
        let page = appine_hal::page_size();
        let (discard_start, host_discard_len) = if used_start < used_end {
            let end = used_end.min(len);
            let start = used_start.min(end) & !(page - 1);
            let host_len = end
                .checked_next_multiple_of(page)
                .map_or(usize::MAX, |host_end| host_end - start);
            (start, host_len)
        } else {
            (0, 0)
        };
        if host_discard_len < MAX_DISCARD {
            let mut cache = CACHE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let c = cache.get_or_insert_with(|| Cache {
                free: HashMap::new(),
                bytes: 0,
            });
            let list = c.free.entry((len, reserve)).or_default();
            if c.bytes + len <= MAX_BYTES && list.len() < MAX_EACH {
                // SAFETY: guaranteed by the caller; `base` and `discard_start` are aligned to host
                // pages and `[discard_start, discard_start + host_discard_len)` covers every
                // exposed byte within the host-aligned mapping. After discarding it reads as zero,
                // like a new mapping.
                let ok = host_discard_len == 0
                    || unsafe { appine_hal::discard(base.add(discard_start), host_discard_len) }
                        .is_ok();
                if ok {
                    list.push(base.as_ptr() as usize);
                    c.bytes += len;
                    return;
                }
            }
        }
        // SAFETY: guaranteed by the caller
        unsafe { appine_hal::unmap(base, len) }
    }
}

fn page_up(v: u64) -> Option<u64> {
    v.checked_add(PAGE_SIZE - 1).map(|v| v & !(PAGE_SIZE - 1))
}

/// The page-table permission for a guest permission: arm64 has no write-only pages, so writable
/// implies readable.
fn mmu_prot(p: u32) -> u32 {
    let mut r = p & (prot::READ | prot::WRITE | prot::EXEC);
    if r & prot::WRITE != 0 {
        r |= prot::READ;
    }
    r
}

/// Bytes of the file that still have contents from `offset`, rounded up to a page, at most `len`.
fn file_extent(fd: i32, offset: u64, len: u64) -> u64 {
    extent(appine_hal::fstat(fd).map_or(0, |s| s.st_size), offset, len)
}

/// Bytes of a file of size `size` that still have contents from `offset` ([`file_extent`]).
fn extent(size: i64, offset: u64, len: u64) -> u64 {
    (size.max(0) as u64)
        .saturating_sub(offset)
        .next_multiple_of(PAGE_SIZE)
        .min(len)
}

/// Triggers a host write fault on each host page covering `[ptr, ptr + len)` without modifying
/// any bytes or racing concurrent guest stores.
///
/// # Safety
///
/// `[ptr, ptr + len)` must lie inside a live writable host mapping within EOF.
unsafe fn populate_write_host(ptr: *const u8, len: usize) {
    let page = appine_hal::page_size();
    let mut at = ptr as usize & !(page - 1);
    let stop = ptr as usize + len;
    while at < stop {
        let target = at.max(ptr as usize) as *const AtomicU8;
        // SAFETY: guaranteed by the caller; atomic OR of 0 leaves bytes unchanged while faulting
        // writable host pages.
        unsafe { (*target).fetch_or(0, Ordering::Relaxed) };
        at += page;
    }
}

/// Discards the contents of private anonymous host memory: whole pages go back to the host, and
/// when host pages are larger than 4K the partial pages at both ends are zeroed. It used to zero
/// everything, so the GCs of Go, the JVM and V8 touched every page they were giving back.
///
/// # Safety
///
/// `[ptr, ptr + len)` is private anonymous host memory held by an [`Mm`].
unsafe fn discard_host(ptr: NonNull<u8>, len: usize) {
    // SAFETY: the caller's guarantee; what the host keeps is zeroed
    unsafe {
        for (off, l) in discard_file_host(ptr, len) {
            std::ptr::write_bytes(ptr.as_ptr().add(off), 0, l);
        }
    }
}

/// Gives the whole host pages of `[ptr, ptr + len)` back to the host (`MADV_DONTNEED`: zeros for
/// anonymous memory, the file's contents for a private file mapping) and returns the pieces it
/// could not, as (offset, length): the partial host pages at both ends when host pages are larger
/// than 4K, or everything when the host refuses.
///
/// # Safety
///
/// `[ptr, ptr + len)` is private host memory (anonymous or a private file mapping) held by an
/// [`Mm`].
unsafe fn discard_file_host(ptr: NonNull<u8>, len: usize) -> Vec<(usize, usize)> {
    let page = appine_hal::page_size();
    let addr = ptr.as_ptr() as usize;
    let head = (addr.next_multiple_of(page) - addr).min(len);
    let tail = ((addr + len) & !(page - 1)).max(addr + head) - addr;
    // SAFETY: all offsets are in [0, len]; [head, tail) is aligned to host pages
    if head < tail && unsafe { appine_hal::discard(ptr.add(head), tail - head) }.is_ok() {
        [(0, head), (tail, len - tail)]
            .into_iter()
            .filter(|&(_, l)| l > 0)
            .collect()
    } else {
        vec![(0, len)]
    }
}

/// Frees the contents of shared host memory (`MADV_REMOVE`): the whole host pages are punched
/// out of the file or shared memory behind them, and the partial host pages at both ends when
/// host pages are larger than 4K, or everything when the host refuses, are zeroed.
///
/// # Safety
///
/// `[ptr, ptr + len)` is writable shared host memory held by an [`Mm`].
unsafe fn remove_host(ptr: *mut u8, len: usize) {
    let page = appine_hal::page_size();
    let addr = ptr as usize;
    let head = (addr.next_multiple_of(page) - addr).min(len);
    let tail = ((addr + len) & !(page - 1)).max(addr + head) - addr;
    // SAFETY: all offsets are in [0, len]; [head, tail) is aligned to host pages
    unsafe {
        let removed = head < tail
            && NonNull::new(ptr.add(head))
                .is_some_and(|p| appine_hal::remove(p, tail - head).is_ok());
        if removed {
            std::ptr::write_bytes(ptr, 0, head);
            std::ptr::write_bytes(ptr.add(tail), 0, len - tail);
        } else {
            std::ptr::write_bytes(ptr, 0, len);
        }
    }
}

fn map_err(e: MapError) -> Errno {
    match e {
        MapError::InvalidArgument => Errno::EINVAL,
        MapError::OutOfMemory => Errno::ENOMEM,
    }
}

/// Copies page by page, skipping all-zero pages (the destination is already zeroed).
///
/// # Safety
///
/// `src` and `dst` must both point to at least `len` bytes of accessible, non-overlapping memory,
/// and `len` must be a multiple of the page size. `touched` tells whether each page was touched
/// ([`appine_hal::touched_pages`]); untouched pages are not looked at.
unsafe fn copy_nonzero_pages(src: *const u8, dst: *mut u8, len: usize, touched: Option<&[bool]>) {
    const PAGE: usize = PAGE_SIZE as usize;
    for (i, off) in (0..len).step_by(PAGE).enumerate() {
        if touched.is_some_and(|t| !t[i]) {
            continue;
        }
        let page = unsafe { std::slice::from_raw_parts(src.add(off), PAGE) };
        let (head, words, tail) = unsafe { page.align_to::<u64>() };
        let zero = head.iter().all(|&b| b == 0)
            && words.iter().all(|&w| w == 0)
            && tail.iter().all(|&b| b == 0);
        if !zero {
            unsafe { std::ptr::copy_nonoverlapping(src.add(off), dst.add(off), PAGE) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RW: u32 = prot::READ | prot::WRITE;

    fn mock_gpu(len: usize) -> Arc<dyn crate::gpu::Mapping> {
        struct MockGpu {
            base: NonNull<u8>,
            len: usize,
        }
        unsafe impl Send for MockGpu {}
        unsafe impl Sync for MockGpu {}
        unsafe impl crate::gpu::Mapping for MockGpu {
            fn base(&self) -> NonNull<u8> {
                self.base
            }
            fn size(&self) -> usize {
                self.len
            }
        }
        impl Drop for MockGpu {
            fn drop(&mut self) {
                // SAFETY: allocated by appine_hal::map_anonymous below.
                unsafe { appine_hal::unmap(self.base, self.len) };
            }
        }
        let base = appine_hal::map_anonymous(len, false).unwrap();
        Arc::new(MockGpu { base, len })
    }

    #[test]
    fn code_groups_register_only_consistent_mappings() {
        // Without Tier 1 support on the host there are no translations to share
        let Some(space) = appine_engine::DbtSpace::new(0, appine_engine::DbtRegs::Default) else {
            return;
        };
        let src = |start: u64, len: u64, ino: u64, offset: u64| appine_engine::DbtSource {
            start,
            len,
            id: [1, ino, offset, 7, 8],
        };
        let lib = 0x7000_0000;
        let group = CodeGroup {
            key: 1,
            space,
            members: Cell::new(1),
            ranges: RefCell::new(vec![src(lib, 0x22000, 5, 0)]),
            claims: RefCell::new(Vec::new()),
            memops: RefCell::new(Vec::new()),
            closed: Cell::new(false),
            shared: Cell::new(false),
        };
        let count = || group.ranges.borrow().len();
        // The dynamic linker maps the whole file first, then maps the later segments over it: the
        // same file with the same base, already covered
        assert!(group.extend(&[src(lib, 0x18000, 5, 0)]));
        // A later piece of the same file with the same base: consistent, so it is registered
        assert!(group.extend(&[src(lib + 0x30000, 0x1000, 5, 0x30000)]));
        assert_eq!(count(), 2);
        // Another file at the same address, another offset of the same file, another version of
        // the same file: all conflict and change nothing
        assert!(!group.extend(&[src(lib, 0x1000, 6, 0)]));
        assert!(!group.extend(&[src(lib + 0x1000, 0x1000, 5, 0)]));
        let mut other_version = src(lib, 0x1000, 5, 0);
        other_version.id[3] = 9;
        assert!(!group.extend(&[other_version]));
        // If one piece conflicts, none of the layout is registered
        assert!(!group.extend(&[src(0x9000_0000, 0x1000, 9, 0), src(lib, 0x1000, 6, 0)]));
        assert_eq!(count(), 2);
        // Ranges whose blocks stay when the last member leaves the group: ones consistent with the
        // registration and unregistered ones stay; registered addresses holding another file do
        // not (the blocks there were translated by other members)
        let (same, other, new) = (
            src(lib, 0x18000, 5, 0),
            src(lib + 0x30000, 0x1000, 6, 0x30000),
            src(0x9000_0000, 0x1000, 9, 0),
        );
        let kept: Vec<_> = group
            .consistent(&[same, other, new])
            .iter()
            .map(|s| (s.start, s.id[1]))
            .collect();
        assert_eq!(kept, [(lib, 5), (0x9000_0000, 9)]);
        // Disjoint new mappings are registered, and once registration is full no more are accepted
        let more: Vec<_> = (0..CodeGroup::MAX_RANGES as u64)
            .map(|i| src(0x1_0000_0000 + i * 0x10000, 0x1000, 100 + i, 0))
            .collect();
        assert!(!group.extend(&more));
        assert!(group.extend(&more[..CodeGroup::MAX_RANGES - 2]));
        assert_eq!(count(), CodeGroup::MAX_RANGES);
    }

    #[test]
    fn code_groups_keep_private_code_apart_from_registered_files() {
        let Some(space) = appine_engine::DbtSpace::new(0, appine_engine::DbtRegs::Default) else {
            return;
        };
        let src = |start: u64, len: u64, ino: u64| appine_engine::DbtSource {
            start,
            len,
            id: [1, ino, 0, 7, 8],
        };
        let lib = 0x7000_0000;
        let group = CodeGroup {
            key: 1,
            space,
            members: Cell::new(1),
            ranges: RefCell::new(vec![src(lib, 0x10000, 5)]),
            claims: RefCell::new(vec![(1, 0x9000_0000, 0x9010_0000)]),
            memops: RefCell::new(Vec::new()),
            closed: Cell::new(false),
            shared: Cell::new(false),
        };
        // Another member (tag 2) also has JIT code at the same address: private ranges may overlap
        // each other
        let jit = [(0x9000_0000, 0x9001_0000), (0xb000_0000, 0xb001_0000)];
        assert!(group.admit(2, &[src(lib, 0x10000, 5)], &jit));
        // JIT code over a registered file, or a file over another member's JIT code: both refused,
        // changing nothing
        assert!(!group.admit(2, &[], &[(lib + 0x8000, lib + 0x9000)]));
        assert!(!group.admit(2, &[src(0x9000_8000, 0x1000, 6)], &[]));
        assert_eq!(group.ranges.borrow().len(), 1);
        assert_eq!(group.claims.borrow().len(), 3);
        // A file now where it used to have JIT code: registered, with the new private ranges
        // installed
        assert!(group.admit(
            2,
            &[src(0xb000_0000, 0x1000, 6)],
            &[(0xa000_0000, 0xa000_1000)]
        ));
        assert_eq!(group.ranges.borrow().len(), 2);
        assert_eq!(
            *group.claims.borrow(),
            [(1, 0x9000_0000, 0x9010_0000), (2, 0xa000_0000, 0xa000_1000)]
        );
    }

    #[test]
    fn read_back_across_pages() {
        let mut mm = Mm::new();
        mm.map_anonymous(0x10000, 2 * PAGE_SIZE, RW).unwrap();
        let data: Vec<u8> = (0..100).collect();
        let addr = 0x10000 + PAGE_SIZE - 50;
        mm.write_kernel(addr, &data).unwrap();
        let mut back = vec![0; data.len()];
        mm.read(UserSlice::new(addr, data.len()), &mut back)
            .unwrap();
        assert_eq!(back, data);
        mm.write_kernel(addr, b"hello\0").unwrap();
        assert_eq!(mm.read_cstr(addr, 64).unwrap(), b"hello");
        assert_eq!(mm.read_cstr(addr, 3), Err(Errno::ENAMETOOLONG));
    }

    #[test]
    fn read_requires_mapping_and_permission() {
        let mut mm = Mm::new();
        mm.map_anonymous(0x10000, PAGE_SIZE, prot::EXEC).unwrap();
        let mut buf = [0u8; 8];
        assert_eq!(
            mm.read(UserSlice::new(0x10000, 8), &mut buf),
            Err(Errno::EFAULT)
        );
        assert_eq!(
            mm.read(UserSlice::new(0x20000, 8), &mut buf),
            Err(Errno::EFAULT)
        );
    }

    #[test]
    fn mmap_munmap_mprotect_split_vmas() {
        let mut mm = Mm::new();
        let a = mm
            .mmap(
                0,
                4 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        assert!(a + 4 * PAGE_SIZE <= mm.mmap_top);
        mm.write_kernel(a + 3 * PAGE_SIZE, b"tail").unwrap();

        // Punch out a page in the middle: both sides stay usable with their data intact; the host
        // memory is released only after the shootdown
        mm.munmap(a + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert!(std::mem::take(&mut mm.dirty));
        assert_eq!(mm.graveyard.len(), 1);
        // Almost the whole address space is unmapped: succeeds at once and does nothing
        mm.munmap(mmap_min(), a - mmap_min()).unwrap();
        assert!(!mm.dirty);
        assert_eq!(mm.vmas.len(), 2);
        assert!(mm.mmu().translate(a + PAGE_SIZE, 0).is_none());
        let mut buf = [0u8; 4];
        mm.read(UserSlice::new(a + 3 * PAGE_SIZE, 4), &mut buf)
            .unwrap();
        assert_eq!(&buf, b"tail");

        // mprotect across a hole fails; carve a read-only page out of a complete mapping
        assert_eq!(
            mm.mprotect(a, 3 * PAGE_SIZE, prot::READ),
            Err(Errno::ENOMEM)
        );
        mm.mprotect(a + 2 * PAGE_SIZE, PAGE_SIZE, prot::READ)
            .unwrap();
        assert!(mm.mmu().translate(a + 2 * PAGE_SIZE, prot::WRITE).is_none());
        assert!(mm.mmu().translate(a + 3 * PAGE_SIZE, prot::WRITE).is_some());
        assert_eq!(mm.vmas.len(), 3);

        // MAP_FIXED replaces existing mappings; NOREPLACE does not
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        assert_eq!(mm.mmap(a, 2 * PAGE_SIZE, RW, fixed, None).unwrap(), a);
        let noreplace = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED_NOREPLACE;
        assert_eq!(
            mm.mmap(a, PAGE_SIZE, RW, noreplace, None),
            Err(Errno::EEXIST)
        );
    }

    #[test]
    fn only_executable_changes_invalidate_translations() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let rx = prot::READ | prot::EXEC;
        let data = mm.mmap(0, 2 * PAGE_SIZE, RW, anon, None).unwrap();
        let code = mm.mmap(0, 2 * PAGE_SIZE, rx, anon, None).unwrap();
        // Changes to data pages need only a TLB flush
        mm.munmap(data, PAGE_SIZE).unwrap();
        mm.mprotect(data + PAGE_SIZE, PAGE_SIZE, prot::READ)
            .unwrap();
        mm.mprotect(code, PAGE_SIZE, rx).unwrap();
        assert!(std::mem::take(&mut mm.dirty) && mm.code_ranges.is_empty());
        // Only adding permissions: no TLB flush needed
        mm.mprotect(data + PAGE_SIZE, PAGE_SIZE, RW).unwrap();
        assert!(!mm.dirty);
        // A code page loses execute permission (before a W^X JIT rewrites code) or is torn down:
        // the translations of those pages must be invalidated
        mm.mprotect(code, PAGE_SIZE, RW).unwrap();
        assert_eq!(std::mem::take(&mut mm.code_ranges), [(code, PAGE_SIZE)]);
        mm.munmap(code + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(mm.code_ranges, [(code + PAGE_SIZE, PAGE_SIZE)]);
    }

    #[test]
    fn code_log_reports_missed_ranges() {
        let mut log = CodeLog::default();
        log.push(1, &[(0x1000, 0x1000)]);
        log.push(2, &[(0x5000, 0x2000), (0x9000, 0x1000)]);
        assert_eq!(log.since(0, 2).unwrap().len(), 3);
        assert_eq!(
            log.since(1, 2),
            Some(vec![(0x5000, 0x2000), (0x9000, 0x1000)])
        );
        // Ranges recorded after the generation read do not count
        assert_eq!(log.since(0, 1), Some(vec![(0x1000, 0x1000)]));
        let last = CodeLog::GENERATIONS + 36;
        for g in 3..=last {
            log.push(g, &[(g << 12, 0x1000)]);
        }
        // Records too old have been pushed out: only a full flush is possible
        assert_eq!(log.since(0, last), None);
        assert_eq!(log.since(last - 1, last), Some(vec![(last << 12, 0x1000)]));
    }

    #[test]
    fn fork_copies_private_and_shares_shared_mappings() {
        let mut mm = Mm::new();
        let private = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        let shared = mm
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_SHARED | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.write_kernel(private + PAGE_SIZE, b"parent").unwrap();
        let child = mm.fork().unwrap();
        let child = child.borrow();
        mm.write_kernel(private + PAGE_SIZE, b"PARENT").unwrap();
        mm.write_kernel(shared, b"both").unwrap();
        let mut buf = [0u8; 6];
        child
            .read(UserSlice::new(private + PAGE_SIZE, 6), &mut buf)
            .unwrap();
        assert_eq!(&buf, b"parent");
        child
            .read(UserSlice::new(shared, 4), &mut buf[..4])
            .unwrap();
        assert_eq!(&buf[..4], b"both");
        // Mappings are allocated top down: right above private is the upper bound of the mmap
        // area, with nothing mapped
        assert!(child.is_mapped(private) && !child.is_mapped(private + 2 * PAGE_SIZE));
    }

    #[test]
    fn usage_counts_shared_memory_once() {
        let mut mm = Mm::new();
        let private = mm
            .mmap(
                0,
                8 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        let shared = mm
            .mmap(
                0,
                4 * PAGE_SIZE,
                RW,
                flags::MAP_SHARED | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        for i in 0..8 {
            mm.write_kernel(private + i * PAGE_SIZE, b"p").unwrap();
        }
        for i in 0..4 {
            mm.write_kernel(shared + i * PAGE_SIZE, b"s").unwrap();
        }
        let usage = |spaces: &[&Mm]| {
            let mut u = Usage::default();
            for &mm in spaces {
                u.add(mm);
            }
            u.pages()
        };
        let alone = usage(&[&mm]);
        assert_eq!(alone, mm.resident_pages());
        assert!(alone >= 12);
        // After fork the child borrows the private pages and maps the same shared memory: each
        // process counts them, together they count once
        let child = mm.fork().unwrap();
        assert!(mm.resident_pages() + child.borrow().resident_pages() >= 2 * alone);
        assert_eq!(usage(&[&mm, &child.borrow()]), alone);
        // A page the child writes becomes its own copy, which counts as well
        child
            .borrow_mut()
            .write_kernel(private + 3 * PAGE_SIZE, b"c")
            .unwrap();
        assert_eq!(usage(&[&mm, &child.borrow()]), alone + 1);
    }

    #[test]
    fn fork_skips_only_never_written_anonymous_mappings() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        // A V8-style reservation: PROT_NONE plus MAP_NORESERVE, then part of it made writable
        let reserved = mm
            .mmap(0, 1 << 33, 0, anon | flags::MAP_NORESERVE, None)
            .unwrap();
        mm.mprotect(reserved, PAGE_SIZE, RW).unwrap();
        mm.write_kernel(reserved, b"heap").unwrap();
        // Permissions removed after writing: the contents remain, so fork must copy them
        let hidden = mm.mmap(0, PAGE_SIZE, RW, anon, None).unwrap();
        mm.write_kernel(hidden, b"kept").unwrap();
        mm.mprotect(hidden, PAGE_SIZE, 0).unwrap();
        // Mapped read-only like the loader does, then written by the kernel
        let text = mm.mmap(0, PAGE_SIZE, prot::READ, anon, None).unwrap();
        mm.write_kernel(text, b"code").unwrap();
        let child = mm.fork().unwrap();
        let mut child = child.borrow_mut();
        let mut buf = [0u8; 4];
        child.read(UserSlice::new(reserved, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"heap");
        child.read(UserSlice::new(text, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"code");
        // PROT_NONE pages are not in the page table, and the contents are still there once
        // permissions are added back
        assert!(child.mmu().translate(hidden, 0).is_none());
        assert!(child.mmu().translate(reserved + PAGE_SIZE, 0).is_none());
        child.mprotect(hidden, PAGE_SIZE, prot::READ).unwrap();
        child.read(UserSlice::new(hidden, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"kept");
        assert!(!child.vmas[&(reserved + PAGE_SIZE)].written.get());
    }

    #[test]
    fn fill_reads_ahead_after_pages_read() {
        let host = appine_hal::memfd(c"appine-mm-fill").unwrap();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let f = Fill::new(host, 2048 * PAGE_SIZE, source);
        let window = |page: u64| {
            let (off, len) = f.window(page).unwrap();
            f.store((off, len), &vec![0u8; len as usize], false)
                .unwrap();
            (off / PAGE_SIZE, len / PAGE_SIZE)
        };
        // Around the first fault, then twice as much where it ended
        assert_eq!(window(0), (0, 32));
        assert_eq!(window(32), (32, 64));
        assert_eq!(window(500), (484, 32));
        // Right after 96 pages read: twice that, though the last read was elsewhere
        assert_eq!(window(96), (96, 192));
        // Up to the pages read further on
        assert_eq!(window(288), (288, 196));
        assert_eq!(window(1000), (984, 32));
        assert_eq!(f.window(100), None);
        assert_eq!(f.window(2048), None);
    }

    #[test]
    fn mapped_writeback_acknowledges_only_the_bytes_sent() {
        use std::os::unix::fs::FileExt;
        let host = appine_hal::memfd(c"appine-fill-writeback").unwrap();
        host.set_len(4).unwrap();
        let pages = FillPages::new(host, 4);
        pages.store((0, PAGE_SIZE), b"abcd", false).unwrap();
        pages.track(0, 1).unwrap();
        pages.host.write_all_at(b"ABCD", 0).unwrap();
        let sent = pages.dirty_runs(0).unwrap();
        assert_eq!(sent, [(0, b"ABCD".to_vec())]);
        // A short reply, with another mapped store while the request was outstanding.
        pages.host.write_all_at(b"X", 0).unwrap();
        pages.acknowledge(0, &sent[0].1[..2]);
        let mut daemon = *b"ABcd";
        pages.overlay(0, &mut daemon).unwrap();
        assert_eq!(&daemon, b"XBCD");
        let retry = pages.dirty_runs(0).unwrap();
        assert_eq!(retry, [(0, b"X".to_vec()), (2, b"CD".to_vec())]);
        for (offset, bytes) in retry {
            pages.acknowledge(offset, &bytes);
        }
        assert!(pages.dirty_runs(0).unwrap().is_empty());
        // Ordinary reads retain a fresh daemon reply for clean bytes.
        let mut external = *b"1234";
        pages.overlay(0, &mut external).unwrap();
        assert_eq!(&external, b"1234");
    }

    #[test]
    fn invalidated_pages_merge_pending_stores_with_short_refills() {
        use std::os::unix::fs::FileExt;
        let host = appine_hal::memfd(c"appine-fill-invalidate").unwrap();
        let size = 3 * PAGE_SIZE;
        host.set_len(size).unwrap();
        let pages = FillPages::new(host, size);
        pages
            .store((0, size), &vec![1; size as usize], false)
            .unwrap();
        pages.track(1, 2).unwrap();
        pages.host.write_all_at(b"abcdef", PAGE_SIZE).unwrap();
        pages.invalidate(1, 2);
        assert_eq!(pages.runs(0, 3), [(0, 1), (2, 3)]);
        // A descriptor write and a hole supersede local stores even while the page is stale.
        pages.written(PAGE_SIZE + 1, b"B").unwrap();
        pages.punch(PAGE_SIZE + 2, PAGE_SIZE + 3).unwrap();
        pages.store((PAGE_SIZE, PAGE_SIZE), b"XB", true).unwrap();
        let mut merged = [0; 8];
        pages.host.read_exact_at(&mut merged, PAGE_SIZE).unwrap();
        assert_eq!(&merged, b"aB\0def\0\0");
        assert_eq!(
            pages.dirty_runs(1).unwrap(),
            [(PAGE_SIZE, b"a".to_vec()), (PAGE_SIZE + 3, b"def".to_vec()),]
        );
        assert_eq!(pages.runs(0, 3), [(0, 3)]);
    }

    #[test]
    fn fill_short_read_records_only_complete_pages() {
        let size = 16 * PAGE_SIZE;
        let host = appine_hal::memfd(c"appine-mm-fill-short").unwrap();
        host.set_len(size).unwrap();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let f = Fill::new(host, size, source);
        let window = f.window(0).unwrap();
        assert_eq!(window, (0, 16 * PAGE_SIZE));
        // Short reply (2 pages + 500 bytes, not at EOF): only pages 0 and 1 become filled
        let short = vec![0x42u8; (2 * PAGE_SIZE + 500) as usize];
        f.store(window, &short, false).unwrap();
        assert!(f.has(0));
        assert!(f.has(1));
        assert!(!f.has(2));
        assert!(!f.has(15));
        assert_eq!(f.window_from(2), Some((2 * PAGE_SIZE, 14 * PAGE_SIZE)));
        // Partial-page reply with confirmed EOF marks only that page, not the rest of the window
        f.store((2 * PAGE_SIZE, 14 * PAGE_SIZE), &[0x77u8; 100], true)
            .unwrap();
        assert!(f.has(2));
        assert!(!f.has(3));
    }

    #[test]
    fn mremap_updates_shm_base_and_vdso_address() {
        let mut mm = Mm::new();
        let mem = SharedMemory::new(PAGE_SIZE).unwrap();
        let a = mm.attach_shm(None, &mem, RW, false, (1, 7)).unwrap();
        let dst = a - 4 * PAGE_SIZE;
        let moved = mm
            .mremap(a, PAGE_SIZE, 2 * PAGE_SIZE, true, Some(dst))
            .unwrap();
        assert_eq!(moved, dst);
        assert_eq!(mm.fault_past_eof(dst + PAGE_SIZE, prot::READ), Some(true));
        assert_eq!(mm.shm_attachments((1, 7)), 1);
        assert_eq!(mm.detach_shm(a), Err(Errno::EINVAL));
        assert_eq!(mm.detach_shm(dst), Ok((1, 7)));
        assert!(!mm.is_mapped(dst + PAGE_SIZE));

        let vdso_len = (crate::vdso::image().len() as u64).next_multiple_of(PAGE_SIZE);
        let v0 = mm
            .mmap(
                0,
                vdso_len,
                prot::READ | prot::EXEC,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.vdso = v0;
        let v1 = v0 - 4 * vdso_len;
        assert_eq!(
            mm.mremap(v0, vdso_len, vdso_len, true, Some(v1)).unwrap(),
            v1
        );
        assert_eq!(mm.vdso, v1);
        assert!(
            mm.regions()
                .iter()
                .any(|r| r.start == v1 && r.name.as_deref() == Some(b"[vdso]".as_slice()))
        );
        mm.munmap(v1, vdso_len).unwrap();
        assert_eq!(mm.vdso, 0);
    }

    #[test]
    fn prefill_pages_preserves_existing_entries_on_failure() {
        let mut mm = Mm::new();
        let a = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.write(UserSlice::new(a, 4), b"keep").unwrap();
        mm.mprotect(a, 2 * PAGE_SIZE, 0).unwrap();
        // Simulate a failing prefill (unaligned host pointer returns EINVAL from fill_shared)
        let bad_host = NonNull::dangling();
        Mm::prefill_pages(&mut mm.mmu, a, bad_host, 2 * PAGE_SIZE, RW, false);
        // Existing prot-0 entry must still be in the page table (protect updates only present entries)
        mm.mmu
            .protect(a, 2 * PAGE_SIZE, appine_engine::prot::READ)
            .unwrap();
        assert!(mm.mmu().translate(a, appine_engine::prot::READ).is_some());
        mm.mprotect(a, 2 * PAGE_SIZE, prot::READ).unwrap();
        let mut buf = [0u8; 4];
        mm.read(UserSlice::new(a, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"keep");
    }

    #[test]
    fn pagemap_marks_cow_lent_pages_non_exclusive() {
        const PRESENT: u64 = 1 << 63;
        const EXCLUSIVE: u64 = 1 << 56;
        let parent = Mm::new().into_shared();
        let a = parent
            .borrow_mut()
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        parent
            .borrow()
            .write(UserSlice::new(a, 4), b"abcd")
            .unwrap();
        assert_eq!(parent.borrow().pagemap(a, 1)[0], PRESENT | EXCLUSIVE);
        let child = parent.borrow_mut().fork().unwrap();
        // While lent to child, parent's pagemap entry must not report EXCLUSIVE
        let entry = parent.borrow().pagemap(a, 1)[0];
        assert_eq!(entry & PRESENT, PRESENT);
        assert_eq!(entry & EXCLUSIVE, 0);
        // Once child breaks CoW (writes its own copy), parent's page is exclusive again
        child.borrow().write(UserSlice::new(a, 4), b"wxyz").unwrap();
        assert_eq!(parent.borrow().pagemap(a, 1)[0], PRESENT | EXCLUSIVE);
    }

    #[test]
    fn remapped_fuse_pages_keep_the_daemon_offset() {
        let size = 2 * PAGE_SIZE;
        let host = appine_hal::memfd(c"appine-mm-fill").unwrap();
        host.set_len(size).unwrap();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let fill = Fill::new(host, size, source);
        let mut mm = Mm::new();
        let a = mm
            .mmap_fill(0, PAGE_SIZE, prot::READ, flags::MAP_SHARED, (fill, 0))
            .unwrap();
        mm.label(a, PAGE_SIZE, None, 42);
        mm.remap_file_pages(a, PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(mm.fill_wanted(a, prot::READ).unwrap().1, 1);
    }

    #[test]
    fn mappings_read_on_demand_map_only_pages_read() {
        let size = 100 * PAGE_SIZE + 100;
        let host = appine_hal::memfd(c"appine-mm-fill").unwrap();
        host.set_len(size).unwrap();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let fill = Fill::new(host, size, source);
        // The daemon's part: file page p holds p + 1
        let read = |f: &Fill, page: u64| {
            let (off, len) = f.window(page).unwrap();
            let mut data: Vec<u8> = (off / PAGE_SIZE..(off + len) / PAGE_SIZE)
                .flat_map(|p| [(p + 1) as u8; PAGE_SIZE as usize])
                .collect();
            data.truncate((size - off).min(len) as usize);
            f.store((off, len), &data, false).unwrap();
        };
        let mut mm = Mm::new();
        let len = 103 * PAGE_SIZE;
        let a = mm
            .mmap_fill(0, len, RW, flags::MAP_PRIVATE, (fill.clone(), 0))
            .unwrap();
        // Nothing has entries yet; a kernel access asks for the page it needs
        assert!(!mm.fault_in(a + 50 * PAGE_SIZE, prot::READ));
        let mut b = [0u8; 6];
        let at = |p: u64| UserSlice::new(a + p * PAGE_SIZE, 6);
        assert_eq!(mm.read(at(50), &mut b), Err(Errno::FUSE_RETRY));
        let (f, page) = take_wanted().unwrap();
        assert_eq!(page, 50);
        // Read-around: 32 pages centred on the fault
        assert_eq!(f.window(50), Some((34 * PAGE_SIZE, 32 * PAGE_SIZE)));
        read(&f, 50);
        mm.read(at(50), &mut b).unwrap();
        assert_eq!(b, [51; 6]);
        assert!(mm.fill_wanted(a + 65 * PAGE_SIZE, prot::READ).is_none());
        assert_eq!(
            mm.fill_wanted(a + 66 * PAGE_SIZE, prot::READ).unwrap().1,
            66
        );
        // A fault where the last read ended reads twice as much, up to the end of the file
        assert_eq!(fill.window(66), Some((66 * PAGE_SIZE, 35 * PAGE_SIZE)));
        read(&fill, 66);
        mm.read(UserSlice::new(a + 100 * PAGE_SIZE + 95, 6), &mut b)
            .unwrap();
        assert_eq!(b, [101, 101, 101, 101, 101, 0]);
        // Past the end of the file there is nothing to read: SIGBUS
        assert!(mm.fill_wanted(a + 101 * PAGE_SIZE, prot::READ).is_none());
        assert_eq!(
            mm.fault_past_eof(a + 101 * PAGE_SIZE, prot::READ),
            Some(true)
        );
        assert_eq!(mm.fault_past_eof(a + 10 * PAGE_SIZE, prot::READ), None);
        // Writes stay private and fork copies them; what either side reads reaches both
        mm.write(at(40), b"parent").unwrap();
        let child = mm.fork().unwrap();
        child.borrow().read(at(40), &mut b).unwrap();
        assert_eq!(&b, b"parent");
        assert_eq!(child.borrow().read(at(10), &mut b), Err(Errno::FUSE_RETRY));
        read(&take_wanted().unwrap().0, 10);
        child.borrow().read(at(10), &mut b).unwrap();
        assert_eq!(b, [11; 6]);
        mm.read(at(10), &mut b).unwrap();
        assert_eq!(b, [11; 6]);
        child.borrow().write(at(41), b"child!").unwrap();
        mm.read(at(41), &mut b).unwrap();
        assert_eq!(b, [42; 6]);
        // MADV_DONTNEED brings back what was read
        assert!(
            mm.discard(a + 40 * PAGE_SIZE, PAGE_SIZE)
                .unwrap()
                .is_empty()
        );
        mm.read(at(40), &mut b).unwrap();
        assert_eq!(b, [41; 6]);
        child.borrow().read(at(40), &mut b).unwrap();
        assert_eq!(&b, b"parent");
        // Grown by mremap, it goes on reading the same file
        let moved = mm
            .mremap(a + 90 * PAGE_SIZE, PAGE_SIZE, 8 * PAGE_SIZE, true, None)
            .unwrap();
        mm.read(UserSlice::new(moved + 5 * PAGE_SIZE, 6), &mut b)
            .unwrap();
        assert_eq!(b, [96; 6]);
        // A kernel write into a page not read asks for it first
        assert_eq!(
            mm.write_kernel(a + 33 * PAGE_SIZE, b"x"),
            Err(Errno::FUSE_RETRY)
        );
        assert_eq!(take_wanted().unwrap().1, 33);
    }

    #[test]
    fn private_store_mapping_keeps_its_pin_after_an_unpinned_elf_mapping() {
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("appine-mapping-pin-{}", std::process::id()));
        let object = std::fs::File::create_new(&path).unwrap();
        let pin = std::fs::File::open(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        object.set_len(PAGE_SIZE).unwrap();
        let mut mm = Mm::new();
        mm.mmap(
            0,
            PAGE_SIZE,
            prot::READ,
            flags::MAP_PRIVATE,
            Some((object.as_raw_fd(), 0, false)),
        )
        .unwrap();
        appine_hal::flock(pin.as_raw_fd(), false, true).unwrap();
        let addr = mm
            .map(
                0,
                PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((pin.as_raw_fd(), 0, false)),
                Some(FileSource::PinnedStore),
            )
            .unwrap();
        drop(pin);
        let child = mm.fork().unwrap();
        mm.munmap(addr, PAGE_SIZE).unwrap();
        assert_eq!(
            appine_hal::flock(object.as_raw_fd(), true, false),
            Err(libc::EWOULDBLOCK)
        );
        child.borrow_mut().munmap(addr, PAGE_SIZE).unwrap();
        mm.sync_except(None);
        child.borrow_mut().sync_except(None);
        appine_hal::flock(object.as_raw_fd(), true, false).unwrap();
    }

    #[test]
    fn fork_never_reads_private_file_mappings_past_the_end() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("appine-mm-{}", std::process::id()));
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(&[7u8; 5000]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let mut mm = Mm::new();
        // Map 3 pages of a file of only 5000 bytes: the last page lies entirely past the end of the
        // file, and touching it is SIGBUS
        let ro = mm
            .mmap(
                0,
                3 * PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, false)),
            )
            .unwrap();
        let rw = mm
            .mmap(
                0,
                3 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, false)),
            )
            .unwrap();
        mm.write_kernel(rw, b"parent").unwrap();
        let child = mm.fork().unwrap();
        let mut child = child.borrow_mut();
        let mut b = [0u8; 6];
        child
            .read(UserSlice::new(ro + 4000, 1), &mut b[..1])
            .unwrap();
        assert_eq!(b[0], 7);
        child.read(UserSlice::new(rw, 6), &mut b).unwrap();
        assert_eq!(&b, b"parent");
        // A shared read-only mapping copies first before becoming writable: the parent writes and
        // the child does not see it
        mm.mprotect(ro, PAGE_SIZE, RW).unwrap();
        mm.write(UserSlice::new(ro, 1), &[1]).unwrap();
        child.read(UserSlice::new(ro, 1), &mut b[..1]).unwrap();
        assert_eq!(b[0], 7);
        // Pages past the end of the file are not in the page table, and stay so after the copy
        for m in [&mut mm, &mut child] {
            for base in [ro, rw] {
                assert!(m.mmu().translate(base + PAGE_SIZE, prot::READ).is_some());
                assert!(m.mmu().translate(base + 2 * PAGE_SIZE, 0).is_none());
                assert_eq!(
                    m.fault_past_eof(base + 2 * PAGE_SIZE, prot::READ),
                    Some(true)
                );
                assert_eq!(m.fault_past_eof(base + PAGE_SIZE, prot::READ), None);
            }
        }
        // An executable file mapping gets its entries at once, but only up to the end of the file:
        // a 1 GB mapping has only two pages
        let exec = mm
            .mmap(
                0,
                1 << 30,
                prot::READ | prot::EXEC,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert!(mm.mmu().translate(exec + PAGE_SIZE, prot::EXEC).is_some());
        let end = exec + (1 << 30);
        assert_eq!(mm.mmu().next_present(exec + 2 * PAGE_SIZE, end), end);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn fork_keeps_clean_file_pages_and_same_value_private_writes() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        let page = appine_hal::page_size() as u64;
        let path = std::env::temp_dir().join(format!("appine-fork-clean-{}", std::process::id()));
        let f = std::fs::File::create_new(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        f.set_len(3 * page).unwrap();
        for readonly in [false, true] {
            f.write_all_at(b"A", page).unwrap();
            f.write_all_at(b"A", 2 * page).unwrap();
            let mut parent = Mm::new();
            let addr = parent
                .mmap(
                    0,
                    2 * page,
                    RW,
                    flags::MAP_PRIVATE,
                    Some((f.as_raw_fd(), page, true)),
                )
                .unwrap();
            // Split a host page into two VMAs before the first private write.
            if page > PAGE_SIZE {
                f.write_all_at(b"S", page + PAGE_SIZE).unwrap();
                parent
                    .mprotect(addr + PAGE_SIZE, PAGE_SIZE, prot::READ)
                    .unwrap();
            }
            parent.write(UserSlice::new(addr, 1), b"A").unwrap();
            if page > PAGE_SIZE {
                f.write_all_at(b"T", page + PAGE_SIZE).unwrap();
            }
            if readonly {
                parent.mprotect(addr, 2 * page, prot::READ).unwrap();
            }
            let child = parent.fork().unwrap();
            let mut child = child.borrow_mut();
            if readonly {
                child.mprotect(addr, 2 * page, RW).unwrap();
            }
            if page > PAGE_SIZE {
                let mut value = [0];
                child
                    .read(UserSlice::new(addr + PAGE_SIZE, 1), &mut value)
                    .unwrap();
                assert_eq!(value, *b"S");
            }
            f.write_all_at(b"B", page).unwrap();
            f.write_all_at(b"B", 2 * page).unwrap();
            for (offset, expected) in [(0, b'A'), (page, b'B')] {
                let mut value = [0];
                child
                    .read(UserSlice::new(addr + offset, 1), &mut value)
                    .unwrap();
                assert_eq!(value[0], expected);
            }
        }
    }

    #[test]
    fn private_file_growth_after_fork_preserves_private_data() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::FileExt;
        let path = std::env::temp_dir().join(format!("appine-private-eof-{}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(path).unwrap();
        f.set_len(PAGE_SIZE).unwrap();
        let mut mm = Mm::new();
        let a = mm
            .mmap(
                0,
                3 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        let b = mm
            .mmap(
                0,
                PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert!(Rc::ptr_eq(
            &mm.vmas[&a].file.as_ref().unwrap().0,
            &mm.vmas[&b].file.as_ref().unwrap().0
        ));
        mm.write_kernel(a, b"p").unwrap();
        let child = mm.fork().unwrap();
        f.write_at(b"g", PAGE_SIZE).unwrap();
        drop(f);
        assert!(mm.grow_for(a, PAGE_SIZE as usize + 1, u64::MAX));
        assert_eq!(
            child.borrow_mut().fault_past_eof(a + PAGE_SIZE, prot::READ),
            Some(false)
        );
        for m in [&mut mm, &mut *child.borrow_mut()] {
            for (addr, byte) in [(a, b'p'), (a + PAGE_SIZE, b'g')] {
                let mut data = [0];
                m.read(UserSlice::new(addr, 1), &mut data).unwrap();
                assert_eq!(data, [byte]);
            }
            m.write_kernel(a + PAGE_SIZE, b"x").unwrap();
            assert_eq!(m.fault_past_eof(a + 2 * PAGE_SIZE, prot::READ), Some(true));
        }
    }

    #[test]
    fn shared_file_mappings_follow_the_end_of_the_file() {
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("appine-eof-{}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.set_len(100).unwrap();
        let mut mm = Mm::new();
        let a = mm
            .mmap(
                0,
                4 * PAGE_SIZE,
                RW,
                flags::MAP_SHARED,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        assert!(mm.mmu().translate(a, prot::WRITE).is_some());
        assert!(mm.mmu().translate(a + PAGE_SIZE, 0).is_none());
        assert_eq!(mm.fault_past_eof(a + PAGE_SIZE, prot::WRITE), Some(true));
        // After the file grows, accessing the new part only needs re-execution
        f.set_len(2 * PAGE_SIZE + 1).unwrap();
        assert_eq!(
            mm.fault_past_eof(a + 2 * PAGE_SIZE, prot::WRITE),
            Some(false)
        );
        assert!(mm.mmu().translate(a + 2 * PAGE_SIZE, prot::WRITE).is_some());
        assert_eq!(
            mm.fault_past_eof(a + 3 * PAGE_SIZE, prot::WRITE),
            Some(true)
        );
        // An address outside every mapping is left to ordinary SIGSEGV handling
        assert_eq!(mm.fault_past_eof(a + 4 * PAGE_SIZE, prot::WRITE), None);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncation_removes_pages_past_the_new_end() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let path = std::env::temp_dir().join(format!("appine-trunc-{}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.set_len(3 * PAGE_SIZE).unwrap();
        let mut mm = Mm::new();
        let file = |shared| Some((f.as_raw_fd(), 0, shared));
        let shared = mm
            .mmap(0, 3 * PAGE_SIZE, RW, flags::MAP_SHARED, file(true))
            .unwrap();
        let private = mm
            .mmap(
                0,
                3 * PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE,
                file(false),
            )
            .unwrap();
        let hidden = mm
            .mmap(0, 3 * PAGE_SIZE, 0, flags::MAP_PRIVATE, file(false))
            .unwrap();
        let meta = f.metadata().unwrap();
        // Another file getting shorter does not affect these mappings
        assert!(!mm.file_truncated(meta.dev(), meta.ino() + 1, 0));
        f.set_len(PAGE_SIZE + 10).unwrap();
        assert!(mm.file_truncated(meta.dev(), meta.ino(), PAGE_SIZE + 10));
        for a in [shared, private] {
            // The page containing the end of the file stays, and the pages after it get SIGBUS on
            // access
            assert!(mm.mmu().translate(a + PAGE_SIZE, prot::READ).is_some());
            assert!(mm.mmu().translate(a + 2 * PAGE_SIZE, 0).is_none());
            assert_eq!(mm.fault_past_eof(a + 2 * PAGE_SIZE, prot::READ), Some(true));
        }
        // A mapping without permissions made readable also gets only the pages before the end of
        // the file
        mm.mprotect(hidden, 3 * PAGE_SIZE, prot::READ).unwrap();
        assert!(mm.mmu().translate(hidden + PAGE_SIZE, prot::READ).is_some());
        assert!(mm.mmu().translate(hidden + 2 * PAGE_SIZE, 0).is_none());
        // Truncating again to the same length changes nothing; after a shared mapping's file grows
        // it can be accessed further
        assert!(!mm.file_truncated(meta.dev(), meta.ino(), PAGE_SIZE + 10));
        f.set_len(3 * PAGE_SIZE).unwrap();
        assert_eq!(
            mm.fault_past_eof(shared + 2 * PAGE_SIZE, prot::READ),
            Some(false)
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn prot_none_stays_out_of_the_page_table() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_NORESERVE;
        // The size V8 reserves for one wasm memory: not a single page enters the page table
        let a = mm.mmap(0, 1 << 33, 0, anon, None).unwrap();
        let page = a + (1 << 32);
        assert!(mm.mmu().translate(page, 0).is_none());
        mm.mprotect(page, PAGE_SIZE, RW).unwrap();
        mm.write(UserSlice::new(page, 2), b"hi").unwrap();
        assert!(mm.mmu().translate(page + PAGE_SIZE, 0).is_none());
        // Remove permissions and add them back: the contents remain
        mm.mprotect(page, PAGE_SIZE, 0).unwrap();
        assert!(mm.mmu().translate(page, 0).is_none());
        mm.mprotect(page, PAGE_SIZE, prot::READ).unwrap();
        let mut buf = [0u8; 2];
        mm.read(UserSlice::new(page, 2), &mut buf).unwrap();
        assert_eq!(&buf, b"hi");
        // Kernel writes ignore the page table: pages without permissions can be written too
        mm.write_kernel(a, b"k").unwrap();
        mm.munmap(a, 1 << 33).unwrap();
        assert!(mm.mmu().translate(page, 0).is_none());
    }

    /// 39-bit host address space (HostRegion::reserved): PROT_NONE reservations take no host
    /// memory; only the parts that became accessible or were written by the kernel have some; fork,
    /// mincore, pagemap, mremap growth and discarding leave them alone.
    #[test]
    fn prot_none_reservations_take_no_host_memory() {
        let mm = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        // V8's sandbox: 1 TB
        let len = 1 << 40;
        let a = mm.borrow_mut().mmap(0, len, 0, anon, None).unwrap();
        let backed = |m: &Rc<RefCell<Mm>>| -> Vec<(u64, u64)> {
            m.borrow()
                .vmas
                .iter()
                .filter(|(_, v)| !v.reserved())
                .map(|(&s, v)| (s, v.len))
                .collect()
        };
        assert!(mm.borrow().vmas[&a].reserved());
        // Two pages in the middle become writable: only they have host memory
        let p = a + (1 << 39);
        mm.borrow_mut().mprotect(p, 2 * PAGE_SIZE, RW).unwrap();
        assert_eq!(backed(&mm), [(p, 2 * PAGE_SIZE)]);
        poke(&mm, p + 1, b'p');
        assert_eq!(byte(&mm, p + 1), b'p');
        // No contents, not resident
        let m = mm.borrow();
        assert_eq!(m.residency(a, 4 * PAGE_SIZE).unwrap(), [false; 4]);
        assert_eq!(m.pagemap(a, 2), [0, 0]);
        assert_eq!(m.resident_in(a, len), 1);
        drop(m);
        mm.borrow_mut().discard(a, p - a).unwrap();
        // The kernel writes into a page without permissions (PTRACE_POKEDATA): only the page
        // written gets host memory
        let q = a + 5 * PAGE_SIZE + 3;
        mm.borrow_mut().write_kernel(q, b"q").unwrap();
        assert_eq!(
            backed(&mm),
            [(a + 5 * PAGE_SIZE, PAGE_SIZE), (p, 2 * PAGE_SIZE)]
        );
        // fork: still only a reservation in the child, and what was written is still visible
        let child = mm.borrow_mut().fork().unwrap();
        assert_eq!(backed(&child).len(), 2);
        assert_eq!(byte(&child, p + 1), b'p');
        child
            .borrow_mut()
            .mprotect(q & !(PAGE_SIZE - 1), PAGE_SIZE, prot::READ)
            .unwrap();
        assert_eq!(byte(&child, q), b'q');
        // mremap grows a reservation in place: the added part is only a reservation too
        let r = 1 << 41;
        let fixed = anon | flags::MAP_FIXED;
        mm.borrow_mut().mmap(r, PAGE_SIZE, 0, fixed, None).unwrap();
        assert_eq!(
            mm.borrow_mut().mremap(r, PAGE_SIZE, 1 << 30, false, None),
            Ok(r)
        );
        assert!(mm.borrow().vmas[&r].reserved());
        assert_eq!(mm.borrow().vmas[&r].len, 1 << 30);
        assert_eq!(backed(&mm).len(), 2);
        mm.borrow_mut().munmap(r, 1 << 30).unwrap();
        mm.borrow_mut().munmap(a, len).unwrap();
        assert!(mm.borrow().vmas.is_empty());
        assert_eq!(byte(&child, p + 1), b'p');
    }

    #[test]
    fn growsdown_mappings_grow_until_the_guard_gap() {
        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let base = 0x4000_0000;
        let top = base + 1024 * PAGE_SIZE;
        mm.mmap(top - PAGE_SIZE, PAGE_SIZE, RW, fixed, None)
            .unwrap();
        mm.set_growsdown(top - PAGE_SIZE);
        // Access an address a few pages below: it grows all the way there, and the grown part can
        // keep growing
        assert!(mm.grow_down(top - 5 * PAGE_SIZE + 8, u64::MAX));
        mm.write(UserSlice::new(top - 5 * PAGE_SIZE, 2), b"ok")
            .unwrap();
        assert!(mm.grow_down(top - 6 * PAGE_SIZE, u64::MAX));
        // No growth at an address already mapped, or below a mapping that does not grow down
        assert!(!mm.grow_down(top - 6 * PAGE_SIZE, u64::MAX));
        mm.mmap(base, PAGE_SIZE, RW, fixed, None).unwrap();
        assert!(!mm.grow_down(base - PAGE_SIZE, u64::MAX));
        // Less than 256 pages from the mapping below: no growth; it does not count when it is
        // PROT_NONE
        let guard_end = base + PAGE_SIZE + STACK_GUARD_GAP;
        assert!(!mm.grow_down(guard_end - PAGE_SIZE, u64::MAX));
        mm.mprotect(base, PAGE_SIZE, 0).unwrap();
        assert!(mm.grow_down(guard_end - PAGE_SIZE, u64::MAX));
        // After fork it grows in the child as well
        let child = mm.fork().unwrap();
        let mut child = child.borrow_mut();
        assert!(child.grow_down(guard_end - 2 * PAGE_SIZE, u64::MAX));
    }

    fn prot_at(mm: &Mm, addr: u64) -> u32 {
        mm.vmas.range(..=addr).next_back().unwrap().1.prot
    }

    /// Around a grows-down mapping as on Linux: a kernel access below it grows it; mprotect with
    /// `PROT_GROWSDOWN` reaches down to the bottom of the mapping it grew into and stops at a part
    /// with other permissions, and is EINVAL on a mapping that does not grow down; a hint in the
    /// guard gap below it is not taken.
    #[test]
    fn growsdown_mappings_behave_as_one_vma() {
        const PROT_GROWSDOWN: u32 = 0x0100_0000;
        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let low = 0x4000_0000 + 1024 * PAGE_SIZE;
        mm.mmap(low, 2 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.set_growsdown(low);
        assert!(mm.grow_for(low - 3 * PAGE_SIZE, 8, u64::MAX));
        assert!(!mm.grow_for(low - 3 * PAGE_SIZE, 8, u64::MAX));
        mm.mprotect(low - 2 * PAGE_SIZE, PAGE_SIZE, prot::READ)
            .unwrap();
        mm.protect(low, PAGE_SIZE, prot::READ, PROT_GROWSDOWN, false)
            .unwrap();
        let prots: Vec<u32> = (-3..2)
            .map(|i: i64| prot_at(&mm, low.wrapping_add_signed(i * PAGE_SIZE as i64)))
            .collect();
        let r = prot::READ;
        assert_eq!(prots, [RW, r, r, r, RW]);
        let other = mm.mmap(0x1000_0000, PAGE_SIZE, RW, fixed, None).unwrap();
        assert_eq!(
            mm.protect(other, PAGE_SIZE, r, PROT_GROWSDOWN, false),
            Err(Errno::EINVAL)
        );
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let hint = low - 3 * PAGE_SIZE - 16 * PAGE_SIZE;
        assert_ne!(mm.mmap(hint, PAGE_SIZE, RW, anon, None), Ok(hint));
    }

    /// mprotect changes the VMAs in turn and stops at the first one that refuses, leaving the ones
    /// before it changed, as Linux does.
    #[test]
    fn mprotect_keeps_what_it_changed_before_an_error() {
        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let a = 0x100000;
        for i in 0..3 {
            mm.mmap(a + i * PAGE_SIZE, PAGE_SIZE, 0, fixed, None)
                .unwrap();
        }
        mm.deny_write(a + PAGE_SIZE, PAGE_SIZE);
        assert_eq!(mm.mprotect(a, 3 * PAGE_SIZE, RW), Err(Errno::EACCES));
        assert_eq!(
            [0, 1, 2].map(|i| prot_at(&mm, a + i * PAGE_SIZE)),
            [RW, 0, 0]
        );
        mm.munmap(a + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            mm.mprotect(a, 3 * PAGE_SIZE, prot::READ),
            Err(Errno::ENOMEM)
        );
        assert_eq!(
            [0, 2].map(|i| prot_at(&mm, a + i * PAGE_SIZE)),
            [prot::READ, 0]
        );
    }

    /// After fork the child's VMAs with contents of their own no longer join their neighbours in
    /// maps (on Linux each has its own anon_vma), while the parent's pieces join again.
    #[test]
    fn forked_mappings_stay_apart_in_the_child() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 3 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        parent.borrow().write(UserSlice::new(a, 1), b"x").unwrap();
        parent
            .borrow_mut()
            .mprotect(a + PAGE_SIZE, PAGE_SIZE, prot::READ)
            .unwrap();
        let child = parent.borrow_mut().fork().unwrap();
        let entries = |mm: &Rc<RefCell<Mm>>| {
            mm.borrow_mut()
                .mprotect(a + PAGE_SIZE, PAGE_SIZE, RW)
                .unwrap();
            let r = mm.borrow().regions();
            r.iter()
                .filter(|r| r.start >= a && r.end <= a + 3 * PAGE_SIZE)
                .count()
        };
        assert_eq!(entries(&parent), 1);
        assert_eq!(entries(&child), 3);
    }

    #[test]
    fn stack_grows_in_place_until_its_reservation_runs_out() {
        let mut mm = Mm::new();
        mm.map_stack(2 * PAGE_SIZE, 16 * PAGE_SIZE).unwrap();
        mm.set_start_stack(STACK_TOP - 16);
        mm.write(UserSlice::new(STACK_TOP - 4, 4), b"top!").unwrap();
        // Within the reserved range: still the same VMA, with the old contents unchanged
        assert!(mm.grow_down(STACK_TOP - 10 * PAGE_SIZE + 100, u64::MAX));
        assert_eq!(mm.vmas.len(), 1);
        assert_eq!(mm.stack_low(), STACK_TOP - 10 * PAGE_SIZE);
        mm.write(UserSlice::new(STACK_TOP - 10 * PAGE_SIZE, 2), b"lo")
            .unwrap();
        let mut buf = [0u8; 4];
        mm.read(UserSlice::new(STACK_TOP - 4, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"top!");
        assert!(mm.grow_down(STACK_TOP - 16 * PAGE_SIZE, u64::MAX));
        assert_eq!(mm.vmas.len(), 1);
        // Beyond the reservation: a new piece, reserving below it as much as the stack again, then
        // growing in place
        assert!(mm.grow_down(STACK_TOP - 17 * PAGE_SIZE, u64::MAX));
        assert!(mm.grow_down(STACK_TOP - 32 * PAGE_SIZE, u64::MAX));
        assert_eq!(mm.vmas.len(), 2);
        assert!(mm.grow_down(STACK_TOP - 33 * PAGE_SIZE, u64::MAX));
        assert_eq!(mm.vmas.len(), 3);
        // Still one [stack] line in maps
        let regions = mm.regions();
        assert_eq!(regions.len(), 1);
        assert_eq!(
            (regions[0].start, regions[0].end),
            (STACK_TOP - 33 * PAGE_SIZE, STACK_TOP)
        );
        assert_eq!(regions[0].name.as_deref(), Some(&b"[stack]"[..]));
    }

    #[test]
    fn stack_growth_stops_at_the_limit() {
        let mut mm = Mm::new();
        mm.map_stack(2 * PAGE_SIZE, 4 * PAGE_SIZE).unwrap();
        // The size after growing counts the separate pieces together
        assert!(!mm.grow_down(STACK_TOP - 9 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert!(mm.grow_down(STACK_TOP - 6 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert!(!mm.grow_down(STACK_TOP - 9 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert!(mm.grow_down(STACK_TOP - 8 * PAGE_SIZE, 8 * PAGE_SIZE));
        assert_eq!(mm.vmas.len(), 3);
        // Keeps growing after the limit is raised
        assert!(mm.grow_down(STACK_TOP - 9 * PAGE_SIZE, 9 * PAGE_SIZE));
    }

    #[test]
    fn fork_keeps_the_reservation_below_the_stack() {
        let mut mm = Mm::new();
        mm.map_stack(2 * PAGE_SIZE, 16 * PAGE_SIZE).unwrap();
        mm.write(UserSlice::new(STACK_TOP - 2, 2), b"hi").unwrap();
        let child = mm.fork().unwrap();
        let mut child = child.borrow_mut();
        assert_eq!(child.stack_low(), STACK_TOP - 2 * PAGE_SIZE);
        assert!(child.grow_down(STACK_TOP - 16 * PAGE_SIZE, u64::MAX));
        assert_eq!(child.vmas.len(), 1);
        let mut buf = [0u8; 2];
        child
            .read(UserSlice::new(STACK_TOP - 2, 2), &mut buf)
            .unwrap();
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn mmap_area_leaves_room_for_the_stack_limit() {
        let mut mm = Mm::new();
        let default = mm.mmap_top;
        mm.set_layout(STACK_SIZE);
        assert_eq!(mm.mmap_top, default);
        mm.set_layout(4 << 30);
        assert_eq!(mm.mmap_top, STACK_TOP - (4 << 30) - STACK_GUARD_GAP);
        mm.set_layout(u64::MAX);
        assert_eq!(mm.mmap_top, (STACK_TOP - MAX_GAP) & !(PAGE_SIZE - 1));
    }

    #[test]
    fn discard_zeroes_private_anonymous_memory() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let len = 8 * PAGE_SIZE;
        let a = mm.mmap(0, len, RW, anon, None).unwrap();
        mm.write(UserSlice::new(a, len as usize), &vec![7u8; len as usize])
            .unwrap();
        // A range not aligned to host pages: the middle goes to the host, both ends are zeroed
        mm.discard(a + PAGE_SIZE, 5 * PAGE_SIZE).unwrap();
        let mut buf = vec![0u8; len as usize];
        mm.read(UserSlice::new(a, len as usize), &mut buf).unwrap();
        let p = PAGE_SIZE as usize;
        assert!(buf[..p].iter().all(|&b| b == 7));
        assert!(buf[p..6 * p].iter().all(|&b| b == 0));
        assert!(buf[6 * p..].iter().all(|&b| b == 7));
    }

    #[test]
    fn anonymous_move_offsets_follow_the_logical_vma() {
        let p = PAGE_SIZE;
        let (src, dst) = (0x200000, 0x400000);
        let mut mm = Mm::new();
        mm.map_anonymous(src, p, RW).unwrap();
        mm.map_anonymous(src + p, p, RW).unwrap();
        mm.map_anonymous(dst - p, p, RW).unwrap();
        mm.map_anonymous(dst + 3 * p, p, RW).unwrap();
        mm.write(UserSlice::new(src + p, 1), b"x").unwrap();
        assert_eq!(mm.mremap(src, 2 * p, 2 * p, true, Some(dst)), Ok(dst));
        assert_eq!(mm.mremap(dst, 2 * p, 3 * p, false, None), Ok(dst));
        assert!(mm.in_one_vma(dst, dst + 3 * p));
        assert_eq!(mm.vmas[&dst].anon_pgoff, src / p);
        assert_eq!(mm.vmas[&(dst + 2 * p)].anon_pgoff, src / p + 2);
        assert!(
            mm.regions()
                .iter()
                .any(|r| r.start == dst && r.end == dst + 3 * p)
        );
        assert_eq!(
            mm.mremap(dst - p, 2 * p, 2 * p, true, Some(src)),
            Err(Errno::EFAULT)
        );
        assert_eq!(mm.mremap(dst, 4 * p, 5 * p, true, None), Err(Errno::EFAULT));
        assert!(!mm.commit_too_big(3 * p));

        // Moving only the unwritten first host piece still preserves the logical identity.
        assert_eq!(mm.mremap(dst, p, p, true, Some(src)), Ok(src));
        assert_eq!(mm.vmas[&src].anon_pgoff, src / p);
        assert_eq!(mm.mremap(src, p, p, true, Some(dst)), Ok(dst));
        assert_eq!(mm.vmas[&dst].anon_pgoff, src / p);
        assert!(mm.in_one_vma(dst, dst + 3 * p));

        let fresh = dst + 8 * p;
        mm.map_anonymous(src, p, RW).unwrap();
        assert!(mm.translate(src, prot::READ).is_some());
        mm.map_anonymous(fresh + p, p, RW).unwrap();
        assert_eq!(mm.mremap(src, p, p, true, Some(fresh)), Ok(fresh));
        assert!(mm.in_one_vma(fresh, fresh + 2 * p));
        assert_eq!(mm.vmas[&fresh].anon_pgoff, fresh / p);
    }

    #[test]
    fn anonymous_first_write_and_fork_identity() {
        let p = PAGE_SIZE;
        let a = 0x400000;
        let parent = Mm::new().into_shared();
        let mut mm = parent.borrow_mut();
        mm.map_anonymous(a, p, RW).unwrap();
        mm.map_anonymous(a + p, p, prot::READ).unwrap();
        mm.mprotect(a + p, p, RW).unwrap();
        assert!(mm.mmu().translate(a, prot::READ).is_some());
        assert!(mm.mmu().translate(a + p, prot::WRITE).is_none());
        let clean = mm.fork().unwrap();
        {
            let mut child = clean.borrow_mut();
            assert!(child.cow.borrow().borrowed.is_empty());
            assert_eq!(child.vmas[&a].anon, 0);
            child.map_anonymous(a + 2 * p, p, RW).unwrap();
            assert!(child.in_one_vma(a, a + 3 * p));
        }
        // A guest write fault grants write only in its host piece. The next fork
        // assigns both pieces one identity and lends only the one that took the fault.
        assert!(mm.try_fault_in(a + p, prot::WRITE).unwrap());
        assert!(mm.mmu().translate(a + p, prot::WRITE).is_some());
        assert!(mm.mmu().translate(a, prot::WRITE).is_none());
        mm.write(UserSlice::new(a + p, 1), b"x").unwrap();
        mm.discard(a + p, p).unwrap();
        let forked = mm.fork().unwrap();
        let mut child = forked.borrow_mut();
        assert_eq!(child.cow.borrow().borrowed.len(), 1);
        assert_ne!(child.vmas[&a].anon, 0);
        assert_eq!(child.vmas[&a].anon, child.vmas[&(a + p)].anon);
        assert!(child.translate(a + p, prot::WRITE).is_none());
        child.map_anonymous(a + 2 * p, p, RW).unwrap();
        assert!(!child.in_one_vma(a, a + 3 * p));
        let id = child.vmas[&a].anon;
        // Release the parent borrow before settling a borrower.
        drop(mm);
        let (dst, _) = child.mremap_dontunmap(a, 2 * p, None).unwrap();
        assert_eq!(child.vmas[&dst].anon, id);
        let remnant = &child.vmas[&a];
        assert_eq!(
            (remnant.len, remnant.anon_pgoff, remnant.anon),
            (2 * p, a / p, 0)
        );
        assert!(!remnant.written.get() && !remnant.has_anon_vma.get());
        assert!(remnant.accounted);
    }

    #[test]
    fn partial_dontunmap_keeps_a_fresh_anonymous_remnant() {
        let (a, dst) = (0x400000, 0x600000);
        let p = PAGE_SIZE;
        let mut mm = Mm::new();
        mm.map_anonymous(a, 3 * p, RW).unwrap();
        mm.write_kernel(a + p, b"x").unwrap();
        mm.mremap_dontunmap(a + p, p, Some(dst)).unwrap();
        assert!(!mm.in_one_vma(a, a + 3 * p));
        assert!(!mm.vmas[&(a + p)].has_anon_vma.get());
        assert_eq!(
            mm.mremap(a, 3 * p, 3 * p, true, Some(dst + 4 * p)),
            Err(Errno::EFAULT)
        );
        let child = mm.fork().unwrap();
        assert_eq!(child.borrow().vmas[&(a + p)].anon, 0);
        mm.mremap(a + p, p, p, true, Some(dst + 4 * p)).unwrap();
        assert_eq!(mm.vmas[&(dst + 4 * p)].anon_pgoff, dst / p + 4);
    }

    #[test]
    fn brk_growth_charges_pages_after_a_noreserve_replacement() {
        let p = PAGE_SIZE;
        let a = 0x400000;
        let mut mm = Mm::new();
        mm.set_brk(a);
        assert_eq!(mm.brk(a + 2 * p, false), a + 2 * p);
        mm.mmap(
            a,
            2 * p,
            RW,
            flags::MAP_FIXED | flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_NORESERVE,
            None,
        )
        .unwrap();
        assert_eq!(mm.brk(a + p, false), a + p);
        mm.sync_except(None);
        assert_eq!(mm.brk(a + 2 * p, false), a + 2 * p);
        assert!(!mm.vmas[&a].accounted);
        assert!(mm.vmas[&(a + p)].accounted);
        assert!(mm.commit_too_big(p - 1));
    }

    #[test]
    fn fork_commit_charge_survives_permission_changes() {
        let p = PAGE_SIZE;
        let a = 0x400000;
        for prot in [0, prot::READ] {
            let mut mm = Mm::new();
            mm.map_anonymous(a, p, RW).unwrap();
            mm.mprotect(a, p, prot).unwrap();
            mm.map_anonymous(a + p, p, prot).unwrap();
            assert!(!mm.in_one_vma(a, a + 2 * p));
            assert!(mm.commit_too_big(p - 1));
            assert!(!mm.commit_too_big(p));
            mm.set_dontfork(a, p, true).unwrap();
            mm.write_kernel(a + p, b"x").unwrap();
            assert!(mm.vmas[&(a + p)].has_anon_vma.get());
            assert!(!mm.commit_too_big(p - 1));
            mm.mprotect(a + p, p, RW).unwrap();
            mm.mprotect(a + p, p, prot).unwrap();
            assert!(mm.fork().unwrap().borrow().commit_too_big(p - 1));
            mm.munmap(a + p, p).unwrap();
            mm.mmap(
                a + p,
                p,
                prot,
                flags::MAP_ANONYMOUS | flags::MAP_PRIVATE | flags::MAP_NORESERVE | flags::MAP_FIXED,
                None,
            )
            .unwrap();
            mm.mprotect(a + p, p, RW).unwrap();
            assert!(!mm.commit_too_big(p - 1));
        }
    }

    /// Leave a given number of free slots without changing the process-wide test limit.
    fn leave_map_slots(mm: &mut Mm, start: u64, free: usize) {
        let limit = MAX_MAP_COUNT.load(Ordering::Relaxed) - free;
        for i in 0..limit - mm.vmas.len() {
            let at = start + i as u64 * 2 * PAGE_SIZE;
            mm.map_anonymous(at, PAGE_SIZE, 0).unwrap();
        }
    }

    #[test]
    fn dontunmap_charges_backing_runs_at_the_map_limit() {
        use std::os::fd::AsRawFd;
        let p = PAGE_SIZE;
        let len = 8 * p;
        let mut mm = Mm::new();
        let (anon, file, fuse, shared) = (0x200000, 0x300000, 0x400000, 0x500000);
        let object = appine_hal::memfd(c"remnant").unwrap();
        object.set_len(len + p).unwrap();
        let fd = object.as_raw_fd();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let cache = appine_hal::memfd(c"remnant-fill").unwrap();
        cache.set_len(len + p).unwrap();
        let fill = Fill::new(cache, len + p, source);
        let fixed = flags::MAP_PRIVATE | flags::MAP_FIXED;
        mm.map_anonymous(anon, len, RW).unwrap();
        mm.mmap(file, len, RW, fixed, Some((fd, p, true))).unwrap();
        mm.mmap_fill(fuse, len, RW, fixed, (fill.clone(), p))
            .unwrap();
        mm.mmap(
            shared,
            len,
            RW,
            flags::MAP_FIXED | flags::MAP_ANONYMOUS | flags::MAP_SHARED,
            None,
        )
        .unwrap();
        for a in [anon, file, fuse, shared] {
            for page in 1..8 {
                mm.split_at(a + page * p);
            }
        }
        let dst = 0x700000;
        leave_map_slots(&mut mm, 0x1_0000_0000, 6);
        for a in [anon, file, fuse, shared] {
            let (_, refills) = mm.mremap_dontunmap(a, len, Some(dst)).unwrap();
            if a == file {
                assert_eq!(refills.len(), 1);
                let r = &refills[0];
                assert_eq!((r.start, r.len, r.offset), (a, len, p));
                assert!(Rc::ptr_eq(
                    r.file.as_ref().unwrap(),
                    &mm.vmas[&dst].file.as_ref().unwrap().0
                ));
            } else {
                assert!(refills.is_empty());
                assert_eq!(mm.vmas[&a].len, len);
                assert_eq!(mm.vmas.range(a..a + len).count(), 1);
                if a == fuse {
                    assert_eq!(mm.vmas[&a].file_len, 0);
                    assert_eq!(mm.fill_wanted(a + 7 * p, prot::READ).unwrap().1, 8);
                } else if a == shared {
                    mm.write_kernel(dst + 7 * p, b"x").unwrap();
                    let mut byte = [0];
                    mm.read(UserSlice::new(a + 7 * p, 1), &mut byte).unwrap();
                    assert_eq!(&byte, b"x");
                }
            }
            // Keep the next move at the same map pressure.
            mm.munmap(dst, len).unwrap();
            if a != shared {
                leave_map_slots(&mut mm, a + len, 6);
            }
        }
    }

    #[test]
    fn dontunmap_preserves_distinct_mount_pins_and_shared_host_regions() {
        use std::os::fd::AsRawFd;
        let p = PAGE_SIZE;
        let (src, dst) = (0x100000, 0x200000);
        let object = appine_hal::memfd(c"remnant-runs").unwrap();
        object.set_len(2 * p).unwrap();
        let file = Some((object.as_raw_fd(), 0, true));
        let mut mm = Mm::new();
        mm.mmap(src, 2 * p, RW, flags::MAP_PRIVATE | flags::MAP_FIXED, file)
            .unwrap();
        mm.split_at(src + p);
        mm.set_mnt(src, p, 41);
        mm.set_mnt(src + p, p, 42);
        let (_, refills) = mm.mremap_dontunmap(src, 2 * p, Some(dst)).unwrap();
        assert_eq!(
            refills
                .iter()
                .map(|r| (r.offset, r.len, r.mnt))
                .collect::<Vec<_>>(),
            [(0, p, Some(41)), (p, p, Some(42))]
        );
        let child = mm.fork().unwrap();
        assert_eq!(child.borrow().vmas[&(dst + p)].mnt.as_ref().unwrap().0, 42);

        mm.mmap(src, p, RW, flags::MAP_SHARED | flags::MAP_FIXED, file)
            .unwrap();
        mm.mremap(src, p, 2 * p, false, None).unwrap();
        mm.mremap_dontunmap(src, 2 * p, Some(dst)).unwrap();
        assert_eq!(mm.vmas.range(src..src + 2 * p).count(), 2);
        for at in [0, p] {
            assert!(Arc::ptr_eq(
                &mm.vmas[&(src + at)].region,
                &mm.vmas[&(dst + at)].region
            ));
        }
    }

    #[test]
    fn private_regrowth_keeps_other_host_views_and_shared_failure_rolls_back() {
        let p = PAGE_SIZE;
        let (a, dst) = (0x100000, 0x200000);
        let mut mm = Mm::new();
        mm.map_anonymous(a, 2 * p, RW).unwrap();
        mm.write_kernel(a + p, b"x").unwrap();
        mm.mremap(a + p, p, p, true, Some(dst)).unwrap();
        mm.mremap(a, p, 2 * p, false, None).unwrap();
        assert!(!Arc::ptr_eq(&mm.vmas[&a].region, &mm.vmas[&(a + p)].region));
        let mut b = [0];
        mm.read(UserSlice::new(dst, 1), &mut b).unwrap();
        assert_eq!(&b, b"x");

        // Exercise map_pages rollback on a shared extension beyond the MMU address limit.
        let segment = SharedMemory::new(2 * p).unwrap();
        let src = mm.attach_shm(None, &segment, RW, false, (1, 6)).unwrap();
        let last = (1 << VA_BITS) - p;
        mm.mremap(src, 0, p, true, Some(last)).unwrap();
        let before = mm.shared_maps.read().unwrap().clone();
        assert!(mm.grow_tail(last, p).is_err());
        assert_eq!(mm.vmas[&last].len, p);
        // A recount can reorder the classification ranges.
        let mut after = mm.shared_maps.read().unwrap().clone();
        let mut before = before;
        before.sort_unstable();
        after.sort_unstable();
        assert_eq!(after, before);
        assert!(mm.mmu().translate(last, prot::WRITE).is_some());
    }

    #[test]
    fn growth_reuses_safe_backing_at_the_map_limit() {
        let p = PAGE_SIZE;
        let (reserved, private, shared, sysv) = (0x200000, 0x300000, 0x400000, 0x500000);
        let mut mm = Mm::new();
        mm.map_anonymous(reserved, p, 0).unwrap();
        mm.map_anonymous(private, 2 * p, RW).unwrap();
        mm.write_kernel(private + p, b"old").unwrap();
        mm.mremap(private, 2 * p, p, false, None).unwrap();
        mm.sync_except(None);
        mm.mmap(
            shared,
            p,
            RW,
            flags::MAP_FIXED | flags::MAP_SHARED | flags::MAP_ANONYMOUS,
            None,
        )
        .unwrap();
        let segment = SharedMemory::new(2 * p).unwrap();
        mm.attach_shm(Some(sysv), &segment, RW, false, (1, 5))
            .unwrap();
        mm.mremap(sysv, 2 * p, p, false, None).unwrap();
        leave_map_slots(&mut mm, 0x1_0000_0000, 0);
        for a in [reserved, private, shared, sysv] {
            assert_eq!(mm.mremap(a, p, 2 * p, false, None), Ok(a));
            assert_eq!(mm.vmas[&a].len, 2 * p);
        }
        let mut byte = [1];
        mm.read(UserSlice::new(private + p, 1), &mut byte).unwrap();
        assert_eq!(byte, [0]);
        assert!(mm.mmu().translate(reserved + p, 0).is_none());
        assert_eq!(mm.fault_past_eof(shared + p, prot::READ), Some(true));
        assert!(mm.mmu().translate(sysv + p, prot::WRITE).is_some());
        for base in [shared, sysv] {
            assert!(
                mm.shared_maps
                    .read()
                    .unwrap()
                    .contains(&(base, base + 2 * p))
            );
        }
    }

    #[test]
    fn mremap_grows_moves_and_shrinks() {
        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let a = mm.mmap(0x100000, 2 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.write_kernel(a, b"keep").unwrap();
        // Free space behind it: extend in place
        let b = mm
            .mremap(a, 2 * PAGE_SIZE, 3 * PAGE_SIZE, false, None)
            .unwrap();
        assert_eq!(b, a);
        mm.write_kernel(a + 2 * PAGE_SIZE, b"x").unwrap();
        // Space behind it taken: fails if moving is not allowed, otherwise moves elsewhere with the
        // contents unchanged
        mm.mmap(a + 3 * PAGE_SIZE, PAGE_SIZE, RW, fixed, None)
            .unwrap();
        assert_eq!(
            mm.mremap(a, 3 * PAGE_SIZE, 5 * PAGE_SIZE, false, None),
            Err(Errno::ENOMEM)
        );
        let c = mm
            .mremap(a, 3 * PAGE_SIZE, 5 * PAGE_SIZE, true, None)
            .unwrap();
        assert_ne!(c, a);
        assert!(!mm.is_mapped(a));
        let mut buf = [0u8; 4];
        mm.read(UserSlice::new(c, 4), &mut buf).unwrap();
        assert_eq!(&buf, b"keep");
        mm.read(UserSlice::new(c + 4 * PAGE_SIZE, 4), &mut buf)
            .unwrap();
        assert_eq!(buf, [0; 4]);
        // Shrink: drop the tail
        assert_eq!(mm.mremap(c, 5 * PAGE_SIZE, PAGE_SIZE, false, None), Ok(c));
        assert!(!mm.is_mapped(c + PAGE_SIZE));
        // A range not fully mapped: shrinking only unmaps the tail (Linux looks up only the
        // mapping at the old address), growing needs the old range in one VMA
        assert_eq!(
            mm.mremap(c, 2 * PAGE_SIZE, 3 * PAGE_SIZE, true, None),
            Err(Errno::EFAULT)
        );
        assert_eq!(mm.mremap(c, 2 * PAGE_SIZE, PAGE_SIZE, true, None), Ok(c));
        assert_eq!(mm.check_mapped(c, 2 * PAGE_SIZE), Err(Errno::ENOMEM));
        assert_eq!(mm.check_mapped(c, PAGE_SIZE), Ok(()));
        // Two mappings Linux would not merge (different permissions) cannot be moved as one
        let d = mm.mmap(0x400000, 2 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.mprotect(d, PAGE_SIZE, prot::READ).unwrap();
        assert_eq!(
            mm.mremap(d, 2 * PAGE_SIZE, 2 * PAGE_SIZE, true, Some(0x800000)),
            Err(Errno::EFAULT)
        );
        mm.mprotect(d, PAGE_SIZE, RW).unwrap();
        assert_eq!(
            mm.mremap(d, 2 * PAGE_SIZE, 2 * PAGE_SIZE, true, Some(0x800000)),
            Ok(0x800000)
        );
    }

    #[test]
    fn mremap_at_the_map_count_limit_changes_nothing() {
        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let a = mm.mmap(0x100000, 4 * PAGE_SIZE, RW, fixed, None).unwrap();
        let w = mm.mmap(0x200000, 2 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.write_kernel(a + PAGE_SIZE, b"keep").unwrap();
        mm.write_kernel(w, b"keep").unwrap();
        // `w` cannot grow in place
        mm.mmap(w + 2 * PAGE_SIZE, PAGE_SIZE, 0, fixed, None)
            .unwrap();
        let kept = |mm: &Mm, at: u64| {
            let mut buf = [0u8; 4];
            mm.read(UserSlice::new(at, 4), &mut buf).is_ok() && &buf == b"keep"
        };
        // Single-page reservations with gaps between them, up to the limit
        let max = MAX_MAP_COUNT.load(Ordering::Relaxed);
        let fillers = 0x1000_0000;
        let mut at = fillers;
        while mm.vmas.len() < max {
            mm.mmap(at, PAGE_SIZE, 0, fixed, None).unwrap();
            at += 2 * PAGE_SIZE;
        }
        // Moving the middle of `a` (split in three), a whole mapping that cannot grow in place, to
        // a fixed target or with MREMAP_DONTUNMAP: refused before anything changes
        let cases: [(u64, u64, u64, Option<u64>); 3] = [
            (a + PAGE_SIZE, 2 * PAGE_SIZE, 3 * PAGE_SIZE, None),
            (w, 2 * PAGE_SIZE, 4 * PAGE_SIZE, None),
            (a + PAGE_SIZE, 2 * PAGE_SIZE, 2 * PAGE_SIZE, Some(0x800000)),
        ];
        for (old, old_len, new_len, target) in cases {
            assert_eq!(
                mm.mremap(old, old_len, new_len, true, target),
                Err(Errno::ENOMEM)
            );
        }
        assert_eq!(
            mm.mremap_dontunmap(a + PAGE_SIZE, 2 * PAGE_SIZE, None)
                .map(|r| r.0),
            Err(Errno::ENOMEM)
        );
        assert!(kept(&mm, a + PAGE_SIZE) && kept(&mm, w));
        assert_eq!(mm.vmas.len(), max);
        // A bad target is EINVAL before the margin, and splits nothing
        mm.munmap(fillers, 20 * PAGE_SIZE).unwrap();
        let before = mm.vmas.len();
        assert_eq!(
            mm.mremap_dontunmap(a + PAGE_SIZE, 2 * PAGE_SIZE, Some(a + 2 * PAGE_SIZE))
                .map(|r| r.0),
            Err(Errno::EINVAL)
        );
        assert_eq!(mm.vmas.len(), before);
        // With room again the move goes ahead
        let b = mm
            .mremap(a + PAGE_SIZE, 2 * PAGE_SIZE, 3 * PAGE_SIZE, true, None)
            .unwrap();
        assert!(kept(&mm, b) && !mm.is_mapped(a + PAGE_SIZE));
    }

    #[test]
    fn mremap_shared_anonymous_regrowth_keeps_aliases_and_the_original_extent() {
        let mut mm = Mm::new();
        let p = PAGE_SIZE;
        let fixed = flags::MAP_SHARED | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let a = mm.mmap(0x100000, 3 * p, RW, fixed, None).unwrap();
        // Keep an alias of the last page while shrinking and regrowing the original in place.
        let alias = mm.mremap(a + 2 * p, 0, p, true, None).unwrap();
        mm.mremap(a, 3 * p, p, false, None).unwrap();
        mm.write_kernel(alias, b"x").unwrap();
        for n in 1..5 {
            assert_eq!(mm.mremap(a, n * p, (n + 1) * p, false, None), Ok(a));
        }
        let mut byte = [0];
        mm.read(UserSlice::new(a + 2 * p, 1), &mut byte).unwrap();
        assert_eq!(&byte, b"x");
        assert_eq!(mm.futex_key(a + 2 * p, false), mm.futex_key(alias, false));
        assert_eq!(mm.fault_past_eof(a + 3 * p, prot::READ), Some(true));
        assert_eq!(
            mm.residency(a + 2 * p, 3 * p).unwrap(),
            [true, false, false]
        );
        assert_eq!(mm.pagemap(a + 3 * p, 2), [0, 0]);
        assert_eq!(mm.resident_in(a + 3 * p, 2 * p), 0);

        // An independent shared mapping at the next address still starts a different Linux VMA.
        mm.mmap(a + 5 * p, p, RW, fixed, None).unwrap();
        assert_eq!(mm.mremap(a, 6 * p, 7 * p, true, None), Err(Errno::EFAULT));
    }

    #[test]
    fn mremap_extends_shared_file_mappings_with_the_file() {
        use std::io::Write;
        use std::os::fd::AsRawFd;
        let path = std::env::temp_dir().join(format!("appine-mremap-{}", std::process::id()));
        let mut f = std::fs::File::options()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)
            .unwrap();
        f.write_all(&vec![1u8; PAGE_SIZE as usize]).unwrap();
        f.write_all(&vec![2u8; PAGE_SIZE as usize]).unwrap();
        let mut mm = Mm::new();
        let a = mm
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_SHARED,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        drop(f);
        let b = mm.mremap(a, PAGE_SIZE, 2 * PAGE_SIZE, true, None).unwrap();
        let mut buf = [0u8; 1];
        mm.read(UserSlice::new(b + PAGE_SIZE, 1), &mut buf).unwrap();
        assert_eq!(buf, [2]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn brk_grows_and_shrinks() {
        let mut mm = Mm::new();
        mm.set_brk(0x50_0123);
        assert_eq!(mm.brk(0, false), 0x50_0123);
        assert_eq!(mm.brk(0x50_3000, false), 0x50_3000);
        mm.write_kernel(0x50_2ff0, &[1; 16]).unwrap();
        assert_eq!(mm.brk(0x50_1000, false), 0x50_1000);
        assert!(mm.mmu().translate(0x50_2000, 0).is_none());
    }

    #[test]
    fn brk_extends_one_vma_and_zeroes_regrown_pages() {
        let mut mm = Mm::new();
        mm.set_brk(0x50_0000);
        for i in 1..=64 {
            assert_eq!(
                mm.brk(0x50_0000 + i * PAGE_SIZE, false),
                0x50_0000 + i * PAGE_SIZE
            );
        }
        assert_eq!(mm.vmas.len(), 1);
        mm.write_kernel(0x53_f000, b"old").unwrap();
        mm.brk(0x52_0000, false);
        mm.brk(0x54_0000, false);
        assert_eq!(mm.vmas.len(), 1);
        let mut buf = [1u8; 3];
        mm.read(UserSlice::new(0x53_f000, 3), &mut buf).unwrap();
        assert_eq!(buf, [0; 3]);
        // Growing further in the child is still one VMA, with the contents copied over
        mm.write_kernel(0x50_0000, b"heap").unwrap();
        let child = mm.fork().unwrap();
        let mut buf = [0u8; 4];
        {
            let mut child = child.borrow_mut();
            assert_eq!(child.brk(0x58_0000, false), 0x58_0000);
            assert_eq!(child.vmas.len(), 1);
            child.read(UserSlice::new(0x50_0000, 4), &mut buf).unwrap();
            assert_eq!(&buf, b"heap");
        }
        // After a page in the middle of the heap is replaced, the part after it can still grow; the
        // page the child borrowed is copied for it first
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        mm.mmap(0x50_0000, PAGE_SIZE, 0, anon, None).unwrap();
        child
            .borrow()
            .read(UserSlice::new(0x50_0000, 4), &mut buf)
            .unwrap();
        assert_eq!(&buf, b"heap");
        assert_eq!(mm.brk(0x60_0000, false), 0x60_0000);
        assert_eq!(mm.vmas.len(), 2);
        let regions = mm.regions();
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[1].name.as_deref(), Some(&b"[heap]"[..]));
    }

    /// Reads one byte at `addr`.
    fn byte(mm: &Rc<RefCell<Mm>>, addr: u64) -> u8 {
        let mut b = [0u8];
        mm.borrow().read(UserSlice::new(addr, 1), &mut b).unwrap();
        b[0]
    }

    fn poke(mm: &Rc<RefCell<Mm>>, addr: u64, b: u8) {
        mm.borrow().write(UserSlice::new(addr, 1), &[b]).unwrap();
    }

    fn writable(mm: &Rc<RefCell<Mm>>, addr: u64) -> bool {
        mm.borrow().mmu().translate(addr, prot::WRITE).is_some()
    }

    /// Fail exactly the nth CoW map on this thread, restoring the hook even on unwind.
    fn with_cow_map_failure<T>(nth: usize, f: impl FnOnce() -> T) -> T {
        struct Reset(usize);
        impl Drop for Reset {
            fn drop(&mut self) {
                COW_MAP_FAIL.set(self.0);
            }
        }
        assert!(nth > 0);
        let _guard = Reset(COW_MAP_FAIL.replace(nth));
        let result = f();
        assert_eq!(COW_MAP_FAIL.get(), 0, "CoW map failpoint was not reached");
        result
    }

    #[test]
    fn try_fault_in_never_exposes_borrower_backing_for_borrowed_page() {
        let parent = Mm::new().into_shared();
        let a = LEAF_SPAN;
        let sibling = a + PAGE_SIZE;
        parent
            .borrow_mut()
            .map_anonymous(a, 2 * PAGE_SIZE, RW)
            .unwrap();
        poke(&parent, a, b'p');
        let owner = parent.borrow().mmu.translate(a, prot::READ).unwrap();
        let child = parent.borrow_mut().fork().unwrap();
        assert!(child.borrow().cow_break(sibling));
        assert_ne!(child.borrow().vmas[&a].host, owner);

        for mm in [&child, &parent] {
            let mut mm = mm.borrow_mut();
            mm.mmu.unmap(a, 2 * PAGE_SIZE).unwrap();
            assert_eq!(mm.try_fault_in(a, prot::WRITE), Ok(false));
            assert_eq!(mm.mmu.next_present(a, sibling), sibling);
            assert_eq!(mm.try_fault_in(sibling, prot::READ), Ok(true));
            assert!(mm.mmu.translate(sibling, prot::READ).is_some());
            assert_eq!(mm.mmu.next_present(a, sibling), sibling);

            mm.mmu.unmap(sibling, PAGE_SIZE).unwrap();
            let mut walk = PopulateWalk::new(a, 2 * PAGE_SIZE);
            assert!(matches!(
                mm.populate_step(&mut walk, false),
                Ok(PopulateStep::Done)
            ));
            assert!(mm.mmu.translate(sibling, prot::READ).is_some());
            assert_eq!(mm.mmu.next_present(a, sibling), sibling);
            assert_eq!(
                with_cow_map_failure(1, || mm.try_fault_in(a, prot::READ)),
                Ok(false)
            );
            assert_eq!(mm.try_fault_in(a, prot::READ), Ok(true));
            assert_eq!(mm.mmu.translate(a, prot::READ), Some(owner));
            assert!(mm.mmu.translate(a, prot::WRITE).is_none());
        }
        assert_eq!(byte(&child, a), b'p');
        // Repossession cannot upgrade an absent PTE. The ordinary write fault must finish it.
        parent.borrow_mut().mmu.unmap(a, PAGE_SIZE).unwrap();
        assert!(!parent.borrow().cow_break(a));
        assert!(parent.borrow().cow.borrow().lent.is_empty());
        assert_eq!(parent.borrow().try_fault_in(a, prot::WRITE), Ok(true));
        assert!(writable(&parent, a));
    }

    #[test]
    fn fork_lend_map_shared_failure_rolls_back_and_preserves_isolation() {
        let parent = Mm::new().into_shared();
        let (a, b) = (LEAF_SPAN, 2 * LEAF_SPAN);
        for page in [a, b] {
            parent
                .borrow_mut()
                .map_anonymous(page, PAGE_SIZE, RW)
                .unwrap();
            poke(&parent, page, b'p');
        }
        parent.borrow_mut().dirty = false;
        // Two child runs, then two parent runs. Fail each, including after the first downgrade.
        for nth in 1..=4 {
            assert!(matches!(
                with_cow_map_failure(nth, || parent.borrow_mut().fork()),
                Err(Errno::ENOMEM)
            ));
            let mm = parent.borrow();
            assert!(mm.cow.borrow().lent.is_empty());
            assert!(mm.loans.borrow().is_empty());
            assert!(!mm.dirty);
            for page in [a, b] {
                assert!(mm.mmu.translate(page, prot::WRITE).is_some());
            }
        }

        let child = parent.borrow_mut().fork().unwrap();
        poke(&child, b, b'c');
        // Only a remains lent. A failed downgrade of b must preserve the first child's loan.
        assert!(matches!(
            with_cow_map_failure(3, || parent.borrow_mut().fork()),
            Err(Errno::ENOMEM)
        ));
        assert_eq!(parent.borrow().cow.borrow().lent, BTreeSet::from([a]));
        let key = parent.borrow().vmas[&a].host.as_ptr() as usize;
        assert_eq!(parent.borrow().loans.borrow()[&key].users(), 2);
        assert!(!writable(&parent, a));
        assert!(writable(&parent, b));
        poke(&parent, a, b'q');
        assert_eq!((byte(&child, a), byte(&child, b)), (b'p', b'c'));
        assert!(parent.borrow().loans.borrow().is_empty());
    }

    #[test]
    fn mprotect_cow_entries_failure_preserves_cow_isolation() {
        let parent = Mm::new().into_shared();
        let a = LEAF_SPAN;
        let len = 2 * PAGE_SIZE;
        parent.borrow_mut().map_anonymous(a, len, RW).unwrap();
        parent.borrow().write(UserSlice::new(a, 2), b"ab").unwrap();
        parent.borrow_mut().mprotect(a, len, 0).unwrap();
        for new in [RW, prot::WRITE] {
            let child = parent.borrow_mut().fork().unwrap();
            {
                let mut mm = child.borrow_mut();
                assert_eq!(mm.mmu.next_present(a, a + len), a + len);
                assert_eq!(
                    with_cow_map_failure(2, || mm.mprotect(a, len, new)),
                    Err(Errno::ENOMEM)
                );
                assert_eq!(mm.vmas[&a].prot, 0);
                // The first entry was installed with prot 0. The failed second one is still absent.
                assert_eq!(mm.mmu.next_present(a, a + len), a);
                assert_eq!(mm.mmu.next_present(a + PAGE_SIZE, a + len), a + len);
                for page in [a, a + PAGE_SIZE] {
                    assert!(mm.mmu.translate(page, 0).is_none());
                }
                // Inspect the host address retained by the prot-0 entry without invoking a fault.
                mm.mmu.protect(a, PAGE_SIZE, prot::READ).unwrap();
                assert_eq!(
                    mm.mmu.translate(a, prot::READ),
                    Some(parent.borrow().vmas[&a].host)
                );
                mm.mmu.protect(a, PAGE_SIZE, 0).unwrap();
                mm.mprotect(a, len, new).unwrap();
                assert_eq!(mm.vmas[&a].prot, new);
                assert_eq!(
                    mm.mmu.translate(a, prot::READ),
                    Some(parent.borrow().vmas[&a].host)
                );
                assert!(mm.mmu.translate(a, prot::WRITE).is_none());
            }
            assert_eq!(byte(&child, a), b'a');
            poke(&child, a, b'x');
            assert_eq!((byte(&child, a), byte(&child, a + 1)), (b'x', b'b'));
        }
        parent.borrow_mut().mprotect(a, len, RW).unwrap();
        assert_eq!((byte(&parent, a), byte(&parent, a + 1)), (b'a', b'b'));
    }

    #[test]
    fn materialize_map_shared_failure_preserves_loan_and_isolation() {
        let parent = Mm::new().into_shared();
        let a = LEAF_SPAN;
        parent.borrow_mut().map_anonymous(a, PAGE_SIZE, RW).unwrap();
        poke(&parent, a, b'p');
        let child = parent.borrow_mut().fork().unwrap();
        let key = parent.borrow().vmas[&a].host.as_ptr() as usize;
        let check_loan = || {
            assert!(child.borrow().cow.borrow().borrowed.contains_key(&a));
            assert!(parent.borrow().cow.borrow().lent.contains(&a));
            assert_eq!(parent.borrow().loans.borrow()[&key].users(), 2);
            assert!(!writable(&parent, a) && !writable(&child, a));
            assert_eq!((byte(&parent, a), byte(&child, a)), (b'p', b'p'));
        };
        assert!(!with_cow_map_failure(1, || child.borrow().cow_break(a)));
        check_loan();
        with_cow_map_failure(1, || child.borrow_mut().release());
        check_loan();
        let other = parent.borrow_mut().fork().unwrap();
        assert!(!with_cow_map_failure(1, || parent.borrow().cow_break(a)));
        // Recall succeeded for the second borrower. Only the failed borrower remains.
        assert!(writable(&other, a));
        check_loan();
        assert_eq!(
            with_cow_map_failure(1, || parent.borrow_mut().discard_range(a, PAGE_SIZE, false)).1,
            Err(Errno::ENOMEM)
        );
        check_loan();
        assert_eq!(
            with_cow_map_failure(1, || parent.borrow_mut().munmap(a, PAGE_SIZE)),
            Err(Errno::ENOMEM)
        );
        check_loan();
        assert!(parent.borrow().cow_break(a));
        poke(&parent, a, b'q');
        assert_eq!(
            (byte(&parent, a), byte(&child, a), byte(&other, a)),
            (b'q', b'p', b'p')
        );
        assert!(parent.borrow().loans.borrow().is_empty());
    }

    #[test]
    fn fork_shares_written_pages_until_either_side_writes() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 4 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        for i in 0..4 {
            poke(&parent, a + i * PAGE_SIZE, b'p');
        }
        let child = parent.borrow_mut().fork().unwrap();
        // Both page tables point at the parent's host page, and neither can write
        let host = |mm: &Rc<RefCell<Mm>>, addr| mm.borrow().mmu().translate(addr, prot::READ);
        assert_eq!(host(&parent, a), host(&child, a));
        assert!(!writable(&parent, a) && !writable(&child, a));
        // The child writes: it copies its own; the parent is now the only user and gets write
        // permission back at once
        poke(&child, a, b'c');
        assert_eq!((byte(&parent, a), byte(&child, a)), (b'p', b'c'));
        assert!(writable(&parent, a) && writable(&child, a));
        // The parent writes: the child copies first
        poke(&parent, a + PAGE_SIZE, b'q');
        assert_eq!(byte(&child, a + PAGE_SIZE), b'p');
        // The grandchild borrows page 0 from the child and page 2 from the original owner
        let grandchild = child.borrow_mut().fork().unwrap();
        assert_eq!(
            host(&grandchild, a + 2 * PAGE_SIZE),
            host(&parent, a + 2 * PAGE_SIZE)
        );
        poke(&parent, a + 2 * PAGE_SIZE, b'r');
        assert_eq!(byte(&child, a + 2 * PAGE_SIZE), b'p');
        assert_eq!(byte(&grandchild, a + 2 * PAGE_SIZE), b'p');
        poke(&child, a, b'd');
        assert_eq!(byte(&grandchild, a), b'c');
        // The owner's address space is destroyed: lent pages stay with the descendants, contents
        // unchanged, and they can still write
        drop(parent);
        poke(&grandchild, a + 3 * PAGE_SIZE, b'g');
        assert_eq!(byte(&child, a + 3 * PAGE_SIZE), b'p');
        assert_eq!(byte(&grandchild, a + 3 * PAGE_SIZE), b'g');
        // The child unmaps: pages the grandchild borrowed from it are copied first
        child.borrow_mut().munmap(a, 4 * PAGE_SIZE).unwrap();
        assert_eq!(byte(&grandchild, a), b'c');
        assert_eq!(byte(&grandchild, a + PAGE_SIZE), b'p');
        drop(child);
        let g = grandchild.borrow();
        assert!(g.cow.borrow().borrowed.is_empty() && g.cow.borrow().lent.is_empty());
        assert!(g.loans.borrow().is_empty());
    }

    #[test]
    fn large_mappings_build_page_tables_on_demand() {
        let mm = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_NORESERVE;
        // 64 GB: building entries page by page would take 128 MB. The start is aligned to a leaf
        // table
        let len = 64 << 30;
        let fixed = anon | flags::MAP_FIXED;
        let a = mm.borrow_mut().mmap(1 << 40, len, RW, fixed, None).unwrap();
        let present = |mm: &Rc<RefCell<Mm>>, from| mm.borrow().mmu().next_present(from, a + len);
        assert_eq!(present(&mm, a), a + len);
        // A fault fills the pages in the same leaf table (2 MB), not those that already have
        // entries
        assert!(mm.borrow().fault_in(a + 5 * PAGE_SIZE + 7, prot::WRITE));
        assert!(!mm.borrow().fault_in(a + 6 * PAGE_SIZE, prot::READ));
        assert!(writable(&mm, a + LEAF_SPAN - PAGE_SIZE));
        assert_eq!(present(&mm, a + LEAF_SPAN), a + len);
        // Kernel-layer reads and writes also fill entries on demand
        let far = a + len / 2 + 3 * PAGE_SIZE;
        poke(&mm, far, b'x');
        assert_eq!(byte(&mm, far), b'x');
        assert_eq!(present(&mm, a + LEAF_SPAN), far & !(LEAF_SPAN - 1));
        // Nothing is filled outside the mapping or without the permission
        assert!(!mm.borrow().fault_in(a + len, prot::READ));
        assert!(!mm.borrow().fault_in(a, prot::EXEC));
        // Resident memory measures only the spans with entries
        poke(&mm, a, b'p');
        assert!(mm.borrow().resident_pages() < 16);
        assert!(mm.borrow().resident_in(a, len) <= 2);
        // fork lends only the pages touched
        let child = mm.borrow_mut().fork().unwrap();
        assert_eq!((byte(&child, a), byte(&child, far)), (b'p', b'x'));
        assert!(child.borrow().cow.borrow().borrowed.len() <= 2 * 512);
        poke(&child, far, b'c');
        assert_eq!((byte(&mm, far), byte(&child, far)), (b'x', b'c'));
        assert_eq!(byte(&child, a + len - 1), 0);
    }

    #[test]
    fn written_pages_keep_entries_through_prot_none_mremap_and_kernel_writes() {
        // In large on-demand mappings every page with contents has an entry: fork's lending looks
        // only at the spans with entries
        let mm = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let len = 64 * LEAF_SPAN;
        let fixed = anon | flags::MAP_FIXED;
        let a = mm.borrow_mut().mmap(1 << 40, len, RW, fixed, None).unwrap();
        let (guest, kernel) = (a + 3 * LEAF_SPAN, a + 9 * LEAF_SPAN + 5);
        poke(&mm, guest, b'g');
        // The kernel layer writes host memory directly (loading programs, PTRACE_POKEDATA)
        mm.borrow_mut().write_kernel(kernel, b"k").unwrap();
        // PROT_NONE: the entries stay with permissions cleared, so they are inaccessible
        mm.borrow_mut().mprotect(a, len, 0).unwrap();
        assert!(mm.borrow().mmu().translate(guest, 0).is_none());
        assert_eq!(
            mm.borrow().mmu().next_present(a, a + len),
            a + 3 * LEAF_SPAN
        );
        mm.borrow_mut()
            .write_kernel(a + 20 * LEAF_SPAN, b"n")
            .unwrap();
        let child = mm.borrow_mut().fork().unwrap();
        for m in [&mm, &child] {
            m.borrow_mut().mprotect(a, len, RW).unwrap();
            assert_eq!(byte(m, guest), b'g');
            assert_eq!(byte(m, kernel), b'k');
            assert_eq!(byte(m, a + 20 * LEAF_SPAN), b'n');
        }
        assert!(!writable(&mm, guest) && !writable(&child, guest));
        // mremap moves it: the entries move along, and a child forked later still sees them
        let dst = 0x1000_0000_0000;
        let moved = mm
            .borrow_mut()
            .mremap(a, len, len, true, Some(dst))
            .unwrap();
        assert_eq!(mm.borrow().mmu().next_present(a, a + len), a + len);
        let grandchild = mm.borrow_mut().fork().unwrap();
        assert_eq!(byte(&grandchild, moved + 3 * LEAF_SPAN), b'g');
        assert_eq!(byte(&grandchild, moved + 9 * LEAF_SPAN + 5), b'k');
        assert_eq!(byte(&child, guest), b'g');
    }

    #[test]
    fn copy_on_write_survives_mprotect_discard_and_mremap() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 3 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        for i in 0..3 {
            poke(&parent, a + i * PAGE_SIZE, b'p');
        }
        let child = parent.borrow_mut().fork().unwrap();
        // Remove permissions and add them back (including PROT_NONE, when the page is not in the
        // page table): still borrowed, still not writable
        for mm in [&parent, &child] {
            for p in [prot::READ, 0, RW] {
                mm.borrow_mut().mprotect(a, 3 * PAGE_SIZE, p).unwrap();
            }
            assert_eq!(byte(mm, a), b'p');
            assert!(!writable(mm, a));
        }
        // Discard: the other side's contents are unchanged
        parent.borrow_mut().discard(a, PAGE_SIZE).unwrap();
        child
            .borrow_mut()
            .discard(a + PAGE_SIZE, PAGE_SIZE)
            .unwrap();
        assert_eq!((byte(&parent, a), byte(&child, a)), (0, b'p'));
        assert_eq!(
            (byte(&parent, a + PAGE_SIZE), byte(&child, a + PAGE_SIZE)),
            (b'p', 0)
        );
        // After mremap moves it, each side writes its own
        let moved = parent
            .borrow_mut()
            .mremap(
                a + 2 * PAGE_SIZE,
                PAGE_SIZE,
                PAGE_SIZE,
                true,
                Some(0x1000_0000),
            )
            .unwrap();
        poke(&parent, moved, b'q');
        assert_eq!(byte(&child, a + 2 * PAGE_SIZE), b'p');
        poke(&child, a + 2 * PAGE_SIZE, b'c');
        assert_eq!(byte(&parent, moved), b'q');
    }

    #[test]
    fn release_frees_private_memory_but_keeps_vmas_and_lent_pages() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 4 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        for i in 0..4 {
            poke(&parent, a + i * PAGE_SIZE, b'p');
        }
        let regions = |mm: &Rc<RefCell<Mm>>| -> Vec<(u64, u64, u32)> {
            let m = mm.borrow();
            m.regions()
                .iter()
                .map(|r| (r.start, r.end, r.prot))
                .collect()
        };
        // The child copies page 0 and borrows pages 1 to 3
        let child = parent.borrow_mut().fork().unwrap();
        poke(&child, a, b'c');
        let maps = regions(&child);
        child.borrow_mut().release();
        // Its own page and its borrowed ones read zero, without copying: the parent is the only
        // user of its pages again and can write them, contents unchanged
        assert_eq!(regions(&child), maps);
        for i in 0..4 {
            assert_eq!(byte(&child, a + i * PAGE_SIZE), 0);
            assert_eq!(byte(&parent, a + i * PAGE_SIZE), b'p');
            assert!(writable(&parent, a + i * PAGE_SIZE));
        }
        assert!(child.borrow().cow.borrow().borrowed.is_empty());
        assert!(parent.borrow().cow.borrow().lent.is_empty());
        // Releasing a lender leaves the pages it lent: the borrower still reads them, while the
        // pages it had copied for itself read zero
        let child = parent.borrow_mut().fork().unwrap();
        poke(&parent, a, b'q');
        parent.borrow_mut().release();
        assert_eq!((byte(&parent, a), byte(&child, a)), (0, b'p'));
        assert_eq!(byte(&child, a + PAGE_SIZE), b'p');
        assert_eq!(byte(&parent, a + PAGE_SIZE), b'p');
        poke(&child, a + PAGE_SIZE, b'c');
        assert_eq!(byte(&parent, a + PAGE_SIZE), b'p');
    }

    #[test]
    fn returned_loans_restore_each_vma_its_own_protection() {
        // The host memory of the VMAs an mprotect split off is contiguous: when the child returns
        // borrowed pages, the parent restores each page with its own VMA's permissions, not with
        // those of the first page in the contiguous run
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 3 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        for i in 0..3 {
            poke(&parent, a + i * PAGE_SIZE, b'p');
        }
        parent.borrow_mut().mprotect(a, PAGE_SIZE, 0).unwrap();
        parent
            .borrow_mut()
            .mprotect(a + 2 * PAGE_SIZE, PAGE_SIZE, prot::READ)
            .unwrap();
        let child = parent.borrow_mut().fork().unwrap();
        drop(child);
        let readable = |addr| parent.borrow().mmu().translate(addr, prot::READ).is_some();
        assert!(!readable(a));
        assert!(writable(&parent, a + PAGE_SIZE));
        assert!(readable(a + 2 * PAGE_SIZE) && !writable(&parent, a + 2 * PAGE_SIZE));
        assert!(parent.borrow().cow.borrow().lent.is_empty());
    }

    #[test]
    fn cow_shared_counts_pages_mapped_by_others() {
        // smaps Shared_Dirty and Pss: the number of address spaces sharing a page matches Linux's
        // mapcount
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, 2 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        poke(&parent, a, b'p');
        poke(&parent, a + PAGE_SIZE, b'p');
        let shared = |mm: &Rc<RefCell<Mm>>| mm.borrow().cow_shared(a, a + 2 * PAGE_SIZE);
        assert_eq!(shared(&parent), (0, 0));
        let child = parent.borrow_mut().fork().unwrap();
        assert_eq!(shared(&parent), (2, PAGE_SIZE));
        assert_eq!(shared(&child), (2, PAGE_SIZE));
        // The grandchild borrows too: each of the three address spaces gets a third
        let grandchild = child.borrow_mut().fork().unwrap();
        assert_eq!(shared(&grandchild), (2, 2 * (PAGE_SIZE / 3)));
        // The child wrote page 0, which is now shared only by the parent and the grandchild
        poke(&child, a, b'c');
        assert_eq!(shared(&child), (1, PAGE_SIZE / 3));
        assert_eq!(shared(&parent), (2, PAGE_SIZE / 2 + PAGE_SIZE / 3));
        // After the parent's address space is destroyed, an orphan page with one borrower counts
        // as private
        drop(parent);
        drop(child);
        assert_eq!(shared(&grandchild), (0, 0));
    }

    #[test]
    fn futex_keys_of_private_memory_follow_the_address() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = parent
            .borrow_mut()
            .mmap(0, PAGE_SIZE, RW, anon, None)
            .unwrap();
        poke(&parent, a, 1);
        let child = parent.borrow_mut().fork().unwrap();
        // A borrowed page has the child's own key, which copy-on-write does not change
        let key = child.borrow().futex_key(a, false).unwrap();
        assert!(key != parent.borrow().futex_key(a, false).unwrap());
        poke(&child, a, 2);
        assert!(child.borrow().futex_key(a, false).unwrap() == key);
        assert_eq!(byte(&parent, a), 1);
        // New memory at the same address keeps the key; a private operation has its own
        let fixed = anon | flags::MAP_FIXED;
        child
            .borrow_mut()
            .mmap(a, PAGE_SIZE, RW, fixed, None)
            .unwrap();
        assert!(child.borrow().futex_key(a, false).unwrap() == key);
        assert!(child.borrow().futex_key(a, true).unwrap() != key);
        // Shared anonymous memory is the same in both after fork
        let shared = flags::MAP_SHARED | flags::MAP_ANONYMOUS;
        let s = parent
            .borrow_mut()
            .mmap(0, PAGE_SIZE, RW, shared, None)
            .unwrap();
        let child = parent.borrow_mut().fork().unwrap();
        assert!(child.borrow().futex_key(s, false) == parent.borrow().futex_key(s, false));
        assert!(child.borrow().futex_key(s, true) != parent.borrow().futex_key(s, true));
    }

    #[test]
    fn regions_join_adjacent_anonymous_mappings() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = mm.mmap(0, PAGE_SIZE, RW, anon, None).unwrap();
        let b = mm.mmap(0, PAGE_SIZE, RW, anon, None).unwrap();
        let c = mm.mmap(0, PAGE_SIZE, prot::READ, anon, None).unwrap();
        assert_eq!((a - b, b - c), (PAGE_SIZE, PAGE_SIZE));
        let r = mm.regions();
        assert_eq!(r.len(), 2);
        assert_eq!((r[1].start, r[1].end), (b, a + PAGE_SIZE));
        let shared = flags::MAP_SHARED | flags::MAP_ANONYMOUS;
        mm.mmap(0, PAGE_SIZE, RW, shared, None).unwrap();
        mm.mmap(0, PAGE_SIZE, RW, shared, None).unwrap();
        assert_eq!(mm.regions().len(), 4);
    }

    /// The commit check before fork counts VMAs merged as on Linux: adjacent writable private
    /// anonymous mappings count only when together they exceed the limit; a read-only,
    /// `MAP_NORESERVE` or shared mapping in between breaks the run, and does not count itself.
    #[test]
    fn fork_counts_the_commit_of_merged_mappings() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let fixed = anon | flags::MAP_FIXED;
        let base = 0x1000_0000;
        let mb = 1 << 20;
        // 4 MB + 4 MB back to back: 8 MB
        mm.mmap(base, 4 * mb, RW, fixed, None).unwrap();
        mm.mmap(base + 4 * mb, 4 * mb, RW, fixed, None).unwrap();
        assert!(!mm.commit_too_big(8 * mb));
        assert!(mm.commit_too_big(8 * mb - PAGE_SIZE));
        assert!(!mm.commit_too_big(0));
        // Second half made read-only: broken into 4 MB each
        mm.mprotect(base + 4 * mb, 4 * mb, prot::READ).unwrap();
        assert!(!mm.commit_too_big(5 * mb));
        assert!(mm.commit_too_big(4 * mb - PAGE_SIZE));
        mm.mprotect(base + 4 * mb, 4 * mb, RW).unwrap();
        assert!(mm.commit_too_big(5 * mb));
        // A MAP_NORESERVE piece in between: not counted, and breaks the run
        mm.munmap(base + 4 * mb, 4 * mb).unwrap();
        mm.mmap(
            base + 4 * mb,
            4 * mb,
            RW,
            fixed | flags::MAP_NORESERVE,
            None,
        )
        .unwrap();
        mm.mmap(base + 8 * mb, 4 * mb, RW, fixed, None).unwrap();
        assert!(!mm.commit_too_big(5 * mb));
        // Shared ones are not counted
        let shared = flags::MAP_SHARED | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        mm.mmap(base + 12 * mb, 64 * mb, RW, shared, None).unwrap();
        assert!(!mm.commit_too_big(5 * mb));
        // Mappings with a gap between them are not merged
        mm.mmap(base + 77 * mb, 4 * mb, RW, fixed, None).unwrap();
        assert!(!mm.commit_too_big(5 * mb));
        mm.mmap(base + 76 * mb, mb, RW, fixed, None).unwrap();
        assert!(mm.commit_too_big(5 * mb - PAGE_SIZE));
        assert!(!mm.commit_too_big(5 * mb));
        // The child keeps MAP_NORESERVE too
        let child = mm.fork().unwrap();
        assert!(child.borrow().vmas[&(base + 4 * mb)].noreserve);
    }

    #[test]
    fn memops_pruned_on_unmap_mprotect_and_write_force() {
        let mut mm = Mm::new();
        let base = 0x2000_0000;
        let rx = prot::READ | prot::EXEC;
        mm.map_anonymous(base, 3 * PAGE_SIZE, rx).unwrap();
        let pc0 = base + 0x100;
        let pc1 = base + PAGE_SIZE + 0x100;
        let pc2 = base + 2 * PAGE_SIZE + 0x100;
        mm.memops = vec![
            appine_engine::DbtMemop {
                pc: pc0,
                kind: appine_engine::MEMOP_MEMCPY,
                reserved: 0,
            },
            appine_engine::DbtMemop {
                pc: pc1,
                kind: appine_engine::MEMOP_MEMSET,
                reserved: 0,
            },
            appine_engine::DbtMemop {
                pc: pc2,
                kind: appine_engine::MEMOP_MEMMOVE,
                reserved: 0,
            },
        ];
        let cpu = unsafe { appine_engine::Cpu::new(mm.mmu()) };
        let sync = Arc::new(TaskSync {
            in_guest: std::sync::atomic::AtomicBool::new(false),
            kicker: cpu.kicker(),
            entry: crate::task::KernelEntry::default(),
        });
        // Removing EXEC on page 0 prunes pc0.
        mm.mprotect(base, PAGE_SIZE, prot::READ).unwrap();
        mm.sync(&sync);
        assert_eq!(
            mm.memops.iter().map(|m| m.pc).collect::<Vec<_>>(),
            vec![pc1, pc2]
        );

        // Unmapping page 1 prunes pc1.
        mm.munmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        mm.sync(&sync);
        assert_eq!(
            mm.memops.iter().map(|m| m.pc).collect::<Vec<_>>(),
            vec![pc2]
        );

        // Forcing a write (ptrace breakpoint) into page 2 prunes pc2.
        mm.write_force(pc2, &0xd420_0000u32.to_le_bytes(), &sync)
            .unwrap();
        assert!(mm.memops.is_empty());
    }

    #[test]
    fn recycled_stack_tracks_used_range_and_zeroes_on_reuse() {
        let reserve = (3 << 20) + 5 * PAGE_SIZE;
        let initial = 33 * PAGE_SIZE;
        let grow = 4 * PAGE_SIZE;

        let first_base = {
            let mut mm = Mm::new();
            mm.map_stack(initial, reserve).unwrap();
            let start = STACK_TOP - initial;
            {
                let v = &mm.vmas[&start];
                assert_eq!(
                    v.region.used_start.load(Ordering::Relaxed),
                    (reserve - initial) as usize
                );
                assert_eq!(v.region.used_end.load(Ordering::Relaxed), reserve as usize);
            }
            mm.write_kernel(STACK_TOP - 16, &[0x5a; 16]).unwrap();
            mm.write_kernel(start, &[0xa5; 16]).unwrap();

            let grown_start = start - grow;
            assert!(mm.grow_down(grown_start, reserve));
            {
                let v = &mm.vmas[&grown_start];
                assert_eq!(
                    v.region.used_start.load(Ordering::Relaxed),
                    (reserve - initial - grow) as usize
                );
                assert_eq!(v.region.used_end.load(Ordering::Relaxed), reserve as usize);
            }
            mm.write_kernel(grown_start, &[0x3c; 16]).unwrap();
            mm.vmas[&grown_start].region.base.as_ptr() as usize
        };

        let mut mm2 = Mm::new();
        let total = initial + grow;
        mm2.map_stack(total, reserve).unwrap();
        let start = STACK_TOP - total;
        assert_eq!(mm2.vmas[&start].region.base.as_ptr() as usize, first_base);
        let mut buf = [0xffu8; 16];
        mm2.read(UserSlice::new(STACK_TOP - 16, 16), &mut buf)
            .unwrap();
        assert_eq!(buf, [0; 16]);
        mm2.read(UserSlice::new(STACK_TOP - initial, 16), &mut buf)
            .unwrap();
        assert_eq!(buf, [0; 16]);
        mm2.read(UserSlice::new(start, 16), &mut buf).unwrap();
        assert_eq!(buf, [0; 16]);
    }

    #[test]
    fn recycled_unmaps_regions_at_or_above_max_discard() {
        // An oversized stack that actually grows to MAX_DISCARD is unmapped instead of recycled.
        let reserve = (3 << 20) + 7 * PAGE_SIZE;
        let initial = 33 * PAGE_SIZE;
        {
            let mut mm = Mm::new();
            mm.map_stack(initial, reserve).unwrap();
            let target = STACK_TOP - recycled::MAX_DISCARD as u64;
            assert!(mm.grow_down(target, reserve));
            let v = &mm.vmas[&target];
            assert_eq!(
                v.region.used_end.load(Ordering::Relaxed)
                    - v.region.used_start.load(Ordering::Relaxed),
                recycled::MAX_DISCARD
            );
        }
        assert!(recycled::take(reserve as usize, false).is_none());

        // An ordinary anonymous mapping of >= MAX_DISCARD is also unmapped rather than recycled.
        let large = recycled::MAX_DISCARD as u64 + 9 * PAGE_SIZE;
        {
            let mut mm = Mm::new();
            mm.map_anonymous(0x2000_0000, large, RW).unwrap();
        }
        assert!(recycled::take(large as usize, true).is_none());
    }

    #[test]
    fn fork_and_brk_track_used_range_on_reserved_regions() {
        let mut parent = Mm::new();
        let stack_len = 33 * PAGE_SIZE;
        parent.map_stack(stack_len, STACK_SIZE).unwrap();
        parent.set_brk(0x50_0000);
        assert_eq!(parent.brk(0x50_2000, false), 0x50_2000);
        assert_eq!(parent.brk(0x50_5000, false), 0x50_5000);

        let stack_start = STACK_TOP - stack_len;
        let heap_len = 0x5000usize;
        assert_eq!(
            parent.vmas[&stack_start]
                .region
                .used_start
                .load(Ordering::Relaxed),
            (STACK_SIZE - stack_len) as usize
        );
        assert_eq!(
            parent.vmas[&stack_start]
                .region
                .used_end
                .load(Ordering::Relaxed),
            STACK_SIZE as usize
        );
        assert_eq!(
            parent.vmas[&0x50_0000]
                .region
                .used_start
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            parent.vmas[&0x50_0000]
                .region
                .used_end
                .load(Ordering::Relaxed),
            heap_len
        );

        let child = parent.fork().unwrap();
        let child = child.borrow();
        assert_eq!(
            child.vmas[&stack_start]
                .region
                .used_start
                .load(Ordering::Relaxed),
            (STACK_SIZE - stack_len) as usize
        );
        assert_eq!(
            child.vmas[&stack_start]
                .region
                .used_end
                .load(Ordering::Relaxed),
            STACK_SIZE as usize
        );
        assert_eq!(
            child.vmas[&0x50_0000]
                .region
                .used_start
                .load(Ordering::Relaxed),
            0
        );
        assert_eq!(
            child.vmas[&0x50_0000]
                .region
                .used_end
                .load(Ordering::Relaxed),
            heap_len
        );
    }

    #[test]
    fn find_free_aligns_large_mappings_to_superpage() {
        let mut mm = Mm::new();
        // A small mapping first shifts the top-down frontier off a 2 MiB boundary.
        let small = mm
            .mmap(
                0,
                PAGE_SIZE,
                prot::READ | prot::WRITE,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        assert_ne!(small % LEAF_SPAN, 0);
        // A >= 2 MiB mapping is still placed on an exact 2 MiB boundary.
        let big = mm
            .mmap(
                0,
                LEAF_SPAN + 0x86000,
                prot::READ | prot::WRITE,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        assert_eq!(big % LEAF_SPAN, 0);
        // Fragmented fallback: if the only gap is >= LEAF_SPAN wide but contains no 2 MiB-aligned
        // range of length LEAF_SPAN, find_free still returns a page-aligned address.
        let base = (mmap_min() + LEAF_SPAN) & !(LEAF_SPAN - 1);
        mm.mmap_top = base + LEAF_SPAN + PAGE_SIZE;
        mm.vmas.clear();
        let _ = mm
            .mmap(
                mmap_min(),
                (base + PAGE_SIZE) - mmap_min(),
                0,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED | flags::MAP_NORESERVE,
                None,
            )
            .unwrap();
        let fallback = mm.find_free(LEAF_SPAN).unwrap();
        assert_eq!(fallback, base + PAGE_SIZE);
        assert_ne!(fallback % LEAF_SPAN, 0);
    }

    #[test]
    fn fault_in_widens_read_only_file_mappings_only() {
        use std::os::fd::AsRawFd;

        let file = appine_hal::memfd(c"mm-fault-span").unwrap();
        let file_len = 20 * LEAF_SPAN; // 40 MiB
        file.set_len(file_len).unwrap();
        let map_len = file_len + 2 * LEAF_SPAN; // 4 MiB past EOF

        let mut mm = Mm::new();
        // Read-only PrivateFile: fault_in fills a full FILE_FAULT_SPAN (16 MiB) and stops at EOF.
        let ro_priv = mm
            .mmap(
                0,
                map_len,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert_eq!(ro_priv % LEAF_SPAN, 0);
        assert_eq!(
            mm.mmu().next_present(ro_priv, ro_priv + map_len),
            ro_priv + map_len
        );
        assert!(mm.fault_in(ro_priv + PAGE_SIZE, prot::READ));
        let first_end = ((ro_priv + PAGE_SIZE) | (FILE_FAULT_SPAN - 1)) + 1;
        assert!(
            mm.mmu()
                .translate(first_end - PAGE_SIZE, prot::READ)
                .is_some()
        );
        assert_eq!(
            mm.mmu().next_present(first_end, ro_priv + map_len),
            ro_priv + map_len
        );
        // Faulting near EOF clips strictly at file_len (pages past EOF remain unmapped).
        assert!(mm.fault_in(ro_priv + file_len - PAGE_SIZE, prot::READ));
        assert!(
            mm.mmu()
                .translate(ro_priv + file_len - PAGE_SIZE, prot::READ)
                .is_some()
        );
        assert_eq!(
            mm.mmu().next_present(ro_priv + file_len, ro_priv + map_len),
            ro_priv + map_len
        );

        // Read-only Shared file: also fills FILE_FAULT_SPAN.
        let ro_shared = mm
            .mmap(
                0,
                file_len,
                prot::READ,
                flags::MAP_SHARED,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert!(mm.fault_in(ro_shared + PAGE_SIZE, prot::READ));
        let shared_end = ((ro_shared + PAGE_SIZE) | (FILE_FAULT_SPAN - 1)) + 1;
        assert!(
            mm.mmu()
                .translate(shared_end - PAGE_SIZE, prot::READ)
                .is_some()
        );
        assert_eq!(
            mm.mmu().next_present(shared_end, ro_shared + file_len),
            ro_shared + file_len
        );

        // Writable PrivateFile: keeps 2 MiB LEAF_SPAN granularity.
        let rw_priv = mm
            .mmap(
                0,
                file_len,
                RW,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert!(mm.fault_in(rw_priv + PAGE_SIZE, prot::READ));
        let last = rw_priv + LEAF_SPAN - PAGE_SIZE;
        assert!(mm.mmu().translate(last, prot::READ).is_some());
        assert_eq!(
            mm.mmu().translate(last, prot::WRITE).is_some(),
            appine_hal::pagemap_readable()
        );
        assert!(mm.translate(last, prot::WRITE).is_some());
        assert_eq!(
            mm.mmu()
                .next_present(rw_priv + LEAF_SPAN, rw_priv + file_len),
            rw_priv + file_len
        );
    }

    #[test]
    fn madvise_prefill_and_ranges_respect_vma_kinds_and_eof() {
        use std::os::fd::AsRawFd;

        let file = appine_hal::memfd(c"mm-advise").unwrap();
        let file_len = 12 * LEAF_SPAN; // 24 MiB
        file.set_len(file_len).unwrap();
        let map_len = file_len + 2 * LEAF_SPAN; // 4 MiB past EOF

        let mut mm = Mm::new();
        let ro_file = mm
            .mmap(
                0,
                map_len,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        // Split the read-only file mapping with set_dontdump so two adjacent VMAs share one
        // HostRegion and must coalesce in advise_ranges.
        mm.set_dontdump(ro_file, 2 * LEAF_SPAN, true).unwrap();

        let rw_file = mm
            .mmap(
                0,
                4 * LEAF_SPAN,
                RW,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        let anon_untouched = mm
            .mmap(
                0,
                2 * LEAF_SPAN,
                prot::READ,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        let anon_written = mm
            .mmap(
                0,
                2 * LEAF_SPAN,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.write_kernel(anon_written, b"x").unwrap();
        let reserved = mm
            .mmap(
                0,
                2 * LEAF_SPAN,
                0,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();

        // prefill_file_ptes fills only read-only non-FUSE file VMAs up to file_len.
        mm.prefill_file_ptes(ro_file, map_len);
        assert!(mm.mmu().translate(ro_file, prot::READ).is_some());
        assert!(
            mm.mmu()
                .translate(ro_file + file_len - PAGE_SIZE, prot::READ)
                .is_some()
        );
        assert_eq!(
            mm.mmu().next_present(ro_file + file_len, ro_file + map_len),
            ro_file + map_len
        );

        mm.prefill_file_ptes(rw_file, 4 * LEAF_SPAN);
        assert_eq!(
            mm.mmu().next_present(rw_file, rw_file + 4 * LEAF_SPAN),
            rw_file + 4 * LEAF_SPAN
        );
        mm.prefill_file_ptes(anon_untouched, 2 * LEAF_SPAN);
        assert_eq!(
            mm.mmu()
                .next_present(anon_untouched, anon_untouched + 2 * LEAF_SPAN),
            anon_untouched + 2 * LEAF_SPAN
        );

        // advise_ranges(file_only = true): coalesces the split read-only file VMAs into one host
        // slice clipped at file_len, and skips anonymous and reserved VMAs.
        let file_ranges = mm.advise_ranges(ro_file, map_len, true);
        assert_eq!(file_ranges.len(), 1);
        assert_eq!(file_ranges[0].len, file_len as usize);
        for r in file_ranges {
            r.apply(libc::MADV_SEQUENTIAL);
        }
        assert!(
            mm.advise_ranges(anon_untouched, 2 * LEAF_SPAN, true)
                .is_empty()
        );
        assert!(
            mm.advise_ranges(anon_written, 2 * LEAF_SPAN, true)
                .is_empty()
        );
        assert!(mm.advise_ranges(reserved, 2 * LEAF_SPAN, true).is_empty());

        // advise_ranges(file_only = false): includes file and written anonymous VMAs, skips
        // untouched anonymous and reserved VMAs, and applies MADV_WILLNEED cleanly.
        assert!(
            mm.advise_ranges(anon_untouched, 2 * LEAF_SPAN, false)
                .is_empty()
        );
        assert!(mm.advise_ranges(reserved, 2 * LEAF_SPAN, false).is_empty());
        let written_ranges = mm.advise_ranges(anon_written, 2 * LEAF_SPAN, false);
        assert_eq!(written_ranges.len(), 1);
        for r in written_ranges {
            r.apply(libc::MADV_WILLNEED);
        }
        let willneed_file = mm.advise_ranges(ro_file, map_len, false);
        assert_eq!(willneed_file.len(), 1);
        assert_eq!(willneed_file[0].len, file_len as usize);
        for r in willneed_file {
            r.apply(libc::MADV_WILLNEED);
        }
    }

    #[test]
    fn fault_past_eof_checks_permissions_before_eof() {
        use std::os::fd::AsRawFd;

        let file = appine_hal::memfd(c"mm-eof-perm").unwrap();
        file.set_len(PAGE_SIZE).unwrap();
        let mut mm = Mm::new();

        // PROT_NONE past EOF: must return None (SIGSEGV/SEGV_ACCERR), not SIGBUS.
        let none_map = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                0,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert_eq!(mm.fault_past_eof(none_map + PAGE_SIZE, prot::READ), None);
        assert_eq!(mm.fault_past_eof(none_map + PAGE_SIZE, prot::WRITE), None);

        // Read-only past EOF: write returns None (SIGSEGV), read returns Some(true) (SIGBUS).
        let ro_map = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        assert_eq!(mm.fault_past_eof(ro_map + PAGE_SIZE, prot::WRITE), None);
        assert_eq!(
            mm.fault_past_eof(ro_map + PAGE_SIZE, prot::READ),
            Some(true)
        );
    }

    #[test]
    fn mlock_stops_at_prot_none_and_avoids_ro_and_cow_rss_inflation() {
        let mut mm = Mm::new();
        let base = mm
            .mmap(
                0,
                3 * PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.mprotect(base + PAGE_SIZE, PAGE_SIZE, 0).unwrap();

        // Locking across [RW, PROT_NONE, RW] stops populating at PROT_NONE and returns ENOMEM.
        mm.set_locked(base, 3 * PAGE_SIZE, true).unwrap();
        assert_eq!(mm.populate_mlock(base, 3 * PAGE_SIZE), Err(Errno::ENOMEM));
        assert!(mm.resident_in(base, PAGE_SIZE) >= 1);
        assert_eq!(mm.resident_in(base + 2 * PAGE_SIZE, PAGE_SIZE), 0);

        // Read-only anonymous mlock does not inflate RSS.
        let ro = mm
            .mmap(
                0,
                PAGE_SIZE,
                prot::READ,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        mm.set_locked(ro, PAGE_SIZE, true).unwrap();
        assert_eq!(mm.populate_mlock(ro, PAGE_SIZE), Ok(()));
        assert_eq!(mm.resident_in(ro, PAGE_SIZE), 0);

        // Writable anonymous mlock after fork breaks CoW without double-counting RSS.
        let parent_rc = Mm::new().into_shared();
        let cow_page = {
            let mut parent = parent_rc.borrow_mut();
            let p = parent
                .mmap(
                    0,
                    PAGE_SIZE,
                    RW,
                    flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                    None,
                )
                .unwrap();
            parent.write(UserSlice::new(p, 4), b"abcd").unwrap();
            p
        };
        let child_rc = parent_rc.borrow_mut().fork().unwrap();
        assert!(parent_rc.borrow().cow.borrow().lent.contains(&cow_page));
        {
            let mut child = child_rc.borrow_mut();
            assert_eq!(child.cow_shared(cow_page, cow_page + PAGE_SIZE).0, 1);
            child.set_locked(cow_page, PAGE_SIZE, true).unwrap();
            assert_eq!(child.populate_mlock(cow_page, PAGE_SIZE), Ok(()));
            assert_eq!(child.cow_shared(cow_page, cow_page + PAGE_SIZE).0, 0);
            assert_eq!(child.resident_in(cow_page, PAGE_SIZE), 1);
        }
        // Returning child's loans repossesses them cleanly in the owner.
        drop(child_rc);
        assert!(parent_rc.borrow().cow.borrow().lent.is_empty());
    }

    #[test]
    fn discard_reverts_written_readonly_cow_private_file_without_corrupting_peer() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let mut file = appine_hal::memfd(c"mm-cow-file-discard").unwrap();
        file.write_all(&[b'A'; PAGE_SIZE as usize]).unwrap();

        let mut parent = Mm::new();
        let addr = parent
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE,
                Some((file.as_raw_fd(), 0, false)),
            )
            .unwrap();
        parent.write(UserSlice::new(addr, 4), b"BBBB").unwrap();
        // Make read-only before fork so fork marks the written PrivateFile VMA `cow = true`.
        parent.mprotect(addr, PAGE_SIZE, prot::READ).unwrap();

        let child_rc = parent.fork().unwrap();
        {
            let mut child = child_rc.borrow_mut();
            assert!(child.vmas[&addr].cow);
            let rereads = child.discard(addr, PAGE_SIZE).unwrap();
            assert!(!child.vmas[&addr].cow);
            // Simulate kernel reread if the host did not discard the entire page (anonymous copy).
            for r in rereads {
                child.fill_private(r.addr, &vec![b'A'; r.len as usize]);
            }
            let mut cbuf = [0u8; 4];
            child.read(UserSlice::new(addr, 4), &mut cbuf).unwrap();
            assert_eq!(&cbuf, b"AAAA");
        }
        let mut pbuf = [0u8; 4];
        parent.read(UserSlice::new(addr, 4), &mut pbuf).unwrap();
        assert_eq!(&pbuf, b"BBBB");
    }

    #[test]
    fn shared_maps_published_before_ptes_and_rolled_back_on_failure() {
        let has_range = |mm: &Mm, addr: u64| {
            mm.shared_maps()
                .read()
                .unwrap()
                .iter()
                .any(|&(s, e)| (s..e).contains(&addr))
        };

        let mut mm = Mm::new();
        // 1. Writable shared anonymous mmap publishes in shared_maps.
        let sh = mm
            .mmap(
                0,
                2 * PAGE_SIZE,
                RW,
                flags::MAP_SHARED | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        assert!(has_range(&mm, sh));
        assert!(has_range(&mm, sh + PAGE_SIZE));

        // 2. Private anonymous mmap does not enter shared_maps.
        let priv_a = mm
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                None,
            )
            .unwrap();
        assert!(!has_range(&mm, priv_a));

        // 3. attach_shm publishes in shared_maps, even when mapped read-only (may_write is true).
        let shm = SharedMemory::new(PAGE_SIZE).unwrap();
        let shm_a = mm
            .attach_shm(None, &shm, prot::READ, false, (1, 1))
            .unwrap();
        assert!(has_range(&mm, shm_a));

        // 4. mmap_gpu publishes in shared_maps; deny_write removes it when non-writable.
        let gpu_a = mm
            .mmap_gpu(
                0,
                PAGE_SIZE,
                prot::READ,
                flags::MAP_SHARED,
                mock_gpu(PAGE_SIZE as usize),
            )
            .unwrap();
        assert!(has_range(&mm, gpu_a));
        mm.deny_write(gpu_a, PAGE_SIZE);
        assert!(!has_range(&mm, gpu_a));

        // 5. insert_vma rollback: if map_pages fails (out-of-range guest address), shared_maps is
        //    rolled back cleanly with no stale entry left behind.
        let before = mm.shared_maps().read().unwrap().clone();
        let (region, host) = Mm::new_anonymous(PAGE_SIZE, false).unwrap();
        let bad_vma = mm.new_vma(
            1 << VA_BITS,
            PAGE_SIZE,
            PAGE_SIZE,
            RW,
            Backing::Shared,
            true,
            region,
            host,
        );
        assert!(mm.insert_vma(1 << VA_BITS, bad_vma).is_err());
        assert_eq!(*mm.shared_maps().read().unwrap(), before);

        // 6. mremap move updates shared_maps to the destination and drops the old address.
        let fixed_dst = 0x2000_0000;
        let moved = mm
            .mremap(sh, PAGE_SIZE, 2 * PAGE_SIZE, true, Some(fixed_dst))
            .unwrap();
        assert_eq!(moved, fixed_dst);
        assert!(!has_range(&mm, sh));
        assert!(has_range(&mm, sh + PAGE_SIZE));
        assert!(has_range(&mm, fixed_dst));
        assert!(has_range(&mm, fixed_dst + PAGE_SIZE));

        // 7. mremap_dontunmap keeps both the moved destination and the shared alias at old.
        let (du_dst, refills) = mm.mremap_dontunmap(fixed_dst, PAGE_SIZE, None).unwrap();
        assert!(refills.is_empty());
        assert!(has_range(&mm, fixed_dst));
        assert!(has_range(&mm, du_dst));

        // 8. mremap duplication (old_len == 0) adds the duplicate range.
        let dup_dst = mm.mremap(du_dst, 0, PAGE_SIZE, true, None).unwrap();
        assert!(has_range(&mm, dup_dst));

        // 9. fork populates child's shared_maps directly via insert_vma.
        let child_rc = mm.fork().unwrap();
        assert!(has_range(&child_rc.borrow(), dup_dst));
        assert!(has_range(&child_rc.borrow(), shm_a));
        assert!(!has_range(&child_rc.borrow(), priv_a));

        // 10. munmap removes torn-down ranges from shared_maps.
        mm.munmap(dup_dst, PAGE_SIZE).unwrap();
        assert!(!has_range(&mm, dup_dst));
        assert!(has_range(&mm, du_dst));
    }

    #[test]
    fn madvise_gap_semantics_match_linux() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let base = 0x3000_0000;
        // Layout: [p0: anon, p1: gap, p2: anon]
        mm.mmap(base, 3 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.munmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();

        // MADV_DONTNEED across [p0, gap, p2]: zeroes both p0 and p2, returns ENOMEM.
        mm.write(UserSlice::new(base, 4), b"AAAA").unwrap();
        mm.write(UserSlice::new(base + 2 * PAGE_SIZE, 4), b"BBBB")
            .unwrap();
        let (rereads, res) = mm.discard_range(base, 3 * PAGE_SIZE, false);
        assert!(rereads.is_empty());
        assert_eq!(res, Err(Errno::ENOMEM));
        let mut b0 = [1u8; 4];
        let mut b2 = [1u8; 4];
        mm.read(UserSlice::new(base, 4), &mut b0).unwrap();
        mm.read(UserSlice::new(base + 2 * PAGE_SIZE, 4), &mut b2)
            .unwrap();
        assert_eq!(&b0, &[0; 4]);
        assert_eq!(&b2, &[0; 4]);

        // MADV_DONTNEED across [gap, locked p2]: EINVAL takes precedence over earlier gap ENOMEM.
        mm.write(UserSlice::new(base + 2 * PAGE_SIZE, 4), b"CCCC")
            .unwrap();
        mm.set_locked(base + 2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();
        let (_, res) = mm.discard_range(base + PAGE_SIZE, 2 * PAGE_SIZE, false);
        assert_eq!(res, Err(Errno::EINVAL));
        mm.read(UserSlice::new(base + 2 * PAGE_SIZE, 4), &mut b2)
            .unwrap();
        assert_eq!(&b2, b"CCCC");
        mm.set_locked(base + 2 * PAGE_SIZE, PAGE_SIZE, false)
            .unwrap();

        // Flag advice (MADV_DONTDUMP / MADV_DONTFORK / MADV_WIPEONFORK) across [p0, gap, p2]:
        // sets flag on both p0 and p2, returns ENOMEM.
        assert_eq!(
            mm.set_dontdump(base, 3 * PAGE_SIZE, true),
            Err(Errno::ENOMEM)
        );
        assert!(mm.vmas[&base].dontdump);
        assert!(mm.vmas[&(base + 2 * PAGE_SIZE)].dontdump);

        assert_eq!(
            mm.set_dontfork(base, 3 * PAGE_SIZE, true),
            Err(Errno::ENOMEM)
        );
        assert!(mm.vmas[&base].dontfork);
        assert!(mm.vmas[&(base + 2 * PAGE_SIZE)].dontfork);

        assert_eq!(
            mm.set_wipeonfork(base, 3 * PAGE_SIZE, true),
            Err(Errno::ENOMEM)
        );
        assert!(mm.vmas[&base].wipeonfork);
        assert!(mm.vmas[&(base + 2 * PAGE_SIZE)].wipeonfork);

        // MADV_WIPEONFORK on [anon p0, file p1, anon p2]: sets p0, stops at file p1 with EINVAL,
        // leaves p2 unchanged.
        mm.set_wipeonfork(base, 3 * PAGE_SIZE, false).unwrap_err();
        let mut f = appine_hal::memfd(c"mm-madvise-gap").unwrap();
        f.write_all(&[b'X'; 3 * PAGE_SIZE as usize]).unwrap();
        mm.mmap(
            base + PAGE_SIZE,
            PAGE_SIZE,
            RW,
            flags::MAP_PRIVATE | flags::MAP_FIXED,
            Some((f.as_raw_fd(), 0, true)),
        )
        .unwrap();
        assert_eq!(
            mm.set_wipeonfork(base, 3 * PAGE_SIZE, true),
            Err(Errno::EINVAL)
        );
        assert!(mm.vmas[&base].wipeonfork);
        assert!(!mm.vmas[&(base + 2 * PAGE_SIZE)].wipeonfork);

        // MADV_FREE on [gap, file p1]: EINVAL overrides earlier gap ENOMEM.
        mm.munmap(base, PAGE_SIZE).unwrap();
        assert_eq!(mm.check_free(base, 2 * PAGE_SIZE), Err(Errno::EINVAL));

        // MADV_REMOVE on [shared p0, gap, shared p2]: zeroes both shared pages, returns ENOMEM.
        let sbase = 0x3100_0000;
        mm.mmap(
            sbase,
            3 * PAGE_SIZE,
            RW,
            flags::MAP_SHARED | flags::MAP_FIXED,
            Some((f.as_raw_fd(), 0, true)),
        )
        .unwrap();
        mm.munmap(sbase + PAGE_SIZE, PAGE_SIZE).unwrap();
        let plan = mm.remove(sbase, 3 * PAGE_SIZE);
        assert!(plan.tmpfs.is_empty() && plan.fuse.is_empty());
        assert_eq!(plan.result, Err(Errno::ENOMEM));
        mm.read(UserSlice::new(sbase, 4), &mut b0).unwrap();
        mm.read(UserSlice::new(sbase + 2 * PAGE_SIZE, 4), &mut b2)
            .unwrap();
        assert_eq!(&b0, &[0; 4]);
        assert_eq!(&b2, &[0; 4]);

        // MADV_REMOVE on [gap, read-only shared p2]: EACCES overrides earlier gap ENOMEM.
        let ro_base = 0x3200_0000;
        mm.mmap(
            ro_base + PAGE_SIZE,
            PAGE_SIZE,
            prot::READ,
            flags::MAP_SHARED | flags::MAP_FIXED,
            Some((f.as_raw_fd(), 0, false)),
        )
        .unwrap();
        let plan = mm.remove(ro_base, 2 * PAGE_SIZE);
        assert_eq!(plan.result, Err(Errno::EACCES));
    }

    #[test]
    fn mlock_munlock_mincore_and_msync_gap_semantics() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let base = 0x3400_0000;
        // Layout: [p0, gap, p2]
        mm.mmap(base, 3 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.munmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();

        // mlock stops at the first gap: p0 locked, p2 untouched, returns ENOMEM.
        assert_eq!(mm.set_locked(base, 3 * PAGE_SIZE, true), Err(Errno::ENOMEM));
        assert!(mm.vmas[&base].locked);
        assert!(!mm.vmas[&(base + 2 * PAGE_SIZE)].locked);

        // mlock starting in a gap locks nothing.
        assert_eq!(
            mm.set_locked(base + PAGE_SIZE, 2 * PAGE_SIZE, true),
            Err(Errno::ENOMEM)
        );
        assert!(!mm.vmas[&(base + 2 * PAGE_SIZE)].locked);

        // munlock stops at the first gap: p0 unlocked, p2 remains locked, returns ENOMEM.
        mm.set_locked(base + 2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();
        assert_eq!(
            mm.set_locked(base, 3 * PAGE_SIZE, false),
            Err(Errno::ENOMEM)
        );
        assert!(!mm.vmas[&base].locked);
        assert!(mm.vmas[&(base + 2 * PAGE_SIZE)].locked);

        // mincore residency_chunk reads p0, then stops with ENOMEM at the gap.
        mm.write(UserSlice::new(base, 4), b"1234").unwrap();
        let mut buf = Vec::new();
        let next = mm
            .residency_chunk(base, base + 3 * PAGE_SIZE, &mut buf)
            .unwrap();
        assert_eq!(next, base + PAGE_SIZE);
        assert_eq!(buf, [1]);
        assert_eq!(
            mm.residency_chunk(next, base + 3 * PAGE_SIZE, &mut buf),
            Err(Errno::ENOMEM)
        );

        // next_msync skips gaps and reports locked VMAs and shared file sync targets.
        let mut f = appine_hal::memfd(c"mm-msync-gap").unwrap();
        f.write_all(&[b'M'; 3 * PAGE_SIZE as usize]).unwrap();
        let fbase = 0x3500_0000;
        mm.mmap(
            fbase,
            3 * PAGE_SIZE,
            RW,
            flags::MAP_SHARED | flags::MAP_FIXED,
            Some((f.as_raw_fd(), 0, true)),
        )
        .unwrap();
        mm.munmap(fbase + PAGE_SIZE, PAGE_SIZE).unwrap();
        mm.set_locked(fbase + 2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();

        match mm.next_msync(fbase, fbase + 3 * PAGE_SIZE, true) {
            MsyncStep::Vma {
                start,
                stop,
                locked,
                target,
            } => {
                assert_eq!((start, stop, locked), (fbase, fbase + PAGE_SIZE, false));
                assert!(matches!(target, Some(MsyncTarget::Host(_))));
            }
            MsyncStep::Unmapped => panic!("expected first shared file VMA"),
        }
        match mm.next_msync(fbase + PAGE_SIZE, fbase + 3 * PAGE_SIZE, true) {
            MsyncStep::Vma {
                start,
                stop,
                locked,
                target,
            } => {
                assert_eq!(
                    (start, stop, locked),
                    (fbase + 2 * PAGE_SIZE, fbase + 3 * PAGE_SIZE, true)
                );
                assert!(matches!(target, Some(MsyncTarget::Host(_))));
            }
            MsyncStep::Unmapped => panic!("expected second shared file VMA after gap"),
        }
        assert!(matches!(
            mm.next_msync(fbase + 3 * PAGE_SIZE, fbase + 4 * PAGE_SIZE, true),
            MsyncStep::Unmapped
        ));
    }

    #[test]
    fn madvise_dontneed_locked_and_lru_locked_checks() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let read4 = |mm: &Mm, addr: u64| {
            let mut b = [1u8; 4];
            mm.read(UserSlice::new(addr, 4), &mut b).unwrap();
            b
        };

        let mut mm = Mm::new();
        let fixed = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS | flags::MAP_FIXED;
        let base = 0x3600_0000;
        // [p0: anon, p1: gap, p2: anon]
        mm.mmap(base, 3 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.munmap(base + PAGE_SIZE, PAGE_SIZE).unwrap();
        mm.write(UserSlice::new(base, 4), b"LOCK").unwrap();
        mm.write(UserSlice::new(base + 2 * PAGE_SIZE, 4), b"DATA")
            .unwrap();
        mm.set_locked(base, PAGE_SIZE, true).unwrap();
        mm.set_locked(base + 2 * PAGE_SIZE, PAGE_SIZE, true)
            .unwrap();

        // Locked anon refuses MADV_DONTNEED, MADV_FREE, and MADV_COLD/MADV_PAGEOUT (check_lru).
        assert_eq!(
            mm.discard_range(base, PAGE_SIZE, false).1,
            Err(Errno::EINVAL)
        );
        assert_eq!(mm.check_free(base, PAGE_SIZE), Err(Errno::EINVAL));
        assert_eq!(mm.check_lru(base, PAGE_SIZE), Err(Errno::EINVAL));
        // EINVAL on locked VMA overrides an earlier unmapped gap.
        assert_eq!(
            mm.check_free(base + PAGE_SIZE, 2 * PAGE_SIZE),
            Err(Errno::EINVAL)
        );
        assert_eq!(
            mm.check_lru(base + PAGE_SIZE, 2 * PAGE_SIZE),
            Err(Errno::EINVAL)
        );

        // MADV_DONTNEED_LOCKED across [locked p0, gap, locked p2]: zeroes both, returns ENOMEM,
        // and keeps both VMAs locked.
        let (rereads, res) = mm.discard_range(base, 3 * PAGE_SIZE, true);
        assert!(rereads.is_empty());
        assert_eq!(res, Err(Errno::ENOMEM));
        assert_eq!(read4(&mm, base), [0; 4]);
        assert_eq!(read4(&mm, base + 2 * PAGE_SIZE), [0; 4]);
        assert!(mm.vmas[&base].locked);
        assert!(mm.vmas[&(base + 2 * PAGE_SIZE)].locked);
        // Subsequent MADV_DONTNEED still returns EINVAL because MADV_DONTNEED_LOCKED did not unlock.
        assert_eq!(
            mm.discard_range(base, PAGE_SIZE, false).1,
            Err(Errno::EINVAL)
        );

        // Unlocked private anon passes check_free and check_lru, and MADV_DONTNEED_LOCKED works on
        // unlocked ranges too.
        mm.set_locked(base, PAGE_SIZE, false).unwrap();
        mm.set_locked(base + 2 * PAGE_SIZE, PAGE_SIZE, false)
            .unwrap();
        assert_eq!(mm.check_free(base, PAGE_SIZE), Ok(()));
        assert_eq!(mm.check_lru(base, PAGE_SIZE), Ok(()));
        assert_eq!(mm.check_free(base, 3 * PAGE_SIZE), Err(Errno::ENOMEM));
        assert_eq!(mm.check_lru(base, 3 * PAGE_SIZE), Err(Errno::ENOMEM));
        mm.write(UserSlice::new(base, 4), b"UNLK").unwrap();
        assert_eq!(mm.discard_range(base, PAGE_SIZE, true).1, Ok(()));
        assert_eq!(read4(&mm, base), [0; 4]);

        // MADV_DONTNEED_LOCKED on locked CoW anonymous memory settles CoW without corrupting peer.
        let parent_rc = Mm::new().into_shared();
        let cow_addr = {
            let mut p = parent_rc.borrow_mut();
            let a = p
                .mmap(
                    0,
                    PAGE_SIZE,
                    RW,
                    flags::MAP_PRIVATE | flags::MAP_ANONYMOUS,
                    None,
                )
                .unwrap();
            p.write(UserSlice::new(a, 4), b"PEEK").unwrap();
            a
        };
        let child_rc = parent_rc.borrow_mut().fork().unwrap();
        {
            let mut child = child_rc.borrow_mut();
            child.set_locked(cow_addr, PAGE_SIZE, true).unwrap();
            assert_eq!(
                child.discard_range(cow_addr, PAGE_SIZE, false).1,
                Err(Errno::EINVAL)
            );
            assert_eq!(child.discard_range(cow_addr, PAGE_SIZE, true).1, Ok(()));
            assert!(child.vmas[&cow_addr].locked);
            assert_eq!(read4(&child, cow_addr), [0; 4]);
        }
        assert_eq!(&read4(&parent_rc.borrow(), cow_addr), b"PEEK");

        // Locked private file: MADV_DONTNEED_LOCKED reverts written data to file contents.
        let mut f = appine_hal::memfd(c"mm-dontneed-locked-file").unwrap();
        f.write_all(&[b'F'; PAGE_SIZE as usize]).unwrap();
        let pf = mm
            .mmap(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        mm.write(UserSlice::new(pf, 4), b"EDIT").unwrap();
        mm.set_locked(pf, PAGE_SIZE, true).unwrap();
        assert_eq!(mm.check_lru(pf, PAGE_SIZE), Err(Errno::EINVAL));
        let (rereads, res) = mm.discard_range(pf, PAGE_SIZE, true);
        assert_eq!(res, Ok(()));
        for r in rereads {
            mm.fill_private(r.addr, &vec![b'F'; r.len as usize]);
        }
        assert!(mm.vmas[&pf].locked);
        assert_eq!(&read4(&mm, pf), b"FFFF");
        mm.set_locked(pf, PAGE_SIZE, false).unwrap();
        assert_eq!(mm.check_lru(pf, PAGE_SIZE), Ok(()));
        assert_eq!(mm.check_free(pf, PAGE_SIZE), Err(Errno::EINVAL));

        // GPU (VM_PFNMAP) mapping refuses DONTNEED, DONTNEED_LOCKED, FREE, and COLD/PAGEOUT.
        let gpu_a = mm
            .mmap_gpu(
                0,
                PAGE_SIZE,
                RW,
                flags::MAP_SHARED,
                mock_gpu(PAGE_SIZE as usize),
            )
            .unwrap();
        assert_eq!(
            mm.discard_range(gpu_a, PAGE_SIZE, false).1,
            Err(Errno::EINVAL)
        );
        assert_eq!(
            mm.discard_range(gpu_a, PAGE_SIZE, true).1,
            Err(Errno::EINVAL)
        );
        assert_eq!(mm.check_free(gpu_a, PAGE_SIZE), Err(Errno::EINVAL));
        assert_eq!(mm.check_lru(gpu_a, PAGE_SIZE), Err(Errno::EINVAL));
    }

    #[test]
    fn madvise_populate_read_and_write_semantics() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        fn run_populate(mm: &mut Mm, addr: u64, len: u64, write: bool) -> Result<(), Errno> {
            let mut walk = PopulateWalk::new(addr, len);
            loop {
                match mm.populate_step(&mut walk, write)? {
                    PopulateStep::Done => break,
                    PopulateStep::Advise(range) => range.apply(libc::MADV_WILLNEED),
                    PopulateStep::Fill(_, _) => panic!("unexpected FUSE fill in non-FUSE test"),
                }
            }
            if walk.has_gap {
                Err(Errno::ENOMEM)
            } else {
                Ok(())
            }
        }

        let mut mm = Mm::new();
        let priv_anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let fixed = priv_anon | flags::MAP_FIXED;

        // Permission checks: EINVAL when VMA lacks PROT_READ (POPULATE_READ) or PROT_WRITE
        // (POPULATE_WRITE).
        for (prot, read_res, write_res) in [
            (0, Err(Errno::EINVAL), Err(Errno::EINVAL)),
            (prot::READ, Ok(()), Err(Errno::EINVAL)),
            (prot::WRITE, Err(Errno::EINVAL), Ok(())),
            (prot::EXEC, Err(Errno::EINVAL), Err(Errno::EINVAL)),
        ] {
            let a = mm.mmap(0, PAGE_SIZE, prot, priv_anon, None).unwrap();
            assert_eq!(run_populate(&mut mm, a, PAGE_SIZE, false), read_res);
            assert_eq!(run_populate(&mut mm, a, PAGE_SIZE, true), write_res);
        }

        // Large (> EAGER_MAX) anonymous mapping: POPULATE_READ installs PTEs and makes pages
        // resident.
        let big_ro = mm.mmap(0, 2 * LEAF_SPAN, RW, priv_anon, None).unwrap();
        assert_eq!(
            mm.mmu().next_present(big_ro, big_ro + 2 * LEAF_SPAN),
            big_ro + 2 * LEAF_SPAN
        );
        run_populate(&mut mm, big_ro, 2 * PAGE_SIZE, false).unwrap();
        assert!(mm.mmu().translate(big_ro, prot::READ).is_some());
        assert!(mm.mmu().translate(big_ro + PAGE_SIZE, prot::READ).is_some());
        assert_eq!(
            mm.residency(big_ro, 2 * PAGE_SIZE).unwrap(),
            vec![true, true]
        );

        assert!(!mm.vmas[&big_ro].has_anon_vma.get());
        run_populate(&mut mm, big_ro, PAGE_SIZE, true).unwrap();
        assert!(mm.vmas[&big_ro].has_anon_vma.get());
        assert!(
            mm.mmu()
                .translate(big_ro + PAGE_SIZE, prot::WRITE)
                .is_some()
        );

        // Fork + CoW: POPULATE_READ preserves CoW sharing; POPULATE_WRITE breaks CoW.
        let parent_rc = Mm::new().into_shared();
        let cow = {
            let mut p = parent_rc.borrow_mut();
            let a = p.mmap(0, 2 * PAGE_SIZE, RW, priv_anon, None).unwrap();
            p.write(UserSlice::new(a, 4), b"ONE1").unwrap();
            p.write(UserSlice::new(a + PAGE_SIZE, 4), b"TWO2").unwrap();
            a
        };
        let child_rc = parent_rc.borrow_mut().fork().unwrap();
        {
            let mut child = child_rc.borrow_mut();
            assert_eq!(child.cow_shared(cow, cow + 2 * PAGE_SIZE).0, 2);
            run_populate(&mut child, cow, PAGE_SIZE, false).unwrap();
            assert_eq!(child.cow_shared(cow, cow + 2 * PAGE_SIZE).0, 2);
            run_populate(&mut child, cow + PAGE_SIZE, PAGE_SIZE, true).unwrap();
            assert_eq!(child.cow_shared(cow, cow + PAGE_SIZE).0, 1);
            assert_eq!(child.cow_shared(cow + PAGE_SIZE, cow + 2 * PAGE_SIZE).0, 0);
            assert!(
                child
                    .mmu()
                    .translate(cow + PAGE_SIZE, prot::WRITE)
                    .is_some()
            );
            let mut buf = [0u8; 4];
            child
                .read(UserSlice::new(cow + PAGE_SIZE, 4), &mut buf)
                .unwrap();
            assert_eq!(&buf, b"TWO2");
        }
        drop(child_rc);
        assert!(parent_rc.borrow().cow.borrow().lent.is_empty());

        // Gaps: [rw p0, gap, rw p2] populates both and returns ENOMEM; [gap, PROT_NONE] -> EINVAL.
        let gbase = 0x3700_0000;
        mm.mmap(gbase, 3 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.munmap(gbase + PAGE_SIZE, PAGE_SIZE).unwrap();
        assert_eq!(
            run_populate(&mut mm, gbase, 3 * PAGE_SIZE, true),
            Err(Errno::ENOMEM)
        );
        assert_eq!(mm.residency(gbase, PAGE_SIZE).unwrap(), vec![true]);
        assert_eq!(
            mm.residency(gbase + 2 * PAGE_SIZE, PAGE_SIZE).unwrap(),
            vec![true]
        );
        mm.mprotect(gbase + 2 * PAGE_SIZE, PAGE_SIZE, 0).unwrap();
        assert_eq!(
            run_populate(&mut mm, gbase + PAGE_SIZE, 2 * PAGE_SIZE, false),
            Err(Errno::EINVAL)
        );

        // File mappings: Advise step on large (>= 64 KB) file, EFAULT past EOF with partial
        // population, EINVAL on PROT_NONE past EOF, and extent refresh after file growth.
        let mut f = appine_hal::memfd(c"mm-populate-file").unwrap();
        let file_bytes = 20 * PAGE_SIZE; // 80 KB >= ADVISE_MIN (64 KB)
        f.write_all(&vec![b'P'; file_bytes as usize]).unwrap();
        let fm = mm
            .mmap(
                0,
                file_bytes + PAGE_SIZE,
                RW,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        // First step on a >= 64 KB file requests unlocked MADV_WILLNEED readahead.
        let mut walk = PopulateWalk::new(fm, file_bytes);
        match mm.populate_step(&mut walk, false).unwrap() {
            PopulateStep::Advise(range) => {
                assert_eq!(walk.cursor, fm);
                assert_eq!(walk.warmed_until, fm + file_bytes);
                assert!(!walk.has_gap);
                range.apply(libc::MADV_WILLNEED);
                assert!(matches!(
                    mm.populate_step(&mut walk, false).unwrap(),
                    PopulateStep::Done
                ));
                assert!(!walk.has_gap);
            }
            _ => panic!("expected Advise step for >= 64 KB regular file"),
        }
        // Past EOF returns EFAULT.
        assert_eq!(
            run_populate(&mut mm, fm, file_bytes + PAGE_SIZE, false),
            Err(Errno::EFAULT)
        );
        // PROT_NONE past EOF checks permissions first -> EINVAL.
        let pnf = mm
            .mmap(
                0,
                file_bytes + PAGE_SIZE,
                0,
                flags::MAP_PRIVATE,
                Some((f.as_raw_fd(), 0, true)),
            )
            .unwrap();
        assert_eq!(
            run_populate(&mut mm, pnf + file_bytes, PAGE_SIZE, false),
            Err(Errno::EINVAL)
        );
        // After extending the file, the previously past-EOF page populates cleanly.
        f.set_len(file_bytes + PAGE_SIZE).unwrap();
        assert_eq!(
            run_populate(&mut mm, fm + file_bytes, PAGE_SIZE, true),
            Ok(())
        );

        // Partial failure across VMAs: [rw p0, past-EOF file p1, rw p2] populates p0, returns
        // EFAULT at p1, and leaves p2 unpopulated.
        let small = appine_hal::memfd(c"mm-populate-eof").unwrap();
        small.set_len(PAGE_SIZE).unwrap();
        let pbase = 0x3800_0000;
        mm.mmap(pbase, 3 * PAGE_SIZE, RW, fixed, None).unwrap();
        mm.mmap(
            pbase + PAGE_SIZE,
            PAGE_SIZE,
            RW,
            flags::MAP_PRIVATE | flags::MAP_FIXED,
            Some((small.as_raw_fd(), PAGE_SIZE, true)),
        )
        .unwrap();
        assert_eq!(
            run_populate(&mut mm, pbase, 3 * PAGE_SIZE, true),
            Err(Errno::EFAULT)
        );
        assert_eq!(mm.residency(pbase, PAGE_SIZE).unwrap(), vec![true]);
        assert_eq!(
            mm.residency(pbase + 2 * PAGE_SIZE, PAGE_SIZE).unwrap(),
            vec![false]
        );

        // FUSE Fill mapping: requests Fill for unread pages, installs PTEs once filled, and
        // returns EFAULT past EOF.
        let fuse_host = appine_hal::memfd(c"mm-populate-fuse").unwrap();
        fuse_host.set_len(PAGE_SIZE).unwrap();
        let source = crate::fd::OpenFile::new(crate::fd::FileKind::Host(-1), 0);
        let fill = Fill::new(fuse_host, PAGE_SIZE, source);
        let fa = mm
            .mmap_fill(0, 2 * PAGE_SIZE, RW, flags::MAP_PRIVATE, (fill.clone(), 0))
            .unwrap();
        let mut fwalk = PopulateWalk::new(fa, 2 * PAGE_SIZE);
        match mm.populate_step(&mut fwalk, true).unwrap() {
            PopulateStep::Fill(_, page) => {
                assert_eq!(fwalk.cursor, fa);
                assert_eq!(page, 0);
                assert!(!fwalk.has_gap);
            }
            _ => panic!("expected Fill step for unread FUSE page"),
        }
        fill.store((0, PAGE_SIZE), &vec![b'U'; PAGE_SIZE as usize], true)
            .unwrap();
        // Now page 0 succeeds and page 1 (past EOF) fails with EFAULT.
        assert_eq!(
            mm.populate_step(&mut fwalk, true).err(),
            Some(Errno::EFAULT)
        );
        assert!(mm.mmu().translate(fa, prot::WRITE).is_some());
        let mut fbuf = [0u8; 4];
        mm.read(UserSlice::new(fa, 4), &mut fbuf).unwrap();
        assert_eq!(&fbuf, b"UUUU");
    }

    #[test]
    fn code_group_drop_preserves_sources_for_surviving_and_pooled_members() {
        use std::io::Write;
        use std::os::fd::AsRawFd;

        if appine_engine::DbtSpace::new(0, appine_engine::DbtRegs::Default).is_none() {
            return;
        }
        // Build two code files with valid aarch64 instructions: movz x0, #imm; svc #0.
        let mut exe_file = appine_hal::memfd(c"cg-exe").unwrap();
        let mut lib_file = appine_hal::memfd(c"cg-lib").unwrap();
        let write_prog = |f: &mut std::fs::File, imm: u16| {
            let mut page = vec![0u8; PAGE_SIZE as usize];
            let insns = [0xd280_0000u32 | ((imm as u32) << 5), 0xd400_0001u32];
            for (i, w) in insns.iter().enumerate() {
                page[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
            }
            f.write_all(&page).unwrap();
        };
        write_prog(&mut exe_file, 11);
        write_prog(&mut lib_file, 42);

        const EXE_ADDR: u64 = 0x4000_0000;
        const LIB_ADDR: u64 = 0x5000_0000;
        let rx = prot::READ | prot::EXEC;
        let fixed = flags::MAP_PRIVATE | flags::MAP_FIXED;
        let map_trusted = |mm: &mut Mm, addr: u64, fd: i32, ino: u64| {
            mm.mmap(addr, PAGE_SIZE, rx, fixed, Some((fd, 0, false)))
                .unwrap();
            let v = mm.vmas.get_mut(&addr).unwrap();
            v.file_id = Some((77, ino, 0));
            v.content = Some((999, PAGE_SIZE));
        };

        // Pick a unique exe key so this test never collides with pooled instances from other tests.
        let key = 0x5a5a_0000_0000_7701u64;
        let groups: CodeGroups = RefCell::new(Vec::new());

        // Member 1 maps both exe and lib, founds the group, and translates both blocks.
        let mut mm1 = Mm::new();
        mm1.exe = Some(key);
        map_trusted(&mut mm1, EXE_ADDR, exe_file.as_raw_fd(), 101);
        map_trusted(&mut mm1, LIB_ADDR, lib_file.as_raw_fd(), 102);
        let cs1 = mm1.code_space(&groups).unwrap();
        assert_eq!(mm1.code_group.as_ref().unwrap().file_sources().len(), 2);

        let run_at = |mm: &Mm, cs: &CodeSpace, pc: u64| -> (u64, appine_engine::DbtStats) {
            let mut cpu = unsafe { appine_engine::Cpu::new(mm.mmu()) };
            cpu.state_mut().pc = pc;
            let mut dbt = appine_engine::Dbt::attach(&cs.space, cs.tag).unwrap();
            assert_eq!(dbt.run(&mut cpu), appine_engine::Exit::Svc { imm: 0 });
            (cpu.state().x[0], dbt.stats())
        };
        assert_eq!(run_at(&mm1, &cs1, EXE_ADDR).0, 11);
        assert_eq!(run_at(&mm1, &cs1, LIB_ADDR).0, 42);

        // Member 2 joins the same group mapping only exe (not lib).
        let mut mm2 = Mm::new();
        mm2.exe = Some(key);
        map_trusted(&mut mm2, EXE_ADDR, exe_file.as_raw_fd(), 101);
        let cs2 = mm2.code_space(&groups).unwrap();
        assert!(Arc::ptr_eq(&cs1.space, &cs2.space));
        assert_eq!(mm2.code_group.as_ref().unwrap().members.get(), 2);

        // Verify CodeGroup::file_sources excludes the vDSO sentinel.
        mm2.code_group
            .as_ref()
            .unwrap()
            .ranges
            .borrow_mut()
            .push(appine_engine::DbtSource {
                start: 0x6000_0000,
                len: PAGE_SIZE,
                id: CodeGroup::VDSO_ID,
            });
        assert_eq!(mm2.code_group.as_ref().unwrap().file_sources().len(), 2);

        // Drop member 1 first (surviving member 2 still owns the group), then drop member 2 last.
        // Previously member 2's drop called set_sources(&mm2.code_sources()) which lacked lib,
        // so pooled reuse invalidated lib's block instead of parking and reviving it.
        drop(cs1);
        drop(mm1);
        assert_eq!(mm2.code_group.as_ref().unwrap().members.get(), 1);
        drop(cs2);
        drop(mm2);

        // Member 3 starts with only exe mapped (like a freshly exec'd process before ld.so maps
        // shared libraries): it pulls the pooled DbtSpace, trusts exe, and parks lib's block.
        let mut mm3 = Mm::new();
        mm3.exe = Some(key);
        map_trusted(&mut mm3, EXE_ADDR, exe_file.as_raw_fd(), 101);
        let cs3 = mm3.code_space(&groups).unwrap();
        let (x0_exe, st_exe) = run_at(&mm3, &cs3, EXE_ADDR);
        assert_eq!(x0_exe, 11);
        assert_eq!(st_exe.blocks, 0, "exe block should be reused from pool");

        // Now map lib into member 3: lib's parked block must revive without retranslation.
        map_trusted(&mut mm3, LIB_ADDR, lib_file.as_raw_fd(), 102);
        let (x0_lib, st_lib) = run_at(&mm3, &cs3, LIB_ADDR);
        assert_eq!(x0_lib, 42);
        assert_eq!(
            st_lib.blocks, 0,
            "lib block should revive from parked group sources instead of being clobbered on mm2 drop"
        );
    }

    #[test]
    fn mcl_future_and_locked_growth_respect_memlock_limit() {
        let mut mm = Mm::new();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let shared = flags::MAP_SHARED | flags::MAP_ANONYMOUS;

        // An unlocked mapping created before MCL_FUTURE stays unlocked when grown by mremap.
        let unlk = mm.mmap(0, PAGE_SIZE, RW, anon, None).unwrap();
        assert!(!mm.is_locked_at(unlk));
        mm.lock_future = true;

        // brk_limited enforces RLIMIT_MEMLOCK on growth, allows shrinking and same-page growth.
        mm.set_brk(0x2000_0000);
        let limit = 2 * PAGE_SIZE;
        assert_eq!(
            mm.brk_limited(0x2000_0000 + 2 * PAGE_SIZE, false, limit),
            0x2000_0000 + 2 * PAGE_SIZE
        );
        assert_eq!(mm.locked_bytes(), 2 * PAGE_SIZE);
        // Exceeding limit returns the old break unchanged.
        assert_eq!(
            mm.brk_limited(0x2000_0000 + 3 * PAGE_SIZE, false, limit),
            0x2000_0000 + 2 * PAGE_SIZE
        );
        // Shrinking back frees locked bytes.
        assert_eq!(mm.brk_limited(0x2000_0000, false, limit), 0x2000_0000);
        assert_eq!(mm.locked_bytes(), 0);

        // mremap_limited enforces RLIMIT_MEMLOCK on growing/duplicating locked VMAs, not unlocked.
        let lk = mm.mmap(0, 2 * PAGE_SIZE, RW, anon, None).unwrap();
        assert_eq!(mm.locked_bytes(), 2 * PAGE_SIZE);
        assert_eq!(
            mm.mremap_limited(lk, 2 * PAGE_SIZE, 4 * PAGE_SIZE, true, None, 3 * PAGE_SIZE),
            Err(Errno::EAGAIN)
        );
        // Growing the unlocked VMA created before MCL_FUTURE still succeeds.
        let unlk = mm
            .mremap_limited(unlk, PAGE_SIZE, 4 * PAGE_SIZE, true, None, 3 * PAGE_SIZE)
            .unwrap();
        assert!(!mm.is_locked_at(unlk));
        // Duplicating a locked shared VMA (old_len == 0) enforces RLIMIT_MEMLOCK.
        let sh = mm.mmap(0, PAGE_SIZE, RW, shared, None).unwrap();
        assert_eq!(mm.locked_bytes(), 3 * PAGE_SIZE);
        assert_eq!(
            mm.mremap_limited(sh, 0, PAGE_SIZE, true, None, 3 * PAGE_SIZE),
            Err(Errno::EAGAIN)
        );
        // MREMAP_FIXED over `sh` (1 page locked) frees its locked page before checking growth.
        let moved = mm
            .mremap_limited(
                lk,
                2 * PAGE_SIZE,
                3 * PAGE_SIZE,
                true,
                Some(sh),
                3 * PAGE_SIZE,
            )
            .unwrap();
        assert_eq!(moved, sh);
        assert_eq!(mm.locked_bytes(), 3 * PAGE_SIZE);
        mm.munmap(moved, 3 * PAGE_SIZE).unwrap();
        assert_eq!(mm.locked_bytes(), 0);

        // grow_down_limited enforces RLIMIT_MEMLOCK on locked grows-down VMAs only.
        mm.map_stack(PAGE_SIZE, 8 * PAGE_SIZE).unwrap();
        assert_eq!(mm.locked_bytes(), PAGE_SIZE);
        assert!(mm.grow_down_limited(STACK_TOP - 2 * PAGE_SIZE, 8 * PAGE_SIZE, 2 * PAGE_SIZE));
        assert_eq!(mm.locked_bytes(), 2 * PAGE_SIZE);
        assert!(!mm.grow_down_limited(STACK_TOP - 3 * PAGE_SIZE, 8 * PAGE_SIZE, 2 * PAGE_SIZE));
        // Unlocked grows-down VMA is not restricted by RLIMIT_MEMLOCK.
        mm.set_all_locked(false);
        assert!(mm.grow_down_limited(STACK_TOP - 4 * PAGE_SIZE, 8 * PAGE_SIZE, PAGE_SIZE));
    }

    #[test]
    fn writably_shared_cleared_on_store_delete_and_skips_unlinked_files() {
        use crate::vfs::store::{ROOT, Store};
        use std::io::Write;
        use std::os::fd::AsRawFd;

        let dir = std::env::temp_dir().join(format!(
            "appine-writably-shared-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = Store::create(&dir).unwrap();

        let trusted = |mut st: libc::stat| {
            st.st_ctime = 1_000_000;
            st.st_ctime_nsec = 0;
            content_version(&st, st.st_dev, st.st_ino).is_some()
        };
        let map_shared = |mm: &mut Mm, fd, off| {
            mm.mmap(0, PAGE_SIZE, RW, flags::MAP_SHARED, Some((fd, off, true)))
        };

        // 1. A failed writable MAP_SHARED (misaligned offset) must not poison WRITABLY_SHARED.
        let (_, mut failed_file) = store.create_file(ROOT, b"failed", 0o600, 0, 0).unwrap();
        failed_file.write_all(&[0u8; PAGE_SIZE as usize]).unwrap();
        let failed_st = appine_hal::fstat(failed_file.as_raw_fd()).unwrap();
        let mut mm = Mm::new();
        assert_eq!(
            map_shared(&mut mm, failed_file.as_raw_fd(), 1),
            Err(Errno::EINVAL)
        );
        assert!(!content::contains(failed_st.st_dev, failed_st.st_ino));
        assert!(trusted(failed_st));

        // 2. An anonymous memfd (st_nlink == 0) is never inserted into WRITABLY_SHARED and never
        //    receives a trusted content version.
        let (_, mut memfd) = store.create_anonymous(0o600, 0, 0).unwrap();
        memfd.write_all(&[1u8; PAGE_SIZE as usize]).unwrap();
        let memfd_st = appine_hal::fstat(memfd.as_raw_fd()).unwrap();
        assert_eq!(memfd_st.st_nlink, 0);
        let _m = map_shared(&mut mm, memfd.as_raw_fd(), 0).unwrap();
        assert!(!content::contains(memfd_st.st_dev, memfd_st.st_ino));
        assert!(!trusted(memfd_st));

        // 3. A linked regular file mapped MAP_SHARED writable is recorded in WRITABLY_SHARED and
        //    suppresses content_version while linked.
        let (_, mut shared_file) = store.create_file(ROOT, b"shared", 0o600, 0, 0).unwrap();
        shared_file.write_all(&[2u8; PAGE_SIZE as usize]).unwrap();
        let shared_st = appine_hal::fstat(shared_file.as_raw_fd()).unwrap();
        assert_eq!(shared_st.st_nlink, 1);
        let mapped = map_shared(&mut mm, shared_file.as_raw_fd(), 0).unwrap();
        assert!(content::contains(shared_st.st_dev, shared_st.st_ino));
        assert!(!trusted(shared_st));

        // 4. Unlinking the file and letting the reaper delete its host object clears
        //    WRITABLY_SHARED while keeping the still-open unlinked fd untrusted (st_nlink == 0).
        store.unlink(ROOT, b"shared").unwrap();
        drop(store); // commits and joins the reaper thread
        assert!(!content::contains(shared_st.st_dev, shared_st.st_ino));

        let unlinked_st = appine_hal::fstat(shared_file.as_raw_fd()).unwrap();
        assert_eq!(unlinked_st.st_nlink, 0);
        assert!(!trusted(unlinked_st));

        // 5. A new linked file reusing the same (dev, ino) is no longer poisoned.
        mm.munmap(mapped, PAGE_SIZE).unwrap();
        drop(shared_file);
        assert!(trusted(shared_st));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pgtables_and_swappable_nonresident_exclude_dontneed_and_unmapped() {
        let mut mm = Mm::new();
        let initial_pgtables = mm.pgtables_bytes();
        assert!(initial_pgtables >= PAGE_SIZE);

        let rw = prot::READ | prot::WRITE;
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let a = mm.mmap(0, 64 * PAGE_SIZE, rw, anon, None).unwrap();
        // Eager mapping created page tables and mapped 64 private anonymous pages; untouched pages
        // are non-resident.
        assert!(mm.pgtables_bytes() > initial_pgtables);
        assert_eq!(mm.swappable_nonresident_pages(), 0);

        // Dirtying half the range makes those 32 pages resident, leaving 32 non-resident.
        mm.write_kernel(a, &vec![0xab; 32 * PAGE_SIZE as usize])
            .unwrap();
        assert_eq!(mm.swappable_nonresident_pages(), 32);

        // MADV_DONTNEED discards the pages and zaps their soft-MMU entries so they are not
        // miscounted as swapped candidates.
        let (_, res) = mm.discard_range(a, 64 * PAGE_SIZE, false);
        res.unwrap();
        assert_eq!(mm.swappable_nonresident_pages(), 0);
        assert_eq!(mm.resident_pages(), 0);

        // Never-written anonymous VMA (PROT_READ only) contributes 0 swap candidates.
        let ro = mm.mmap(0, 16 * PAGE_SIZE, prot::READ, anon, None).unwrap();
        assert_eq!(mm.swappable_nonresident_pages(), 0);
        mm.munmap(ro, 16 * PAGE_SIZE).unwrap();
        mm.munmap(a, 64 * PAGE_SIZE).unwrap();
        assert_eq!(mm.swappable_nonresident_pages(), 0);
    }

    #[test]
    fn swap_candidates_include_disjoint_runs_of_borrowed_pages() {
        let parent = Mm::new().into_shared();
        let anon = flags::MAP_PRIVATE | flags::MAP_ANONYMOUS;
        let addr = parent
            .borrow_mut()
            .mmap(0, 5 * PAGE_SIZE, RW, anon, None)
            .unwrap();
        // Stop at the first write fault, before the retried guest store touches host memory.
        assert!(parent.borrow().fault_in(addr, prot::WRITE));
        let child = parent.borrow_mut().fork().unwrap();
        let mut child = child.borrow_mut();
        assert_eq!(child.swappable_nonresident_pages(), 5);
        child.munmap(addr + PAGE_SIZE, 2 * PAGE_SIZE).unwrap();
        assert_eq!(child.cow.borrow().borrowed.len(), 3);
        assert_eq!(child.swappable_nonresident_pages(), 3);
    }
}
