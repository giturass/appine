//! In-process pipes (the kernel/pipe map): pipe2's anonymous pipes and the store's named pipes
//! (FIFOs; all opens of one inode share one pipe object).
//!
//! The buffer size defaults to 64 KiB as on Linux and can be changed with `F_SETPIPE_SZ`; writes
//! of at most `PIPE_BUF` are atomic.
//! The read and write ends each count their open files: after the last write end closes, the read
//! end reads EOF; after the last read end closes, writes fail and raise SIGPIPE. Blocking and
//! waking go through the common wait mechanism of [`crate::kernel`].

use std::collections::VecDeque;
use std::rc::{Rc, Weak};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::cell::RefCell;
use crate::kernel::{request_wake_object, wake};
use crate::mm::Mm;
use crate::uaccess::UserSlice;
use crate::vfs::store::Ino;
use appine_engine::prot;

/// The default capacity of a pipe.
pub const PIPE_CAPACITY: usize = 64 * 1024;
/// The default of `/proc/sys/fs/pipe-max-size`: the maximum pipe capacity without
/// `CAP_SYS_RESOURCE`.
pub const PIPE_MAX_SIZE: usize = 1024 * 1024;
/// Writes up to this length are never interleaved with other writes.
pub const PIPE_BUF: usize = 4096;

/// Device number anonymous pipes report (pipefs).
pub(crate) const PIPE_DEV: u64 = 0xd;

/// A vmsplice source page. The generation guards against host address reuse after a shootdown.
#[derive(Clone)]
struct VmSource {
    mm: Weak<RefCell<Mm>>,
    // Slot::start supplies the current offset, including after a partial read or transfer.
    page: u64,
    host_page: usize,
    generation: u64,
}

impl VmSource {
    fn read(&self, offset: usize, out: &mut [u8]) -> bool {
        let Some(mm) = self.mm.upgrade() else {
            return false;
        };
        let Ok(mm) = mm.try_borrow() else {
            return false;
        };
        let addr = self.page + offset as u64;
        // Check the current translation too: a mapping can be replaced before the next shootdown.
        // A missing PTE uses the snapshot without faulting or queuing a FUSE fill on the reader.
        mm.generations().tlb.load(Ordering::Relaxed) == self.generation
            && mm
                .mmu()
                .translate(addr, prot::READ)
                .is_some_and(|host| host.as_ptr() as usize == self.host_page + offset)
            && mm.read(UserSlice::new(addr, out.len()), out).is_ok()
    }
}

/// One occupied pipe buffer. Consuming its prefix does not make the page tail longer.
struct Slot {
    start: usize,
    end: usize,
    mergeable: bool,
    vm: Option<VmSource>,
}

impl Slot {
    fn read_live(&self, out: &mut [u8]) -> bool {
        self.vm.as_ref().is_some_and(|vm| vm.read(self.start, out))
    }
}

/// A pipe.
pub struct Pipe {
    /// Buffered data.
    buf: VecDeque<u8>,
    slots: VecDeque<Slot>,
    /// Slots claimed by a splice reading its input without the BKL.
    pub reserved: usize,
    /// Capacity in bytes, a multiple of the guest page size.
    pub capacity: usize,
    /// Number of open read ends.
    pub readers: usize,
    /// Number of open write ends.
    pub writers: usize,
    /// The inode number fstat reports.
    pub ino: u64,
    /// A named pipe's inode in the store; None for anonymous pipes.
    pub fifo: Option<Ino>,
    /// How many times the read and write ends have been opened: opening a FIFO waits for the other
    /// end, and these show that the other end has come (even if it has closed again).
    pub reader_opens: u64,
    pub writer_opens: u64,
    /// Number of writes of data: as on Linux, every write makes the read end's `EPOLLET` fire
    /// again.
    pub writes: u64,
    /// Write-side wakeups observed by edge-triggered pollers.
    pub room: u64,
    /// A splice is writing out data it takes from the pipe only once written: every other
    /// consumer waits until it is done, as Linux's hold the pipe's lock across the write, so the
    /// bytes it then removes are still the ones it wrote.
    pub splicing: bool,
}

impl Pipe {
    fn new(ino: u64, fifo: Option<Ino>, capacity: usize) -> Rc<RefCell<Pipe>> {
        Rc::new(RefCell::new(Pipe {
            buf: VecDeque::new(),
            capacity,
            readers: 0,
            writers: 0,
            ino,
            fifo,
            reader_opens: 0,
            writer_opens: 0,
            slots: VecDeque::new(),
            reserved: 0,
            writes: 0,
            room: 0,
            splicing: false,
        }))
    }

    /// The pipe object of named pipe `ino`, with no ends yet.
    pub fn fifo(ino: Ino, capacity: usize) -> Rc<RefCell<Pipe>> {
        Pipe::new(ino, Some(ino), capacity)
    }

    /// Buffered snapshots in slot order, used for byte counts and readiness.
    pub fn bytes(&self) -> &VecDeque<u8> {
        &self.buf
    }

    /// Readiness observes published slots. An input read in flight can still be short or fail.
    pub fn writable(&self) -> bool {
        self.slots.len() < self.capacity / PIPE_BUF
    }

    /// Occupied or reserved page buffers, including partially consumed ones.
    pub fn used_slots(&self) -> usize {
        self.slots.len() + self.reserved
    }

    pub fn free_slots(&self) -> usize {
        self.capacity / PIPE_BUF - self.used_slots()
    }

    /// Adds new slots split at source page boundaries. Spliced buffers cannot merge with writes.
    pub fn push_pages(&mut self, data: &[u8], offset: usize, mergeable: bool) {
        self.push_slots(data, offset, mergeable, |_| None);
    }

    /// Keeps a live source for each guest page alongside its vmsplice-time snapshot.
    pub fn push_vmsplice(&mut self, data: &[u8], offset: usize, mm: &Rc<RefCell<Mm>>, addr: u64) {
        let source = mm.borrow();
        let generation = source.generations().tlb.load(Ordering::Relaxed);
        self.push_slots(data, offset, false, |done| {
            let page = (addr + done as u64) & !(PIPE_BUF as u64 - 1);
            let host = source.mmu().translate(page, prot::READ)?;
            Some(VmSource {
                mm: Rc::downgrade(mm),
                page,
                host_page: host.as_ptr() as usize,
                generation,
            })
        });
    }

    fn push_slots(
        &mut self,
        data: &[u8],
        mut offset: usize,
        mergeable: bool,
        source: impl Fn(usize) -> Option<VmSource>,
    ) {
        let mut left = data.len();
        while left != 0 {
            let n = left.min(PIPE_BUF - offset);
            self.slots.push_back(Slot {
                start: offset,
                end: offset + n,
                mergeable,
                vm: source(data.len() - left),
            });
            left -= n;
            offset = 0;
        }
        self.buf.extend(data);
    }

    /// Copies the current contents without consuming any slots.
    pub fn copy_out(&self, out: &mut [u8]) -> usize {
        let total = out.len().min(self.buf.len());
        let (first, second) = self.buf.as_slices();
        let split = total.min(first.len());
        out[..split].copy_from_slice(&first[..split]);
        out[split..total].copy_from_slice(&second[..total - split]);
        let mut pos = 0;
        for slot in &self.slots {
            if pos == total {
                break;
            }
            let n = (slot.end - slot.start).min(total - pos);
            slot.read_live(&mut out[pos..pos + n]);
            pos += n;
        }
        pos
    }

    /// Owned copy for consumers that may release the BKL before committing a read.
    pub fn snapshot(&self, len: usize) -> Vec<u8> {
        let mut data = vec![0; len.min(self.buf.len())];
        self.copy_out(&mut data);
        data
    }

    /// Linux pipe_write merges the initial partial page only if it fits entirely in the tail.
    pub fn merge_len(&self, len: usize) -> usize {
        let tail = len % PIPE_BUF;
        if self
            .slots
            .back()
            .is_some_and(|s| s.mergeable && s.end + tail <= PIPE_BUF)
        {
            tail
        } else {
            0
        }
    }

    pub fn write(&mut self, data: &[u8], first: bool) -> usize {
        let tail = if first { self.merge_len(data.len()) } else { 0 };
        if tail != 0 {
            self.slots.back_mut().unwrap().end += tail;
            self.buf.extend(&data[..tail]);
        }
        let n = (data.len() - tail).min(self.free_slots() * PIPE_BUF);
        self.push_pages(&data[tail..tail + n], 0, true);
        tail + n
    }

    /// Copies up to one destination slot per source slot. Only a whole slot moved by splice
    /// carries its merge flag. The caller consumes the transferred bytes on a move.
    pub fn transfer(&self, dst: &mut Pipe, len: usize, take: bool) -> usize {
        let mut done = 0;
        let mut page = [0; PIPE_BUF];
        for slot in self.slots.iter().take(dst.free_slots()) {
            if done == len {
                break;
            }
            let n = (slot.end - slot.start).min(len - done);
            dst.slots.push_back(Slot {
                start: slot.start,
                end: slot.start + n,
                mergeable: take && slot.mergeable && slot.start + n == slot.end,
                vm: slot.vm.clone(),
            });
            if slot.read_live(&mut page[..n]) {
                dst.buf.extend(&page[..n]);
            } else {
                dst.buf.extend(self.buf.range(done..done + n));
            }
            done += n;
        }
        done
    }

    /// Ordinary reads wake writers of a full pipe. A pipe-to-pipe splice also wakes them
    /// whenever it moves a whole slot, even if the pipe was already writable.
    pub fn consume(&mut self, n: usize, splice_move: bool) {
        let full = self.free_slots() == 0;
        let slots = self.slots.len();
        let writable = self.writable();
        self.buf.drain(..n);
        let mut left = n;
        while left != 0 {
            let first = self.slots.front_mut().unwrap();
            let used = (first.end - first.start).min(left);
            first.start += used;
            left -= used;
            if first.start == first.end {
                self.slots.pop_front();
            }
        }
        if self.slots.len() == slots {
            return;
        }
        if !writable || splice_move {
            self.room += 1;
        }
        if full || splice_move {
            request_wake_object(wake::of_value(self));
        }
    }
}

/// One end of a pipe, held by an open file. A FIFO opened read-write is both a read end and a
/// write end.
pub struct PipeEnd {
    /// The pipe.
    pub pipe: Rc<RefCell<Pipe>>,
    /// Whether this is a read end.
    pub read: bool,
    /// Whether this is a write end.
    pub write: bool,
    /// When a FIFO is opened read-only with `O_NONBLOCK` and there is no write end yet: records
    /// how many times write ends had been opened, and POLLHUP is reported for no write end only
    /// after some write end has opened since (Linux's `f_version` of the read end, `pipe_poll`).
    pub hup_after: Option<u64>,
}

impl PipeEnd {
    /// Creates an anonymous pipe of capacity `capacity` and returns (read end, write end).
    pub fn pair(capacity: usize) -> (PipeEnd, PipeEnd) {
        static NEXT_INO: AtomicU64 = AtomicU64::new(1);
        let pipe = Pipe::new(NEXT_INO.fetch_add(1, Ordering::Relaxed), None, capacity);
        (
            PipeEnd::open(&pipe, true, false),
            PipeEnd::open(&pipe, false, true),
        )
    }

    /// Opens one end of a pipe (a FIFO's open, or a reopen through `/proc/<pid>/fd/<n>`).
    pub fn open(pipe: &Rc<RefCell<Pipe>>, read: bool, write: bool) -> PipeEnd {
        {
            let mut p = pipe.borrow_mut();
            if read {
                p.readers += 1;
                p.reader_opens += 1;
            }
            if write {
                p.writers += 1;
                p.writer_opens += 1;
            }
        }
        // Threads waiting for the other end while opening the FIFO can go on
        request_wake_object(object(pipe));
        PipeEnd {
            pipe: pipe.clone(),
            read,
            write,
            hup_after: None,
        }
    }
}

impl Drop for PipeEnd {
    fn drop(&mut self) {
        let mut p = self.pipe.borrow_mut();
        if self.read {
            p.readers -= 1;
        }
        if self.write {
            p.writers -= 1;
        }
        // Threads waiting at the other end must see EOF or EPIPE
        request_wake_object(object(&self.pipe));
    }
}

/// The object that threads waiting for this pipe register ([`crate::kernel::Cx::wait_object`]).
pub(crate) fn object(pipe: &Rc<RefCell<Pipe>>) -> crate::kernel::wake::Object {
    crate::kernel::wake::of(pipe)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vmsplice_snapshot_survives_a_borrowed_or_dropped_address_space() {
        let mm = Mm::new().into_shared();
        let base = 0x10000;
        let addr = base + PIPE_BUF as u64 - 1;
        mm.borrow_mut()
            .map_anonymous(base, 2 * PIPE_BUF as u64, prot::READ | prot::WRITE)
            .unwrap();
        let src = UserSlice::new(addr, 3);
        mm.borrow().write(src, b"old").unwrap();
        let pipe = Pipe::fifo(1, PIPE_CAPACITY);
        let mut pipe = pipe.borrow_mut();
        pipe.push_vmsplice(b"old", PIPE_BUF - 1, &mm, addr);
        mm.borrow().write(src, b"new").unwrap();
        {
            let _writer = mm.borrow_mut();
            assert_eq!(pipe.snapshot(3), b"old");
        }
        assert_eq!(pipe.snapshot(3), b"new");
        drop(mm);
        assert_eq!(pipe.snapshot(3), b"old");
    }
}
