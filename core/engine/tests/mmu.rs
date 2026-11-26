//! Unit tests for the soft-MMU page table (mmu.c): the operations on-demand filling uses.

use std::ptr::NonNull;

use appine_engine::{Mmu, PAGE_SIZE, prot};

#[repr(C, align(4096))]
struct Page([u8; 4096]);

const RW: u32 = prot::READ | prot::WRITE;
/// The range one leaf table covers.
const LEAF: u64 = PAGE_SIZE << 9;

#[test]
fn fill_only_adds_missing_entries() {
    let mut mem = pages(4);
    let mmu = Mmu::new();
    let a = 0x10_0000;
    // Page 1 is first mapped elsewhere, and page 2 keeps an entry with permission 0 (as left by
    // copy-on-write or PROT_NONE)
    unsafe {
        mmu.map_shared(a + PAGE_SIZE, host(&mut mem, 3), PAGE_SIZE, prot::READ)
            .unwrap();
        mmu.map_shared(a + 2 * PAGE_SIZE, host(&mut mem, 2), PAGE_SIZE, 0)
            .unwrap();
        mmu.fill_shared(a, host(&mut mem, 0), 3 * PAGE_SIZE, RW)
            .unwrap();
    }
    assert_eq!(mmu.translate(a, prot::WRITE), Some(host(&mut mem, 0)));
    assert_eq!(mmu.translate(a + PAGE_SIZE, 0), Some(host(&mut mem, 3)));
    assert!(mmu.translate(a + PAGE_SIZE, prot::WRITE).is_none());
    // An entry with permission 0 cannot be accessed and does not count as mapped even when 0 is
    // passed; restoring a permission makes it usable again
    assert!(mmu.translate(a + 2 * PAGE_SIZE, 0).is_none());
    assert_eq!(
        mmu.next_present(a + 2 * PAGE_SIZE, a + LEAF),
        a + 2 * PAGE_SIZE
    );
    mmu.protect_shared(a + 2 * PAGE_SIZE, PAGE_SIZE, RW)
        .unwrap();
    assert_eq!(
        mmu.translate(a + 2 * PAGE_SIZE, RW),
        Some(host(&mut mem, 2))
    );
}

#[test]
fn ranges_skip_missing_tables_at_every_level() {
    let mut mem = pages(2);
    let mut mmu = Mmu::new();
    let top = 1u64 << 48;
    let (lo, hi) = (0x7000_0000, top - 3 * LEAF);
    unsafe {
        mmu.map(lo, host(&mut mem, 0), PAGE_SIZE, RW).unwrap();
        mmu.map(hi, host(&mut mem, 1), PAGE_SIZE, prot::READ)
            .unwrap();
    }
    // Only two pages in the whole address space: lookup, unmap and protect all skip the places
    // without tables
    assert_eq!(mmu.next_present(0, top), lo);
    assert_eq!(mmu.next_present(lo + PAGE_SIZE, top), hi);
    assert_eq!(mmu.next_present(hi + PAGE_SIZE, top), top);
    mmu.protect(0, top, prot::READ).unwrap();
    assert!(mmu.translate(lo, prot::WRITE).is_none());
    assert!(mmu.translate(lo, prot::READ).is_some());
    mmu.unmap(PAGE_SIZE, top - PAGE_SIZE).unwrap();
    assert_eq!(mmu.next_present(0, top), top);
}

#[test]
fn move_carries_entries_and_their_permissions() {
    let mut mem = pages(3);
    let mut mmu = Mmu::new();
    let (from, to) = (LEAF - PAGE_SIZE, 0x40_0000_0000);
    unsafe {
        mmu.map(from, host(&mut mem, 0), PAGE_SIZE, RW).unwrap();
        // Crossing leaf tables; the middle page has no entry, and the third page has permission 0
        mmu.map(from + 2 * PAGE_SIZE, host(&mut mem, 1), PAGE_SIZE, 0)
            .unwrap();
    }
    mmu.move_entries(from, to, 3 * PAGE_SIZE).unwrap();
    assert_eq!(
        mmu.next_present(from, from + 3 * PAGE_SIZE),
        from + 3 * PAGE_SIZE
    );
    assert_eq!(mmu.translate(to, prot::WRITE), Some(host(&mut mem, 0)));
    assert_eq!(
        mmu.next_present(to + PAGE_SIZE, to + 3 * PAGE_SIZE),
        to + 2 * PAGE_SIZE
    );
    assert!(mmu.translate(to + 2 * PAGE_SIZE, 0).is_none());
    // Two overlapping ranges are not allowed
    assert!(mmu.move_entries(to, to + PAGE_SIZE, 2 * PAGE_SIZE).is_err());
}

#[test]
fn superpages_map_protect_unmap_demote_and_move() {
    // Allocate 2 MiB + 4 extra pages so we can test non-2 MiB-aligned host addresses and CoW
    // single-page replacements.
    let mut mem = pages(512 + 4);
    let mut mmu = Mmu::new();
    let base = 0x2000_0000u64; // 2 MiB-aligned
    assert_eq!(base % LEAF, 0);

    // 1. Full 2 MiB fill with 4 KiB-aligned (not 2 MiB-aligned) host pointer -> L2 superpage.
    let h0 = host(&mut mem, 1);
    unsafe {
        mmu.fill_shared(base, h0, LEAF, RW).unwrap();
    }
    assert_eq!(mmu.translate(base, RW), Some(h0));
    assert_eq!(
        mmu.translate(base + 123 * PAGE_SIZE + 0x456, RW),
        Some(NonNull::new(unsafe { h0.as_ptr().add(123 * 4096 + 0x456) }).unwrap())
    );
    assert_eq!(
        mmu.translate(base + 511 * PAGE_SIZE, RW),
        Some(NonNull::new(unsafe { h0.as_ptr().add(511 * 4096) }).unwrap())
    );
    assert_eq!(mmu.next_present(0, base + 2 * LEAF), base);
    assert_eq!(
        mmu.next_present(base + 77 * PAGE_SIZE, base + LEAF),
        base + 77 * PAGE_SIZE
    );
    assert_eq!(
        mmu.next_present(base + LEAF, base + 2 * LEAF),
        base + 2 * LEAF
    );

    // 2. fill_shared over an existing superpage (full or partial) leaves existing mapping intact.
    let alt = host(&mut mem, 513);
    unsafe {
        mmu.fill_shared(base, alt, PAGE_SIZE, prot::READ).unwrap();
        mmu.fill_shared(base, h0, LEAF, prot::READ).unwrap();
    }
    assert_eq!(mmu.translate(base, RW), Some(h0));

    // 3. Whole-2 MiB protect RW -> PROT_NONE -> READ -> RW stays consistent.
    mmu.protect(base, LEAF, 0).unwrap();
    assert!(mmu.translate(base, 0).is_none());
    assert!(mmu.translate(base + 200 * PAGE_SIZE, 0).is_none());
    assert_eq!(
        mmu.next_present(base + 200 * PAGE_SIZE, base + LEAF),
        base + 200 * PAGE_SIZE
    );
    mmu.protect(base, LEAF, prot::READ).unwrap();
    assert!(mmu.translate(base, prot::WRITE).is_none());
    assert_eq!(
        mmu.translate(base + 200 * PAGE_SIZE, prot::READ),
        Some(host(&mut mem, 201))
    );
    mmu.protect(base, LEAF, RW).unwrap();

    // 4. Whole-2 MiB aligned move preserves superpage and clears source.
    let dst = 0x2040_0000u64;
    mmu.move_entries(base, dst, LEAF).unwrap();
    assert_eq!(mmu.next_present(base, base + LEAF), base + LEAF);
    assert_eq!(
        mmu.translate(dst + 500 * PAGE_SIZE, RW),
        Some(host(&mut mem, 501))
    );

    // 5. Partial protect demotes superpage: only protected slice changes.
    mmu.protect(dst + 10 * PAGE_SIZE, 2 * PAGE_SIZE, prot::READ)
        .unwrap();
    assert!(mmu.translate(dst + 9 * PAGE_SIZE, prot::WRITE).is_some());
    assert!(mmu.translate(dst + 10 * PAGE_SIZE, prot::WRITE).is_none());
    assert!(mmu.translate(dst + 10 * PAGE_SIZE, prot::READ).is_some());
    assert!(mmu.translate(dst + 11 * PAGE_SIZE, prot::WRITE).is_none());
    assert!(mmu.translate(dst + 12 * PAGE_SIZE, prot::WRITE).is_some());

    // 6. Full-2 MiB unmap on a fresh superpage clears everything cleanly.
    unsafe {
        mmu.map(base, h0, LEAF, RW).unwrap();
    }
    mmu.unmap(base, LEAF).unwrap();
    assert_eq!(mmu.next_present(base, base + LEAF), base + LEAF);

    // 7. Partial unmap & single-page CoW map_shared demote superpage cleanly.
    unsafe {
        mmu.map(base, h0, LEAF, RW).unwrap();
    }
    mmu.unmap(base + 5 * PAGE_SIZE, 3 * PAGE_SIZE).unwrap();
    assert_eq!(
        mmu.translate(base + 4 * PAGE_SIZE, RW),
        Some(host(&mut mem, 5))
    );
    assert!(mmu.translate(base + 5 * PAGE_SIZE, 0).is_none());
    assert!(mmu.translate(base + 7 * PAGE_SIZE, 0).is_none());
    assert_eq!(
        mmu.next_present(base + 5 * PAGE_SIZE, base + LEAF),
        base + 8 * PAGE_SIZE
    );
    assert_eq!(
        mmu.translate(base + 8 * PAGE_SIZE, RW),
        Some(host(&mut mem, 9))
    );

    // CoW single-page replacement inside a fresh superpage.
    let base2 = 0x2080_0000u64;
    unsafe {
        mmu.map(base2, h0, LEAF, RW).unwrap();
        mmu.map_shared(base2 + 300 * PAGE_SIZE, alt, PAGE_SIZE, prot::READ)
            .unwrap();
    }
    assert_eq!(
        mmu.translate(base2 + 299 * PAGE_SIZE, RW),
        Some(host(&mut mem, 300))
    );
    assert_eq!(
        mmu.translate(base2 + 300 * PAGE_SIZE, prot::READ),
        Some(alt)
    );
    assert!(
        mmu.translate(base2 + 300 * PAGE_SIZE, prot::WRITE)
            .is_none()
    );
    assert_eq!(
        mmu.translate(base2 + 301 * PAGE_SIZE, RW),
        Some(host(&mut mem, 302))
    );

    // 8. Unaligned move from a fresh superpage demotes and carries all 512 pages.
    let base3 = 0x20c0_0000u64;
    let unaligned_dst = 0x2100_1000u64;
    unsafe {
        mmu.map(base3, h0, LEAF, RW).unwrap();
    }
    mmu.move_entries(base3, unaligned_dst, LEAF).unwrap();
    assert_eq!(mmu.next_present(base3, base3 + LEAF), base3 + LEAF);
    assert_eq!(mmu.translate(unaligned_dst, RW), Some(h0));
    assert_eq!(
        mmu.translate(unaligned_dst + 511 * PAGE_SIZE, RW),
        Some(host(&mut mem, 512))
    );

    // 9. A small mapping followed by unmap leaves an empty L3 table; a subsequent full-2 MiB fill
    //    at the same 2 MiB VA must still promote cleanly to a superpage (retiring the empty L3).
    let base4 = 0x2140_0000u64;
    unsafe {
        mmu.map(base4, alt, PAGE_SIZE, RW).unwrap();
    }
    mmu.unmap(base4, PAGE_SIZE).unwrap();
    unsafe {
        mmu.fill_shared(base4, h0, LEAF, RW).unwrap();
    }
    assert_eq!(mmu.translate(base4, RW), Some(h0));
    assert_eq!(
        mmu.translate(base4 + 511 * PAGE_SIZE, RW),
        Some(host(&mut mem, 512))
    );
    // Partial protect after promotion must demote cleanly again without touching the retired L3.
    mmu.protect(base4 + PAGE_SIZE, PAGE_SIZE, prot::READ)
        .unwrap();
    assert!(mmu.translate(base4, prot::WRITE).is_some());
    assert!(mmu.translate(base4 + PAGE_SIZE, prot::WRITE).is_none());
    assert!(mmu.translate(base4 + 2 * PAGE_SIZE, prot::WRITE).is_some());
}

#[test]
fn table_bytes_tracks_allocated_tables_and_superpages() {
    let mut mem = pages(512 + 2);
    let mut mmu = Mmu::new();
    // Fresh Mmu has only the L0 root table (512 * sizeof(uintptr_t) = 4 KiB on 64-bit).
    let table_size = 512 * std::mem::size_of::<usize>() as u64;
    assert_eq!(mmu.table_bytes(), table_size);
    assert_eq!(mmu.table_pages(), table_size / PAGE_SIZE);

    // Aligned 2 MiB superpage allocates L1 + L2, without an L3 leaf table.
    let super_va = 0x2000_0000u64;
    unsafe {
        mmu.fill_shared(super_va, host(&mut mem, 0), LEAF, RW)
            .unwrap();
    }
    assert_eq!(mmu.table_bytes(), 3 * table_size);

    // Partial protect demotes the superpage into a newly allocated L3 table.
    mmu.protect(super_va + PAGE_SIZE, PAGE_SIZE, prot::READ)
        .unwrap();
    assert_eq!(mmu.table_bytes(), 4 * table_size);

    // Mapping a single 4 KiB page in a fresh 2 MiB slot under the same L2 allocates one L3 table.
    let small_va = super_va + LEAF;
    unsafe {
        mmu.map(small_va, host(&mut mem, 512), PAGE_SIZE, RW)
            .unwrap();
    }
    assert_eq!(mmu.table_bytes(), 5 * table_size);

    // Unmapping and re-promoting retires the empty L3 (still allocated until Mmu::drop), so
    // table_bytes stays monotonic, and a later demotion allocates a fresh L3 table.
    mmu.unmap(small_va, PAGE_SIZE).unwrap();
    unsafe {
        mmu.fill_shared(small_va, host(&mut mem, 0), LEAF, RW)
            .unwrap();
    }
    assert_eq!(mmu.table_bytes(), 5 * table_size);
    mmu.unmap(small_va, PAGE_SIZE).unwrap();
    assert_eq!(mmu.table_bytes(), 6 * table_size);
}

fn pages(n: usize) -> Box<[Page]> {
    (0..n).map(|_| Page([0; 4096])).collect()
}

fn host(p: &mut [Page], i: usize) -> NonNull<u8> {
    NonNull::new(p[i..].as_mut_ptr().cast::<u8>()).unwrap()
}
