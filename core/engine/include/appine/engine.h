/*
 * The Appine engine's public interface (design doc §13.1, the engine and kernel/mmu maps).
 *
 * The engine only executes guest instructions and the soft-MMU fast path. On svc, a memory access
 * failure, an undefined instruction or brk, appine_cpu_run() returns an exit reason; the kernel
 * layer (Rust) handles it and calls appine_cpu_run() again to continue.
 *
 * Threading model: a struct appine_cpu can be run by only one thread; apart from
 * appine_cpu_kick(), no function is thread-safe. Several cpus can share one mmu and run at the
 * same time: the page table may be modified while it is being walked, but the caller must
 * serialize the modifications themselves. After unmapping or lowering permissions, the caller
 * must make every cpu using that mmu call appine_cpu_tlb_flush(), and must not free the unmapped
 * host memory before they all have.
 */
#ifndef APPINE_ENGINE_H
#define APPINE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#define APPINE_PAGE_SHIFT 12
#define APPINE_PAGE_SIZE (UINT64_C(1) << APPINE_PAGE_SHIFT)
#define APPINE_VA_BITS 48
#define APPINE_TLB_ENTRIES 4096 /* data TLB, direct-mapped */
#define APPINE_ITLB_ENTRIES 512 /* instruction-fetch TLB, used only by Tier 0 */

/* Page permissions, with the same values as Linux's PROT_* */
enum {
    APPINE_PROT_READ = 1u << 0,
    APPINE_PROT_WRITE = 1u << 1,
    APPINE_PROT_EXEC = 1u << 2,
};

/* Memory access type, for fault reporting */
enum appine_access {
    APPINE_ACCESS_READ = 1,
    APPINE_ACCESS_WRITE = 2,
    APPINE_ACCESS_EXEC = 3,
};

enum appine_fault_kind {
    APPINE_FAULT_PAGE = 1,     /* unmapped or wrong permissions; corresponds to SIGSEGV */
    /* the PC, or a data access that requires alignment, is misaligned; corresponds to SIGBUS */
    APPINE_FAULT_ALIGN = 2,
    /* SP misaligned when used as the base (fault_addr = SP); corresponds to SIGBUS */
    APPINE_FAULT_SP_ALIGN = 3,
    /* the access hit a hardware watchpoint (fault_addr = start of the access); corresponds to
     * SIGTRAP */
    APPINE_FAULT_WATCH = 4,
    /* the pc hit a hardware breakpoint (fault_addr = pc); corresponds to SIGTRAP */
    APPINE_FAULT_BREAK = 5,
};

/* Exit reasons of appine_cpu_run() */
enum appine_exit {
    /* used only by appine_cpu_exec_insn() and appine_cpu_step(): the instruction completed
     * normally */
    APPINE_EXIT_NONE = 0,
    APPINE_EXIT_SVC = 1,   /* pc already points at the next instruction, exit_info = imm16 */
    APPINE_EXIT_UNDEF = 2, /* pc points at the instruction, exit_info = instruction encoding */
    APPINE_EXIT_BRK = 3,   /* pc points at the instruction, exit_info = imm16 */
    /* pc points at the faulting instruction, the fault_* fields are valid, and the instruction
     * had no side effects */
    APPINE_EXIT_FAULT = 4,
    APPINE_EXIT_KICK = 5,  /* interrupted by appine_cpu_kick(); pending already cleared */
    /* ic ivau: pc already points at the next instruction, fault_addr = its address (tag
     * removed) */
    APPINE_EXIT_CODE = 6,
    /* A bug in the engine itself made the host receive SIGSEGV, SIGBUS or SIGILL (only after
     * appine_fault_guard_install()): guest state cannot be trusted and the caller should end this
     * guest process. Details from appine_host_fault_last(); the Tier 1 instance is already
     * poisoned, and appine_dbt_free() releases it directly */
    APPINE_EXIT_HOST_FAULT = 7,
};

/*
 * Data TLB entry: host address = guest address + addend. tag and addend are stored next to each
 * other, and Tier 1's generated code loads both with one ldp. tag holds the inverted guest page
 * number, and 0 means invalid: zeroed memory is an empty TLB that need not be written entry by
 * entry (so untouched pages take no memory either).
 */
struct appine_tlb_entry {
    uint64_t tag_read; /* ~guest page number; 0 means invalid */
    uint64_t addend_read;
    uint64_t tag_write;
    uint64_t addend_write;
};

/*
 * Hardware watchpoint (ptrace's NT_ARM_HW_WATCH): hits when any byte in [lo, hi) is accessed with
 * a kind in type (APPINE_WATCH_*); the instruction is not executed.
 */
#define APPINE_WATCH_LOAD 1u
#define APPINE_WATCH_STORE 2u
#define APPINE_HW_SLOTS 16
struct appine_watch {
    uint64_t lo, hi;
    uint32_t type;
    uint32_t reserved;
};

/* Instruction-fetch TLB entry, used only by Tier 0's instruction fetch (Tier 1's translation
 * reads guest code through the page table) */
struct appine_itlb_entry {
    uint64_t tag;
    uint64_t addend;
};

struct appine_mmu;

/*
 * Guest CPU state. The Rust side mirrors the layout field by field (core/engine/src/lib.rs);
 * changes must be made in both, and are checked by appine_cpu_layout_check().
 */
struct appine_cpu {
    /* Tier 1's generated code reads and writes the fields before tlb directly with ldr/str
     * immediate offsets */
    uint64_t x[31];
    uint64_t sp;
    uint64_t pc;
    uint64_t nzcv; /* only bits 31..28 are used */
    uint64_t fpcr;
    uint64_t fpsr;
    uint64_t tpidr_el0;
    /* x0 restored when a syscall restarts (the kernel/signal map), maintained by the kernel
     * layer */
    uint64_t orig_x0;
    uint64_t fault_addr;
    uint32_t fault_access; /* enum appine_access */
    uint32_t fault_kind;   /* enum appine_fault_kind */
    uint32_t exit_info;
    /* Tier 1: odd means a lock-free lookup of the translation table is in progress (dbt.c's
     * table_lookup) */
    uint32_t dbt_lookup_seq;
    /* accessed only atomically; 64 bits so that Tier 1 can read it with one ldr */
    uint64_t pending;
    struct appine_mmu *mmu;
    /* Exclusive monitor (LDXR/STXR): the recorded address, size and loaded value */
    uint64_t excl_addr;
    uint64_t excl_value[2];
    uint32_t excl_size; /* 0 means no exclusive mark */
    /* Tier 1: the tag of the thread's address space in the group sharing translations (dbt.c's
     * TAG_SHIFT) */
    uint32_t dbt_tag;
    /* The following fields are used internally by Tier 1 */
    uint64_t dbt_reason;
    uint64_t dbt_site;
    void *dbt_jump_cache;
    void *dbt_rs; /* top of the shadow return stack (a 1 KB-aligned ring in the Tier 1 instance) */
    /* The page recorded by Tier 1's ic ivau whose translations are not invalidated yet (0 means
     * none): appine_dbt_run() invalidates it in place at the next dsb or isb, and the caller
     * collects it at other exits; also aligns tlb to 16 bytes */
    uint64_t ivau_page;
    /* Host base addresses of several access groups, kept by Tier 1 while a block runs (dbt.c's
     * plan_group) */
    uint64_t dbt_groups[4];
    /* Tier 1 addresses entries as "ldp [cpu + index * 32 + offset]", so the offset of tlb must
     * not exceed the range of ldp's immediate */
    struct appine_tlb_entry tlb[APPINE_TLB_ENTRIES];
    struct appine_itlb_entry itlb[APPINE_ITLB_ENTRIES];
    uint64_t v[32][2]; /* V0–V31, low 64 bits first */
    /* tlb entries that were filled; flushing only handles these */
    uint64_t tlb_used[APPINE_TLB_ENTRIES / 64];
    /* Hardware breakpoints and watchpoints (ptrace's NT_ARM_HW_BREAK, NT_ARM_HW_WATCH): the first
     * nbrk, nwatch entries of brk and watch are valid. Only Tier 0 checks them: a thread with
     * breakpoints runs only in Tier 0; with watchpoints, watched pages stay out of tlb
     * (appine_tlb_fill), and Tier 1 falls back to Tier 0 when accessing them. tlb must be flushed
     * after the watchpoints change */
    uint32_t nbrk, nwatch;
    /* PSTATE.DIT (0 or 1): read and written by MSR and MRS DIT; bit 24 of pstate in signal frames
     * and ptrace. When entering guest code the host thread's DIT follows it (appine_sync_dit) */
    uint32_t dit;
    uint32_t reserved;
    uint64_t brk[APPINE_HW_SLOTS];
    struct appine_watch watch[APPINE_HW_SLOTS];
};

/* ---- Guest-visible CPU features (the engine map), with the same values as Linux's HWCAP_* ---- */

#define APPINE_HWCAP_FP (UINT64_C(1) << 0)
#define APPINE_HWCAP_ASIMD (UINT64_C(1) << 1)
#define APPINE_HWCAP_AES (UINT64_C(1) << 3)
#define APPINE_HWCAP_PMULL (UINT64_C(1) << 4)
#define APPINE_HWCAP_SHA1 (UINT64_C(1) << 5)
#define APPINE_HWCAP_SHA2 (UINT64_C(1) << 6)
#define APPINE_HWCAP_CRC32 (UINT64_C(1) << 7)
#define APPINE_HWCAP_ATOMICS (UINT64_C(1) << 8)
#define APPINE_HWCAP_FPHP (UINT64_C(1) << 9)
#define APPINE_HWCAP_ASIMDHP (UINT64_C(1) << 10)
#define APPINE_HWCAP_CPUID (UINT64_C(1) << 11)
#define APPINE_HWCAP_ASIMDRDM (UINT64_C(1) << 12)
#define APPINE_HWCAP_JSCVT (UINT64_C(1) << 13)
#define APPINE_HWCAP_FCMA (UINT64_C(1) << 14)
#define APPINE_HWCAP_LRCPC (UINT64_C(1) << 15)
#define APPINE_HWCAP_DCPOP (UINT64_C(1) << 16)
#define APPINE_HWCAP_SHA3 (UINT64_C(1) << 17)
#define APPINE_HWCAP_ASIMDDP (UINT64_C(1) << 20)
#define APPINE_HWCAP_SHA512 (UINT64_C(1) << 21)
#define APPINE_HWCAP_ASIMDFHM (UINT64_C(1) << 23)
#define APPINE_HWCAP_DIT (UINT64_C(1) << 24)
#define APPINE_HWCAP_ILRCPC (UINT64_C(1) << 26)
#define APPINE_HWCAP_FLAGM (UINT64_C(1) << 27)
#define APPINE_HWCAP_SB (UINT64_C(1) << 29)

/* AT_HWCAP2 bits, with the same values as Linux's HWCAP2_* */
#define APPINE_HWCAP2_DCPODP (UINT64_C(1) << 0)
#define APPINE_HWCAP2_FLAGM2 (UINT64_C(1) << 7)
#define APPINE_HWCAP2_FRINT (UINT64_C(1) << 8)
#define APPINE_HWCAP2_I8MM (UINT64_C(1) << 13)
#define APPINE_HWCAP2_BF16 (UINT64_C(1) << 14)
#define APPINE_HWCAP2_ECV (UINT64_C(1) << 19)

/* The AT_HWCAP advertised to the guest: host support ∩ implemented by Tier 0 ∩ the whitelist */
uint64_t appine_guest_hwcap(void);

/* The AT_HWCAP2 advertised to the guest, by the same rule */
uint64_t appine_guest_hwcap2(void);

/* The MIDR_EL1 the guest reads (0 when the host does not allow reading ID registers) */
uint64_t appine_guest_midr(void);

/* ---- soft-MMU page table (the kernel/mmu map) ---- */

enum {
    APPINE_OK = 0,
    /* argument not 4K-aligned, beyond the 48-bit address space, or invalid permission bits */
    APPINE_EINVAL = -1,
    APPINE_ENOMEM = -2, /* page table allocation failed; pages already done keep the new mapping */
};

struct appine_mmu *appine_mmu_new(void);
void appine_mmu_free(struct appine_mmu *mmu);

/*
 * Maps guest [gva, gva + len) to host [host, host + len), replacing existing mappings. gva, host
 * and len must all be 4K-aligned. The caller owns the host memory, which must stay valid while the
 * mapping exists.
 */
int appine_mmu_map(struct appine_mmu *mmu, uint64_t gva, void *host, uint64_t len, uint32_t prot);
/* Same as appine_mmu_map, but pages with existing entries (including ones with permission 0) stay
 * unchanged: on-demand filling */
int appine_mmu_fill(struct appine_mmu *mmu, uint64_t gva, void *host, uint64_t len, uint32_t prot);
int appine_mmu_unmap(struct appine_mmu *mmu, uint64_t gva, uint64_t len);
/* Changes only the permissions of existing entries (possibly to 0: the host page is kept but
 * cannot be accessed); pages without entries stay unchanged */
int appine_mmu_protect(struct appine_mmu *mmu, uint64_t gva, uint64_t len, uint32_t prot);
/* Moves the existing entries in [from, from + len) unchanged to the same positions starting at to,
 * clearing the originals; the two ranges must not overlap */
int appine_mmu_move(struct appine_mmu *mmu, uint64_t from, uint64_t to, uint64_t len);
/* The first page in [gva, end) with an entry (including ones with permission 0); end if none */
uint64_t appine_mmu_next_present(const struct appine_mmu *mmu, uint64_t gva, uint64_t end);

/*
 * Looks up the host pointer for a guest address (including the offset in the page). Every
 * permission in required_prot must be present, otherwise NULL is returned; 0 means only an
 * accessible entry is required (ones with permission 0 do not count).
 */
void *appine_mmu_translate(const struct appine_mmu *mmu, uint64_t gva, uint32_t required_prot);

/* ---- CPU ---- */

/*
 * Allocates and initializes a cpu (NULL on failure); release it with appine_cpu_free(). The TLB in
 * the struct is over a hundred KB, so it is allocated with mmap and unused pages take no memory.
 */
struct appine_cpu *appine_cpu_new(struct appine_mmu *mmu);
void appine_cpu_free(struct appine_cpu *cpu);

/* Clears all state and binds mmu (may be NULL, in which case every memory access fails) */
void appine_cpu_init(struct appine_cpu *cpu, struct appine_mmu *mmu);
void appine_cpu_tlb_flush(struct appine_cpu *cpu);

/* Executes from cpu->pc until the kernel layer is needed */
enum appine_exit appine_cpu_run(struct appine_cpu *cpu);

/* Executes the given instruction at cpu->pc (without fetching), for the lockstep tests */
enum appine_exit appine_cpu_exec_insn(struct appine_cpu *cpu, uint32_t insn);

/* Executes the instruction at cpu->pc under the interpreter (ptrace single-step), ignoring
 * pending */
enum appine_exit appine_cpu_step(struct appine_cpu *cpu);

/* May be called from any thread: makes appine_cpu_run() return APPINE_EXIT_KICK at the next
 * instruction boundary */
void appine_cpu_kick(struct appine_cpu *cpu);

/* ---- Host-side fault guard (the engine map, design doc §12 item 5) ---- */

/* A fault signal received by the host (APPINE_EXIT_HOST_FAULT) */
struct appine_host_fault {
    int32_t signo;
    int32_t code;  /* si_code */
    uint64_t addr; /* si_addr: a host address */
    uint64_t pc;   /* the faulting host instruction */
};

/*
 * Installs the host's SIGSEGV, SIGBUS and SIGILL handlers; may be called repeatedly. Afterwards
 * these faults during appine_cpu_run() or appine_dbt_run() become APPINE_EXIT_HOST_FAULT; other
 * faults first write a one-line report to stderr and are then passed to the original handling (on
 * Android, debuggerd produces a tombstone from it).
 */
void appine_fault_guard_install(void);

/* Details of the current thread's latest APPINE_EXIT_HOST_FAULT */
void appine_host_fault_last(struct appine_host_fault *out);

/* Checks the struct layout mirrored on the Rust side; returns 1 when it matches */
int appine_cpu_layout_check(size_t size, size_t off_x, size_t off_pc, size_t off_tpidr,
                            size_t off_pending, size_t off_mmu, size_t off_jump_cache,
                            size_t off_tlb, size_t off_v);

/* ---- Tier 1: a same-ISA pass-through DBT (the engine/dbt map) ---- */

struct appine_dbt;

/* Translation and run statistics */
struct appine_dbt_stats {
    uint64_t blocks;         /* blocks translated */
    uint64_t insns;          /* guest instructions translated */
    uint64_t insns_copied;   /* copied verbatim */
    uint64_t insns_remapped; /* involve a stolen register or SP, rewritten before execution */
    uint64_t insns_memory;   /* memory access instructions rewritten into the TLB fast path */
    uint64_t insns_fallback; /* instructions handed to Tier 0 (static count) */
    uint64_t exits_chain;    /* exits to the dispatcher at run time, by reason */
    uint64_t exits_lookup;
    uint64_t exits_interp;
    uint64_t exits_svc;
    uint64_t exits_kick;
    uint64_t flushes;
    uint64_t invalidated;   /* blocks invalidated by appine_dbt_invalidate() */
    uint64_t blocks_shared; /* blocks among blocks obtained by copying a translation template */
    uint64_t insns_grouped; /* of insns_memory, those sharing one TLB check with an earlier one */
    uint64_t ungrouped;     /* times a shared check failed and it was retranslated ungrouped */
};

/*
 * The Tier 1 translations of one address space (code cache, translation table): shared by all
 * threads in that address space; each thread attaches with appine_dbt_attach() to get its own part
 * (jump cache, shadow return stack, statistics) and runs with it. Returns NULL when the host is not
 * aarch64 Linux. appine_dbt_free() is called after every thread has detached; the instance goes
 * back to the pool, and when there are not many translations they are kept and checked block by
 * block before the next user runs. `key` distinguishes programs (0 means no distinction):
 * appine_dbt_new() first takes back translations left under the same key. `regs` selects which
 * host registers the translated code takes for itself (enum appine_dbt_regs); it only affects
 * speed.
 *
 * appine_dbt_run() handles ic ivau in place: it invalidates the page recorded in ivau_page at the
 * next dsb or isb, and the page of an ic ivau it hands to Tier 0 as soon as Tier 0 runs it.
 * Otherwise translations never invalidate themselves: after APPINE_EXIT_CODE, after an exit that
 * leaves ivau_page set, or after an executable mapping is torn down or changes permissions, the
 * caller must call appine_dbt_invalidate() or appine_dbt_flush() (once per address space, through
 * any one attached thread).
 */
enum appine_dbt_regs {
    APPINE_DBT_REGS_DEFAULT, /* x16, x17, x26–x28: rarely used in compiler-generated code */
    /* x21–x25: Go programs use x16 and x26–x28 heavily and these hardly at all */
    APPINE_DBT_REGS_GO,
};
struct appine_dbt *appine_dbt_new(uint64_t key, enum appine_dbt_regs regs);
void appine_dbt_free(struct appine_dbt *dbt, uint64_t key);
/* Releases the translations kept in the pool (when host memory is tight) */
void appine_dbt_trim(void);
/*
 * Unmaps the pages of every instance's code cache written through the writable view (the one used
 * for writing in the W^X double mapping), keeping the content: the host counts RSS per mapping,
 * and pages touched through both views count twice. The caller calls it periodically (the kernel
 * layer's timer thread, once a second); any thread may call it
 */
void appine_dbt_unmap_written(void);
/* How many bytes in total were written through the writable view and not yet unmapped (they count
 * twice in the host's RSS) */
uint64_t appine_dbt_written_bytes(void);

/*
 * A mapping that translations come from: a guest address range, and an identity given by the
 * caller (the file and its version) from which identical content can be concluded. Two mappings
 * with the same identity always have the same content; the caller guarantees it.
 */
struct appine_dbt_source {
    uint64_t start, len;
    uint64_t id[5];
};

/* Before the address space goes out of use (the translations go back to the pool): records the
 * mappings the translations come from, at most APPINE_DBT_SOURCES ranges */
#define APPINE_DBT_SOURCES 64
void appine_dbt_set_sources(struct appine_dbt *dbt, const struct appine_dbt_source *s, size_t n);

/*
 * Known libc memory primitives accelerated by Tier 1: same-page calls use in-cache helpers with
 * inline TLB checks (n >= 32 B for memset/memcpy/memmove, n >= 8 B for memcmp, first page for
 * memchr), while cross-page or cold-TLB large calls (n >= 128 B in guest X2) fall back to a
 * page-validated host libc call. Tiny operations stay inline in translated guest code, and any
 * watchpoint or missing page permission falls back to guest execution with precise faults.
 */
enum appine_memop_kind {
    APPINE_MEMOP_NONE = 0,
    APPINE_MEMOP_MEMCPY = 1,
    APPINE_MEMOP_MEMSET = 2,
    APPINE_MEMOP_MEMMOVE = 3,
    APPINE_MEMOP_MEMCMP = 4,
    APPINE_MEMOP_MEMCHR = 5,
    APPINE_MEMOP_STRNCMP = 6,
};

#define APPINE_DBT_MEMOPS 32
struct appine_dbt_memop {
    uint64_t pc;
    uint32_t kind;
    uint32_t reserved;
};
/* Replaces the registered memop entry PCs on this instance (at most APPINE_DBT_MEMOPS) and retires
 * any existing translation at a PC whose registration changed. Other threads may be running. */
void appine_dbt_set_memops(struct appine_dbt *dbt, const struct appine_dbt_memop *ops, size_t n);
/*
 * Before an instance taken from the pool first runs in a new address space: blocks in mappings of
 * the new address space that are exactly the same as the recorded ones need not be checked block
 * by block (on execve, the code segments of the program and the dynamic linker; checking them
 * would read every page)
 */
void appine_dbt_trust(struct appine_dbt *dbt, const struct appine_dbt_source *s, size_t n);
/*
 * Retires blocks whose guest pc is not in these mappings (parked ones included): before the
 * instance is shared by several address spaces, drops the translations valid only for the
 * original address space (for example, ones left by the previous user from the pool). Other
 * threads may be running
 */
void appine_dbt_retire_outside(struct appine_dbt *dbt, const struct appine_dbt_source *s, size_t n);
/*
 * When several address spaces share one instance: the trusted file mappings they all map
 * identically (the same version of the same file at the same addresses), all of them given every
 * time, only growing. Blocks in these mappings are shared by all members, and blocks elsewhere
 * (JIT-generated code) are only for the member that translated them, told apart by the tag given
 * when attaching (appine_dbt_attach)
 */
void appine_dbt_share(struct appine_dbt *dbt, const struct appine_dbt_source *s, size_t n);
/* Allocates a tag for one address space sharing this instance (1–65535, not repeated until the
 * instance goes back to the pool); returns 0 when they run out */
unsigned appine_dbt_new_tag(struct appine_dbt *dbt);

struct appine_dbt_thread;
/* `tag` is the tag of the thread's address space (appine_dbt_new_tag), 0 when not shared */
struct appine_dbt_thread *appine_dbt_attach(struct appine_dbt *dbt, unsigned tag);
void appine_dbt_detach(struct appine_dbt_thread *t);

/* Discards all translations: this has to wait until every thread has left translated code, so it
 * is only a request, completed by the next thread to enter appine_dbt_run() */
void appine_dbt_flush(struct appine_dbt_thread *t);

/* About to run in a different address space (after exec): keeps the translations and, before the
 * next run, checks the guest instruction words block by block, invalidating the ones that do not
 * match. Instances taken from the pool are handled the same way. */
void appine_dbt_recheck(struct appine_dbt_thread *t);

/* Invalidates the blocks starting in the pages covered by [start, start + len); when `cpu` is
 * given, only those whose guest instruction words differ from the current ones in its address
 * space. When there is no room it is the same as appine_dbt_flush() */
void appine_dbt_invalidate(struct appine_dbt_thread *t, const struct appine_cpu *cpu, uint64_t start,
                           uint64_t len);

/* Same semantics as appine_cpu_run(), but executes in translated code */
enum appine_exit appine_dbt_run(struct appine_dbt_thread *t, struct appine_cpu *cpu);
/* This thread's statistics: how many times it exited, and the translations and invalidations it
 * did */
void appine_dbt_get_stats(const struct appine_dbt_thread *t, struct appine_dbt_stats *out);

#endif /* APPINE_ENGINE_H */
