# difftest-files: gtest
# gVisor's tests for cross-process transfers, memory mappings, page residency and the program break.
# kernel/ptrace: an oversized remote iovec count is rejected before the empty local transfer.
SKIP="ProcessVMInvalidTest.EmptyTransferPrecedesRemoteValidation"
sh /tmp/difftest-files/gtest/run.sh gvisor "$SKIP" process_vm_read_write_test mremap_test \
    msync_test madvise_test mincore_test munmap_test brk_test
