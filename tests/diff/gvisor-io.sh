# difftest-files: gtest
# gVisor's tests for file range copies and vectored I/O with explicit or shared file offsets.
SKIP=""
sh /tmp/difftest-files/gtest/run.sh gvisor "$SKIP" copy_file_range_test preadv2_test pwritev2_test
