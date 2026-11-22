// Check the DRM file description, GEM handle and VMA lifetimes independently of Mesa.
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>
#include <virtgpu_drm.h>

#define CHECK(op)                                                                                            \
    do {                                                                                                     \
        if ((op) < 0) {                                                                                      \
            perror(#op);                                                                                     \
            return 1;                                                                                        \
        }                                                                                                    \
    } while (0)

int main(void) {
    int fd = open("/dev/dri/renderD128", O_RDWR | O_CLOEXEC);
    CHECK(fd);
    int dupfd = dup(fd);
    CHECK(dupfd);
    struct drm_virtgpu_context_set_param param = {.param = VIRTGPU_CONTEXT_PARAM_CAPSET_ID, .value = 4};
    struct drm_virtgpu_context_init init = {.num_params = 1, .ctx_set_params = (uintptr_t)&param};
    CHECK(ioctl(fd, DRM_IOCTL_VIRTGPU_CONTEXT_INIT, &init));
    struct drm_virtgpu_resource_create_blob blob = {
        .blob_mem = VIRTGPU_BLOB_MEM_HOST3D, .blob_flags = VIRTGPU_BLOB_FLAG_USE_MAPPABLE, .size = 65536};
    CHECK(ioctl(dupfd, DRM_IOCTL_VIRTGPU_RESOURCE_CREATE_BLOB, &blob));
    struct drm_virtgpu_map map = {.handle = blob.bo_handle};
    CHECK(ioctl(fd, DRM_IOCTL_VIRTGPU_MAP, &map));
    volatile uint32_t *words = mmap(NULL, blob.size, PROT_READ | PROT_WRITE, MAP_SHARED, dupfd, map.offset);
    if (words == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    struct drm_gem_close gem = {.handle = blob.bo_handle};
    CHECK(ioctl(fd, DRM_IOCTL_GEM_CLOSE, &gem));
    CHECK(close(fd));
    CHECK(close(dupfd));
    words[0] = 0xabc123;
    pid_t child = fork();
    CHECK(child);
    if (!child) {
        words[16383] = ~words[0];
        _exit(0);
    }
    int status;
    CHECK(waitpid(child, &status, 0));
    if (status || words[16383] != ~0xabc123u)
        return 1;
    CHECK(munmap((void *)words, blob.size));
    puts("Verified shared mapping after GEM_CLOSE, close and fork");
    return 0;
}
