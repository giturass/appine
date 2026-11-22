#pragma once
#include <stddef.h>
#include <stdint.h>
#include "virgl_resource.h"
#include "reverse.h"

// Each connection serves one Venus context. Fixed-size requests precede chunked
// command data.
enum gpu_op { GPU_OPEN, GPU_CREATE, GPU_RELEASE, GPU_SUBMIT, GPU_REVERSE_ALLOCATOR };
struct gpu_request {
    enum gpu_op op;
    union {
        uint32_t probe; // GPU_OPEN
        uint32_t id;    // GPU_CREATE or GPU_RELEASE
    };
    uint64_t blob;
    uint64_t size;
    uint32_t ring;
    uint32_t fence;
    struct gpu_route route;
};
struct gpu_reply {
    int error;
    int type;
    struct virgl_resource_vulkan_info info;
    struct gpu_route route;
};
#define GPU_CHUNK 16384

static inline size_t gpu_chunk_size(size_t remaining) {
    return remaining < GPU_CHUNK ? remaining : GPU_CHUNK;
}
