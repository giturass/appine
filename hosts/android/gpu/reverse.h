#pragma once
#include <stdint.h>

// The probe selects both indices on the same physical device. Only the exporter
// maps the memory.
struct gpu_route {
    uint8_t uuid[16];
    uint32_t cpu_type;
    uint32_t gpu_type;
};

struct cpu_blob_request {
    uint64_t id;
    uint64_t size; // Zero releases an allocation that the guest has not mapped.
};
