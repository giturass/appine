#ifndef APPINE_ANDROID_BLOB_H
#define APPINE_ANDROID_BLOB_H

#include "reverse.h"
#include <pthread.h>

// Ring threads share one allocation connection per Venus context.
struct appine_allocator {
    int fd;
    pthread_mutex_t lock;
    struct gpu_route route;
};

struct AHardwareBuffer;
struct AHardwareBuffer *appine_request_blob(struct appine_allocator *allocator, uint64_t id, uint64_t size);
void appine_release_blob(struct appine_allocator *allocator, uint64_t id);
// Consumes the caller's AHardwareBuffer reference on both success and failure.
VkResult appine_import_blob(VkDevice device, struct AHardwareBuffer *buffer, uint32_t index,
                            const VkMemoryAllocateInfo *info, VkDeviceMemory *memory);
int appine_send_blob(int fd, VkDevice device, VkDeviceMemory memory);

// The caller includes either the Venus protocol headers or the Android Vulkan
// headers.
int appine_export_android_blob(VkDevice device, VkDeviceMemory memory);
#endif
