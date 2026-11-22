#define VK_USE_PLATFORM_ANDROID_KHR
#include <android/hardware_buffer.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vulkan/vulkan.h>
#include "android_blob.h"
#include <errno.h>
#include <stdbool.h>

// A socket carrying an AHardwareBuffer preserves gralloc's metadata and every
// fd in its native handle. The receiver imports it on the same physical device.
int appine_send_blob(int fd, VkDevice device, VkDeviceMemory memory) {
    PFN_vkGetMemoryAndroidHardwareBufferANDROID get =
        (PFN_vkGetMemoryAndroidHardwareBufferANDROID)vkGetDeviceProcAddr(
            device, "vkGetMemoryAndroidHardwareBufferANDROID");
    VkMemoryGetAndroidHardwareBufferInfoANDROID info = {
        .sType = VK_STRUCTURE_TYPE_MEMORY_GET_ANDROID_HARDWARE_BUFFER_INFO_ANDROID, .memory = memory};
    AHardwareBuffer *buffer;
    if (!get || get(device, &info, &buffer) != VK_SUCCESS)
        return -1;
    int result = AHardwareBuffer_sendHandleToUnixSocket(buffer, fd);
    AHardwareBuffer_release(buffer);
    return result;
}

int appine_export_android_blob(VkDevice device, VkDeviceMemory memory) {
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair))
        return -1;
    int result = appine_send_blob(pair[0], device, memory);
    close(pair[0]);
    if (!result)
        return pair[1];
    close(pair[1]);
    return -1;
}

static bool send_request(struct appine_allocator *allocator, uint64_t id, uint64_t size) {
    struct cpu_blob_request req = {.id = id, .size = size};
    return TEMP_FAILURE_RETRY(send(allocator->fd, &req, sizeof(req), MSG_NOSIGNAL)) == sizeof(req);
}

AHardwareBuffer *appine_request_blob(struct appine_allocator *allocator, uint64_t id, uint64_t size) {
    pthread_mutex_lock(&allocator->lock);
    AHardwareBuffer *buffer = NULL;
    uint8_t ready;
    if (!send_request(allocator, id, size) || TEMP_FAILURE_RETRY(recv(allocator->fd, &ready, 1, 0)) != 1 ||
        (ready && AHardwareBuffer_recvHandleFromUnixSocket(allocator->fd, &buffer))) {
        shutdown(allocator->fd, SHUT_RDWR);
    }
    pthread_mutex_unlock(&allocator->lock);
    return buffer;
}

void appine_release_blob(struct appine_allocator *allocator, uint64_t id) {
    pthread_mutex_lock(&allocator->lock);
    if (!send_request(allocator, id, 0))
        shutdown(allocator->fd, SHUT_RDWR);
    pthread_mutex_unlock(&allocator->lock);
}

VkResult appine_import_blob(VkDevice device, AHardwareBuffer *buffer, uint32_t index,
                            const VkMemoryAllocateInfo *info, VkDeviceMemory *memory) {
    PFN_vkGetAndroidHardwareBufferPropertiesANDROID get =
        (PFN_vkGetAndroidHardwareBufferPropertiesANDROID)vkGetDeviceProcAddr(
            device, "vkGetAndroidHardwareBufferPropertiesANDROID");
    VkAndroidHardwareBufferPropertiesANDROID props = {
        .sType = VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_PROPERTIES_ANDROID};
    VkResult result = VK_ERROR_INVALID_EXTERNAL_HANDLE;
    if (index < 32 && get && get(device, buffer, &props) == VK_SUCCESS &&
        props.allocationSize >= info->allocationSize && (props.memoryTypeBits & (1u << index))) {
        VkImportAndroidHardwareBufferInfoANDROID import = {
            .sType = VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID,
            .pNext = info->pNext,
            .buffer = buffer};
        VkMemoryAllocateInfo alloc = *info;
        alloc.pNext = &import;
        alloc.allocationSize = props.allocationSize;
        alloc.memoryTypeIndex = index;
        result = vkAllocateMemory(device, &alloc, NULL, memory);
    }
    AHardwareBuffer_release(buffer);
    return result;
}
