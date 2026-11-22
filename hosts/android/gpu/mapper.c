#define VK_USE_PLATFORM_ANDROID_KHR
#include <android/hardware_buffer.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vulkan/vulkan.h>
#include "virgl_resource.h"
#include "android_blob.h"

// The machine process maps coherent memory. The worker submits the guest's GPU commands.
struct gpu_mapper {
    VkInstance instance;
    VkDevice device;
    uint8_t uuid[VK_UUID_SIZE];
    uint32_t coherent_types;
};

void appine_mapper_destroy(struct gpu_mapper *m) {
    if (m->device)
        vkDestroyDevice(m->device, NULL);
    if (m->instance)
        vkDestroyInstance(m->instance, NULL);
    free(m);
}

struct gpu_mapper *appine_mapper_create(const struct gpu_route *route) {
    struct gpu_mapper *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo instance = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO,
                                     .pApplicationInfo = &app};
    if (vkCreateInstance(&instance, NULL, &m->instance) != VK_SUCCESS)
        goto fail;
    uint32_t count = 0;
    if (vkEnumeratePhysicalDevices(m->instance, &count, NULL) != VK_SUCCESS || !count)
        goto fail;
    VkPhysicalDevice *gpus = calloc(count, sizeof(*gpus));
    if (!gpus)
        goto fail;
    if (vkEnumeratePhysicalDevices(m->instance, &count, gpus) == VK_SUCCESS) {
        for (uint32_t i = 0; i < count; i++) {
            VkPhysicalDeviceIDProperties id = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES};
            VkPhysicalDeviceProperties2 props = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2,
                                                 .pNext = &id};
            vkGetPhysicalDeviceProperties2(gpus[i], &props);
            if (props.properties.deviceType == VK_PHYSICAL_DEVICE_TYPE_CPU ||
                props.properties.apiVersion < VK_API_VERSION_1_1)
                continue;
            if (route && memcmp(id.deviceUUID, route->uuid, sizeof(id.deviceUUID)))
                continue;
            float priority = 1;
            // Queue family zero exists on every physical device. This device submits
            // no work.
            VkDeviceQueueCreateInfo queue = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                                             .queueCount = 1,
                                             .pQueuePriorities = &priority};
            const char *ext = VK_ANDROID_EXTERNAL_MEMORY_ANDROID_HARDWARE_BUFFER_EXTENSION_NAME;
            VkDeviceCreateInfo ci = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
                                     .queueCreateInfoCount = 1,
                                     .pQueueCreateInfos = &queue,
                                     .enabledExtensionCount = 1,
                                     .ppEnabledExtensionNames = &ext};
            if (vkCreateDevice(gpus[i], &ci, NULL, &m->device) != VK_SUCCESS)
                continue;
            memcpy(m->uuid, id.deviceUUID, sizeof(m->uuid));
            VkPhysicalDeviceMemoryProperties mem;
            vkGetPhysicalDeviceMemoryProperties(gpus[i], &mem);
            VkMemoryPropertyFlags needed =
                VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
            for (uint32_t j = 0; j < mem.memoryTypeCount; j++)
                if ((mem.memoryTypes[j].propertyFlags & needed) == needed)
                    m->coherent_types |= 1u << j;
            break;
        }
    }
    free(gpus);
    if (m->device && m->coherent_types &&
        (!route || (route->cpu_type < 32 && (m->coherent_types & (1u << route->cpu_type)))))
        return m;
fail:
    appine_mapper_destroy(m);
    return NULL;
}

static void *map_allocated_memory(VkDevice device, VkDeviceMemory *memory, uint64_t size) {
    void *base;
    if (vkMapMemory(device, *memory, 0, size, 0, &base) == VK_SUCCESS)
        return base;
    vkFreeMemory(device, *memory, NULL);
    *memory = VK_NULL_HANDLE;
    return NULL;
}

void *appine_gpu_map(struct gpu_mapper *m, int fd, uint64_t blob, uint64_t size, int type,
                     const uint8_t uuid[16], uint32_t index, uint64_t allocation, VkDeviceMemory *memory) {
    *memory = VK_NULL_HANDLE;
    if (!blob && type == VIRGL_RESOURCE_FD_SHM) {
        struct stat st;
        int seals = F_SEAL_SHRINK | F_SEAL_GROW;
        // A producer may already have sealed the file. Check the final seal set
        // before trusting st_size or installing pages in the guest MMU.
        (void)fcntl(fd, F_ADD_SEALS, seals);
        int current = fcntl(fd, F_GET_SEALS);
        if (current < 0 || (current & seals) != seals || fstat(fd, &st) || !S_ISREG(st.st_mode) ||
            st.st_size != (off_t)size)
            return NULL;
        void *base = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        return base == MAP_FAILED ? NULL : base;
    }
    if (!blob || type != VIRGL_RESOURCE_FD_OPAQUE || memcmp(uuid, m->uuid, 16) || index >= 32 ||
        !(m->coherent_types & (1u << index)) || allocation < size)
        return NULL;
    struct timeval timeout = {.tv_sec = 2};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)))
        return NULL;
    AHardwareBuffer *buffer;
    if (AHardwareBuffer_recvHandleFromUnixSocket(fd, &buffer))
        return NULL;
    AHardwareBuffer_Desc desc;
    AHardwareBuffer_describe(buffer, &desc);
    if (desc.format != AHARDWAREBUFFER_FORMAT_BLOB || desc.layers != 1 || desc.height != 1 ||
        desc.width < size) {
        AHardwareBuffer_release(buffer);
        return NULL;
    }
    VkMemoryAllocateInfo alloc = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO, .allocationSize = size};
    if (appine_import_blob(m->device, buffer, index, &alloc, memory) != VK_SUCCESS)
        return NULL;
    return map_allocated_memory(m->device, memory, size);
}

void appine_gpu_unmap(struct gpu_mapper *m, VkDeviceMemory memory, void *base, size_t size) {
    if (memory) {
        vkUnmapMemory(m->device, memory);
        vkFreeMemory(m->device, memory, NULL);
    } else {
        munmap(base, size);
    }
}

void *appine_gpu_allocate_export(struct gpu_mapper *m, const struct gpu_route *route, uint64_t size,
                                 VkDeviceMemory *memory) {
    const uint64_t page = (uint64_t)getpagesize();
    if (!size || size > UINT32_MAX || size % page || route->cpu_type >= 32 ||
        memcmp(m->uuid, route->uuid, sizeof(m->uuid)) || !(m->coherent_types & (1u << route->cpu_type)))
        return NULL;
    VkExportMemoryAllocateInfo export = {
        .sType = VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,
        .handleTypes = VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID};
    VkMemoryAllocateInfo alloc = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                                  .pNext = &export,
                                  .allocationSize = size,
                                  .memoryTypeIndex = route->cpu_type};
    if (vkAllocateMemory(m->device, &alloc, NULL, memory) != VK_SUCCESS)
        return NULL;
    return map_allocated_memory(m->device, memory, size);
}

int appine_gpu_send_export(struct gpu_mapper *m, VkDeviceMemory memory, int fd) {
    return appine_send_blob(fd, m->device, memory);
}
