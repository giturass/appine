// Used by both the private GPU service at machine startup and the standalone instrumentation probe.
#define VK_USE_PLATFORM_ANDROID_KHR
#include <android/hardware_buffer.h>
#include <errno.h>
#include <inttypes.h>
#include "probe.h"
#include <linux/dma-buf.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vulkan/vulkan.h>

#define CHECK(op)                                                                                            \
    do {                                                                                                     \
        VkResult r = (op);                                                                                   \
        if (r != VK_SUCCESS) {                                                                               \
            fprintf(out, "FAIL %s: VkResult %d\n", #op, r);                                                  \
            goto done;                                                                                       \
        }                                                                                                    \
    } while (0)
#define REQUIRE(test, message)                                                                               \
    do {                                                                                                     \
        if (!(test)) {                                                                                       \
            fprintf(out, "FAIL %s\n", message);                                                              \
            goto done;                                                                                       \
        }                                                                                                    \
    } while (0)

static bool cpu_access(FILE *out, int fd, uint64_t flags) {
    struct dma_buf_sync sync = {.flags = flags};
    int ret;
    do {
        ret = ioctl(fd, DMA_BUF_IOCTL_SYNC, &sync);
    } while (ret < 0 && (errno == EINTR || errno == EAGAIN));
    if (ret < 0)
        fprintf(out, "FAIL DMA_BUF_IOCTL_SYNC(%" PRIu64 "): %s\n", flags, strerror(errno));
    return ret == 0;
}

static bool has_extension(VkExtensionProperties *props, uint32_t count, const char *name) {
    for (uint32_t i = 0; i < count; i++)
        if (strcmp(props[i].extensionName, name) == 0)
            return true;
    return false;
}

static bool probe_device(FILE *out, VkPhysicalDevice gpu, enum path path, struct gpu_route *reverse) {
    const bool dedicated = path == DEDICATED_CONTROL;
    const bool blob = path == ANDROID_BLOB || path == CPU_EXPORT_BLOB;
    const bool gpu_mapping = path != DMA_BUF;
    bool passed = false;
    const VkExternalMemoryHandleTypeFlagBits type =
        blob          ? VK_EXTERNAL_MEMORY_HANDLE_TYPE_ANDROID_HARDWARE_BUFFER_BIT_ANDROID
        : gpu_mapping ? VK_EXTERNAL_MEMORY_HANDLE_TYPE_OPAQUE_FD_BIT
                      : VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT;
    const char *extensions[] = {
        VK_KHR_EXTERNAL_MEMORY_FD_EXTENSION_NAME, VK_EXT_EXTERNAL_MEMORY_DMA_BUF_EXTENSION_NAME,
        VK_EXT_IMAGE_DRM_FORMAT_MODIFIER_EXTENSION_NAME, VK_EXT_QUEUE_FAMILY_FOREIGN_EXTENSION_NAME};
    const unsigned required = gpu_mapping ? 1 : 4;
    if (blob)
        extensions[0] = VK_ANDROID_EXTERNAL_MEMORY_ANDROID_HARDWARE_BUFFER_EXTENSION_NAME;
    VkPhysicalDeviceProperties props;
    vkGetPhysicalDeviceProperties(gpu, &props);
    fprintf(out, "GPU=%s vendor=%#x device=%#x type=%d driver=%#x Vulkan=%u.%u.%u\n", props.deviceName,
            props.vendorID, props.deviceID, props.deviceType, props.driverVersion,
            VK_VERSION_MAJOR(props.apiVersion), VK_VERSION_MINOR(props.apiVersion),
            VK_VERSION_PATCH(props.apiVersion));

    VkExtensionProperties *available = NULL;
    VkQueueFamilyProperties *families = NULL;
    VkDevice device = VK_NULL_HANDLE, mapper = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE, imported = VK_NULL_HANDLE;
    AHardwareBuffer *ahb = NULL;
    VkBuffer second = VK_NULL_HANDLE, buffer = VK_NULL_HANDLE, import_buffer = VK_NULL_HANDLE;
    VkCommandPool pool = VK_NULL_HANDLE;
    VkFence fence = VK_NULL_HANDLE;
    void *mapping = NULL;
    int fd = -1;
    const size_t page = (size_t)getpagesize();
    VkDeviceSize allocation = 0;
    uint32_t n = 0;
    CHECK(vkEnumerateDeviceExtensionProperties(gpu, NULL, &n, NULL));
    available = calloc(n, sizeof(*available));
    REQUIRE(available || n == 0, "extension list allocation");
    CHECK(vkEnumerateDeviceExtensionProperties(gpu, NULL, &n, available));
    for (uint32_t i = 0; i < n; i++)
        fprintf(out, "%s\n", available[i].extensionName);
    REQUIRE(props.apiVersion >= VK_API_VERSION_1_1, "requires Vulkan 1.1");
    REQUIRE(props.deviceType != VK_PHYSICAL_DEVICE_TYPE_CPU, "software Vulkan device");
    for (unsigned i = 0; i < required; i++) {
        if (!has_extension(available, n, extensions[i])) {
            fprintf(out, "FAIL required extension %s\n", extensions[i]);
            goto done;
        }
    }

    const VkBufferUsageFlags usage = VK_BUFFER_USAGE_TRANSFER_SRC_BIT | VK_BUFFER_USAGE_TRANSFER_DST_BIT;
    VkPhysicalDeviceExternalBufferInfo query = {
        .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_EXTERNAL_BUFFER_INFO, .usage = usage, .handleType = type};
    VkExternalBufferProperties ext = {.sType = VK_STRUCTURE_TYPE_EXTERNAL_BUFFER_PROPERTIES};
    vkGetPhysicalDeviceExternalBufferProperties(gpu, &query, &ext);
    VkExternalMemoryProperties p = ext.externalMemoryProperties;
    fprintf(out, "externalMemoryFeatures=%#x exportFromImportedHandleTypes=%#x compatible=%#x\n",
            p.externalMemoryFeatures, p.exportFromImportedHandleTypes, p.compatibleHandleTypes);
    REQUIRE((p.externalMemoryFeatures & VK_EXTERNAL_MEMORY_FEATURE_EXPORTABLE_BIT) &&
                (blob || (p.exportFromImportedHandleTypes & type)),
            "Venus export capability");
    REQUIRE(!gpu_mapping || (p.externalMemoryFeatures & VK_EXTERNAL_MEMORY_FEATURE_IMPORTABLE_BIT),
            "opaque fd import capability");
    REQUIRE(dedicated || !(p.externalMemoryFeatures & VK_EXTERNAL_MEMORY_FEATURE_DEDICATED_ONLY_BIT),
            "Venus non-dedicated allocation");

    vkGetPhysicalDeviceQueueFamilyProperties(gpu, &n, NULL);
    families = calloc(n, sizeof(*families));
    REQUIRE(families, "queue family allocation");
    vkGetPhysicalDeviceQueueFamilyProperties(gpu, &n, families);
    uint32_t family = 0;
    while (family < n && !(families[family].queueFlags & VK_QUEUE_COMPUTE_BIT))
        family++;
    REQUIRE(family < n, "compute queue family");
    float priority = 1;
    VkDeviceQueueCreateInfo qci = {.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO,
                                   .queueFamilyIndex = family,
                                   .queueCount = 1,
                                   .pQueuePriorities = &priority};
    VkDeviceCreateInfo dci = {.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO,
                              .queueCreateInfoCount = 1,
                              .pQueueCreateInfos = &qci,
                              .enabledExtensionCount = required,
                              .ppEnabledExtensionNames = extensions};
    CHECK(vkCreateDevice(gpu, &dci, NULL, &device));
    VkQueue queue;
    vkGetDeviceQueue(device, family, 0, &queue);

    VkExternalMemoryBufferCreateInfo external = {
        .sType = VK_STRUCTURE_TYPE_EXTERNAL_MEMORY_BUFFER_CREATE_INFO, .handleTypes = type};
    VkBufferCreateInfo bci = {.sType = VK_STRUCTURE_TYPE_BUFFER_CREATE_INFO,
                              .pNext = &external,
                              .size = 2 * page,
                              .usage = usage,
                              .sharingMode = VK_SHARING_MODE_EXCLUSIVE};
    CHECK(vkCreateBuffer(device, &bci, NULL, &buffer));
    VkMemoryRequirements req;
    vkGetBufferMemoryRequirements(device, buffer, &req);
    VkPhysicalDeviceMemoryProperties mp;
    vkGetPhysicalDeviceMemoryProperties(gpu, &mp);
    VkMemoryPropertyFlags flags = VK_MEMORY_PROPERTY_HOST_VISIBLE_BIT | VK_MEMORY_PROPERTY_HOST_COHERENT_BIT;
    uint32_t index = 0;
    while (index < mp.memoryTypeCount &&
           (!(req.memoryTypeBits & (1u << index)) || (mp.memoryTypes[index].propertyFlags & flags) != flags))
        index++;
    REQUIRE(index < mp.memoryTypeCount, "host-visible coherent memory type");
    VkExportMemoryAllocateInfo export = {.sType = VK_STRUCTURE_TYPE_EXPORT_MEMORY_ALLOCATE_INFO,
                                         .handleTypes = type};
    VkMemoryDedicatedAllocateInfo dedicate = {.sType = VK_STRUCTURE_TYPE_MEMORY_DEDICATED_ALLOCATE_INFO,
                                              .buffer = buffer};
    if (dedicated)
        export.pNext = &dedicate;
    allocation = dedicated ? req.size : (req.size + page - 1) & ~(VkDeviceSize)(page - 1);
    if (blob) {
        // Bind two independent resources at distinct offsets of one non-dedicated allocation.
        CHECK(vkCreateBuffer(device, &bci, NULL, &second));
        allocation = (allocation + req.alignment - 1) & ~(req.alignment - 1);
        allocation *= 2;
    }
    VkMemoryAllocateInfo alloc = {.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO,
                                  .pNext = &export,
                                  .allocationSize = allocation,
                                  .memoryTypeIndex = index};
    if (reverse)
        CHECK(vkCreateDevice(gpu, &dci, NULL, &mapper));
    VkDevice exporter = reverse ? mapper : device;
    VkDeviceMemory *export_memory = reverse ? &imported : &memory;
    CHECK(vkAllocateMemory(exporter, &alloc, NULL, export_memory));
    if (!reverse)
        CHECK(vkBindBufferMemory(device, buffer, memory, 0));
    if (blob) {
        if (!reverse)
            CHECK(vkBindBufferMemory(device, second, memory, allocation / 2));
        PFN_vkGetMemoryAndroidHardwareBufferANDROID get_ahb =
            (PFN_vkGetMemoryAndroidHardwareBufferANDROID)vkGetDeviceProcAddr(
                exporter, "vkGetMemoryAndroidHardwareBufferANDROID");
        REQUIRE(get_ahb, "vkGetMemoryAndroidHardwareBufferANDROID entry point");
        VkMemoryGetAndroidHardwareBufferInfoANDROID info = {
            .sType = VK_STRUCTURE_TYPE_MEMORY_GET_ANDROID_HARDWARE_BUFFER_INFO_ANDROID, .memory = *export_memory};
        CHECK(get_ahb(exporter, &info, &ahb));
    } else {
        PFN_vkGetMemoryFdKHR get_fd = (PFN_vkGetMemoryFdKHR)vkGetDeviceProcAddr(device, "vkGetMemoryFdKHR");
        REQUIRE(get_fd, "vkGetMemoryFdKHR entry point");
        VkMemoryGetFdInfoKHR fdinfo = {
            .sType = VK_STRUCTURE_TYPE_MEMORY_GET_FD_INFO_KHR, .memory = memory, .handleType = type};
        CHECK(get_fd(device, &fdinfo, &fd));
    }
    if (gpu_mapping) {
        if (!reverse)
            CHECK(vkCreateDevice(gpu, &dci, NULL, &mapper));
        VkDevice importer = reverse ? device : mapper;
        VkImportMemoryFdInfoKHR import = {
            .sType = VK_STRUCTURE_TYPE_IMPORT_MEMORY_FD_INFO_KHR, .handleType = type, .fd = fd};
        VkImportAndroidHardwareBufferInfoANDROID import_ahb = {
            .sType = VK_STRUCTURE_TYPE_IMPORT_ANDROID_HARDWARE_BUFFER_INFO_ANDROID, .buffer = ahb};
        if (blob) {
            PFN_vkGetAndroidHardwareBufferPropertiesANDROID get_props =
                (PFN_vkGetAndroidHardwareBufferPropertiesANDROID)vkGetDeviceProcAddr(
                    importer, "vkGetAndroidHardwareBufferPropertiesANDROID");
            REQUIRE(get_props, "vkGetAndroidHardwareBufferPropertiesANDROID entry point");
            VkAndroidHardwareBufferPropertiesANDROID props = {
                .sType = VK_STRUCTURE_TYPE_ANDROID_HARDWARE_BUFFER_PROPERTIES_ANDROID};
            CHECK(get_props(importer, ahb, &props));
            if (reverse) {
                uint32_t types = req.memoryTypeBits & props.memoryTypeBits;
                REQUIRE(types, "GPU import memory type");
                alloc.memoryTypeIndex = (uint32_t)__builtin_ctz(types);
                VkPhysicalDeviceIDProperties id = {.sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_ID_PROPERTIES};
                VkPhysicalDeviceProperties2 properties = {
                    .sType = VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2, .pNext = &id};
                vkGetPhysicalDeviceProperties2(gpu, &properties);
                memcpy(reverse->uuid, id.deviceUUID, sizeof(reverse->uuid));
                reverse->cpu_type = index;
                reverse->gpu_type = alloc.memoryTypeIndex;
                fprintf(out, "CPU export type=%u, GPU import type=%u\n", index, alloc.memoryTypeIndex);
            }
            REQUIRE(props.allocationSize >= allocation &&
                        (props.memoryTypeBits & (1u << alloc.memoryTypeIndex)),
                    "AHB import memory properties");
            alloc.allocationSize = props.allocationSize;
        }
        if (dedicated) {
            CHECK(vkCreateBuffer(mapper, &bci, NULL, &import_buffer));
            dedicate.buffer = import_buffer;
            import.pNext = &dedicate;
        }
        alloc.pNext = blob ? (void *)&import_ahb : (void *)&import;
        CHECK(vkAllocateMemory(importer, &alloc, NULL, reverse ? &memory : &imported));
        fd = -1;
        if (reverse) {
            CHECK(vkBindBufferMemory(device, buffer, memory, 0));
            CHECK(vkBindBufferMemory(device, second, memory, allocation / 2));
        }
        if (dedicated)
            CHECK(vkBindBufferMemory(mapper, import_buffer, imported, 0));
        CHECK(vkMapMemory(mapper, imported, 0, allocation, 0, &mapping));
    } else {
        mapping = mmap(NULL, allocation, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
        if (mapping == MAP_FAILED) {
            fprintf(out, "FAIL mmap: %s\n", strerror(errno));
            mapping = NULL;
            goto done;
        }
        if (!cpu_access(out, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_WRITE))
            goto done;
    }
    uint32_t *words = mapping;
    const size_t dst_word = blob ? allocation / 2 / 4 : page / 4;
    for (uint32_t i = 0; i < page / 4; i++) {
        words[i] = i ^ 0xa5c39687u;
        words[dst_word + i] = ~words[i];
    }
    if (!gpu_mapping && !cpu_access(out, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_WRITE))
        goto done;
    VkCommandPoolCreateInfo pci = {.sType = VK_STRUCTURE_TYPE_COMMAND_POOL_CREATE_INFO,
                                   .queueFamilyIndex = family};
    CHECK(vkCreateCommandPool(device, &pci, NULL, &pool));
    VkCommandBufferAllocateInfo cai = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_ALLOCATE_INFO,
                                       .commandPool = pool,
                                       .level = VK_COMMAND_BUFFER_LEVEL_PRIMARY,
                                       .commandBufferCount = 1};
    VkCommandBuffer cmd;
    CHECK(vkAllocateCommandBuffers(device, &cai, &cmd));
    VkCommandBufferBeginInfo begin = {.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO};
    CHECK(vkBeginCommandBuffer(cmd, &begin));
    VkBufferCopy region = {.dstOffset = blob ? 0 : page, .size = page};
    vkCmdCopyBuffer(cmd, buffer, blob ? second : buffer, 1, &region);
    VkMemoryBarrier barrier = {.sType = VK_STRUCTURE_TYPE_MEMORY_BARRIER,
                               .srcAccessMask = VK_ACCESS_TRANSFER_WRITE_BIT,
                               .dstAccessMask = VK_ACCESS_HOST_READ_BIT};
    vkCmdPipelineBarrier(cmd, VK_PIPELINE_STAGE_TRANSFER_BIT, VK_PIPELINE_STAGE_HOST_BIT, 0, 1, &barrier, 0,
                         NULL, 0, NULL);
    CHECK(vkEndCommandBuffer(cmd));
    VkFenceCreateInfo fci = {.sType = VK_STRUCTURE_TYPE_FENCE_CREATE_INFO};
    CHECK(vkCreateFence(device, &fci, NULL, &fence));
    VkSubmitInfo submit = {
        .sType = VK_STRUCTURE_TYPE_SUBMIT_INFO, .commandBufferCount = 1, .pCommandBuffers = &cmd};
    CHECK(vkQueueSubmit(queue, 1, &submit, fence));
    VkResult wait = vkWaitForFences(device, 1, &fence, VK_TRUE, 5000000000ull);
    if (wait != VK_SUCCESS) {
        fprintf(out, "FAIL vkWaitForFences: VkResult %d\n", wait);
        // Device destruction requires completion of all pending work.
        vkDeviceWaitIdle(device);
        goto done;
    }
    if (!gpu_mapping && !cpu_access(out, fd, DMA_BUF_SYNC_START | DMA_BUF_SYNC_READ))
        goto done;
    passed = true;
    for (uint32_t i = 0; i < page / 4; i++) {
        if (words[dst_word + i] != (i ^ 0xa5c39687u)) {
            fprintf(out, "FAIL readback at word %u: %#x\n", i, words[dst_word + i]);
            passed = false;
            break;
        }
    }
    if (!gpu_mapping && !cpu_access(out, fd, DMA_BUF_SYNC_END | DMA_BUF_SYNC_READ))
        passed = false;
    if (passed)
        fprintf(out, "verified %zu words\n", page / 4);
done:
    if (fence)
        vkDestroyFence(device, fence, NULL);
    if (pool)
        vkDestroyCommandPool(device, pool, NULL);
    if (mapping && gpu_mapping)
        vkUnmapMemory(mapper, imported);
    if (mapping && !gpu_mapping)
        munmap(mapping, allocation);
    if (fd >= 0)
        close(fd);
    if (import_buffer)
        vkDestroyBuffer(mapper, import_buffer, NULL);
    if (imported)
        vkFreeMemory(mapper, imported, NULL);
    if (mapper)
        vkDestroyDevice(mapper, NULL);
    if (ahb)
        AHardwareBuffer_release(ahb);
    if (second)
        vkDestroyBuffer(device, second, NULL);
    if (buffer)
        vkDestroyBuffer(device, buffer, NULL);
    if (memory)
        vkFreeMemory(device, memory, NULL);
    if (device)
        vkDestroyDevice(device, NULL);
    free(families);
    free(available);
    return passed;
}

static bool probe(FILE *out, enum path path, struct gpu_route *reverse) {
    bool passed = false;
    fprintf(out, "uid=%u page=%d path=%s\n", getuid(), getpagesize(),
            (const char *[]){"dma-buf", "opaque-fd", "dedicated-control", "android-blob", "cpu-export-blob"}[path]);
    VkApplicationInfo app = {.sType = VK_STRUCTURE_TYPE_APPLICATION_INFO, .apiVersion = VK_API_VERSION_1_1};
    VkInstanceCreateInfo ci = {.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO, .pApplicationInfo = &app};
    VkInstance instance = VK_NULL_HANDLE;
    VkPhysicalDevice *devices = NULL;
    uint32_t n = 0;
    CHECK(vkCreateInstance(&ci, NULL, &instance));
    CHECK(vkEnumeratePhysicalDevices(instance, &n, NULL));
    REQUIRE(n, "no Vulkan physical devices");
    devices = calloc(n, sizeof(*devices));
    REQUIRE(devices, "physical device list allocation");
    CHECK(vkEnumeratePhysicalDevices(instance, &n, devices));
    for (uint32_t i = 0; i < n; i++) {
        if (probe_device(out, devices[i], path, reverse)) {
            passed = true;
            fputs("PASS\n", out);
            break;
        }
    }
done:
    free(devices);
    if (instance)
        vkDestroyInstance(instance, NULL);
    return passed;
}

bool appine_gpu_probe(FILE *out, enum path path) {
    struct gpu_route route;
    return probe(out, path, path == CPU_EXPORT_BLOB ? &route : NULL);
}

bool appine_gpu_probe_reverse(FILE *out, struct gpu_route *route) { return probe(out, CPU_EXPORT_BLOB, route); }
