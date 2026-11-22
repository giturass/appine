#include "transport.h"
#include <sys/socket.h>
#include <string.h>
#include "vkr_renderer.h"
#include <errno.h>
#include <unistd.h>

size_t appine_gpu_capset(void *caps) { return vkr_get_capset(caps, 0); }

static int request(int fd, const struct gpu_request *req, const uint8_t *cmd, struct gpu_reply *reply,
                   int *received) {
    if (TEMP_FAILURE_RETRY(send(fd, req, sizeof(*req), MSG_NOSIGNAL)) != sizeof(*req))
        goto broken;
    for (size_t i = 0; cmd && i < req->size; i += GPU_CHUNK) {
        size_t n = gpu_chunk_size(req->size - i);
        if (TEMP_FAILURE_RETRY(send(fd, cmd + i, n, MSG_NOSIGNAL)) != (ssize_t)n)
            goto broken;
    }
    memset(reply, 0, sizeof(*reply));
    struct iovec vec = {.iov_base = reply, .iov_len = sizeof(*reply)};
    union {
        struct cmsghdr alignment;
        char data[CMSG_SPACE(2 * sizeof(int))];
    } control;
    struct msghdr msg = {
        .msg_iov = &vec, .msg_iovlen = 1, .msg_control = control.data, .msg_controllen = sizeof(control)};
    ssize_t n = TEMP_FAILURE_RETRY(recvmsg(fd, &msg, MSG_CMSG_CLOEXEC));
    if (n < 0)
        goto broken;
    int result = -1, count = 0;
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS)
            continue;
        for (size_t i = 0; i < (c->cmsg_len - CMSG_LEN(0)) / sizeof(int); i++) {
            int handle;
            memcpy(&handle, (char *)CMSG_DATA(c) + i * sizeof(int), sizeof(handle));
            if (++count == 1)
                result = handle;
            else
                close(handle);
        }
    }
    const bool local_blob = req->op == GPU_CREATE && req->blob && reply->type == VIRGL_RESOURCE_OPAQUE_HANDLE;
    if (n != sizeof(*reply) || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        count != (received && !reply->error && !local_blob)) {
        if (result >= 0)
            close(result);
        goto broken;
    }
    if (received)
        *received = result;
    switch (reply->error) {
    case 0:
    case ENOMEM:
    case ENODEV:
        return reply->error;
    default:
        return EIO;
    }
broken:
    shutdown(fd, SHUT_RDWR);
    return EIO;
}

int appine_gpu_open(int fd, int probe, struct gpu_route *route) {
    struct gpu_reply reply;
    int error = request(fd, &(struct gpu_request){.op = GPU_OPEN, .probe = probe != 0}, NULL, &reply, NULL);
    if (error)
        return -1;
    *route = reply.route;
    return reply.type;
}

int appine_gpu_reverse_allocator(int fd, const struct gpu_route *route) {
    struct gpu_reply reply;
    int socket = -1;
    if (request(fd, &(struct gpu_request){.op = GPU_REVERSE_ALLOCATOR, .route = *route}, NULL, &reply,
                &socket))
        return -1;
    return socket;
}

int appine_gpu_submit(int fd, uint32_t ring, const uint8_t *cmd, size_t len, int *fence) {
    struct gpu_request req = {.op = GPU_SUBMIT, .ring = ring, .size = len, .fence = fence != NULL};
    struct gpu_reply reply;
    return request(fd, &req, cmd, &reply, fence);
}

void appine_gpu_release(int fd, uint32_t resource) {
    struct gpu_reply reply;
    request(fd, &(struct gpu_request){.op = GPU_RELEASE, .id = resource}, NULL, &reply, NULL);
}

int appine_gpu_create(int fd, uint32_t id, uint64_t blob, uint64_t size, int *type, uint8_t uuid[16],
                      uint32_t *index, uint64_t *allocation, int *handle) {
    struct gpu_request req = {.op = GPU_CREATE, .id = id, .blob = blob, .size = size};
    struct gpu_reply reply;
    int ret = request(fd, &req, NULL, &reply, handle);
    if (ret)
        return ret;
    *type = reply.type;
    memcpy(uuid, reply.info.device_uuid, 16);
    *index = reply.info.memory_type_index;
    *allocation = reply.info.allocation_size;
    return 0;
}
