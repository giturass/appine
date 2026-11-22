#include "transport.h"
#include "probe.h"
#include "render_socket.h"
#include "vkr_renderer.h"
#include "vkr_context.h"
#include <android/log.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "android_blob.h"

enum { GPU_RING_COUNT = 64, GPU_MAX_COMMAND_SIZE = 1024 * 1024 };

// virglrenderer may retire only the last of several completed fences on a ring.
struct pending {
    uint64_t serial;
    int writer;
    struct pending *next;
};
struct worker {
    uint32_t id;
    uint64_t serial;
    struct vkr_context *ctx;
    struct appine_allocator allocator;
    struct pending *fences[GPU_RING_COUNT];
    struct pending **tails[GPU_RING_COUNT];
    struct worker *next;
};
static pthread_mutex_t fence_lock = PTHREAD_MUTEX_INITIALIZER;
static struct worker *workers;
static uint32_t next_id;

static void retire(uint32_t id, uint32_t ring, uint64_t completed) {
    pthread_mutex_lock(&fence_lock);
    struct worker *w = workers;
    while (w && w->id != id)
        w = w->next;
    if (w && ring < GPU_RING_COUNT) {
        struct pending *f;
        while ((f = w->fences[ring]) && f->serial <= completed) {
            TEMP_FAILURE_RETRY(write(f->writer, "1", 1));
            close(f->writer);
            w->fences[ring] = f->next;
            free(f);
        }
        if (!w->fences[ring])
            w->tails[ring] = &w->fences[ring];
    }
    pthread_mutex_unlock(&fence_lock);
}

static void logger(enum virgl_log_level_flags level, const char *msg, void *data) {
    (void)level;
    (void)data;
    __android_log_write(ANDROID_LOG_WARN, "appine-venus", msg);
}

static const struct vkr_renderer_callbacks callbacks = {
    .debug_logger = logger,
    .retire_fence = retire,
};

static int probe_hardware(struct gpu_reply *reply) {
    char *report = NULL;
    size_t size = 0;
    FILE *out = open_memstream(&report, &size);
    bool passed = out && appine_gpu_probe(out, ANDROID_BLOB);
    if (out && !passed && appine_gpu_probe_reverse(out, &reply->route)) {
        passed = true;
        reply->type = 1;
    }
    if (out)
        fclose(out);
    if (!passed)
        __android_log_print(ANDROID_LOG_WARN, "appine-venus", "Hardware probe failed: %s",
                            report ? report : "");
    free(report);
    return passed ? 0 : ENODEV;
}

static bool submit_commands(struct vkr_context *ctx, struct render_socket *socket, size_t size) {
    if (!size)
        return true;
    uint8_t *cmd = malloc(size);
    if (!cmd)
        return false;
    for (size_t offset = 0; offset < size; offset += GPU_CHUNK) {
        if (!render_socket_receive_data(socket, cmd + offset, gpu_chunk_size(size - offset))) {
            free(cmd);
            return false;
        }
    }
    bool ok = vkr_context_submit_cmd(ctx, cmd, size);
    free(cmd);
    return ok;
}

static int submit_fence(struct worker *w, uint32_t ring) {
    struct pending *f = calloc(1, sizeof(*f));
    int pair[2];
    if (!f || pipe2(pair, O_CLOEXEC | O_NONBLOCK) < 0) {
        free(f);
        return -1;
    }
    uint64_t serial = ++w->serial;
    f->serial = serial;
    f->writer = pair[1];
    // Submit may retire the fence immediately. The queue owns the writer from
    // here.
    pthread_mutex_lock(&fence_lock);
    *w->tails[ring] = f;
    w->tails[ring] = &f->next;
    pthread_mutex_unlock(&fence_lock);
    if (!vkr_context_submit_fence(w->ctx, 0, ring, serial)) {
        close(pair[0]);
        return -1;
    }
    return pair[0];
}

static bool run(struct worker *w, struct render_socket *socket) {
    bool initialized = false;
    struct gpu_request req;
    size_t read;
    while (render_socket_receive_request(socket, &req, sizeof(req), &read)) {
        if (read != sizeof(req))
            return false;
        struct gpu_reply reply = {0};
        int fd = -1;
        if (!initialized && req.op != GPU_OPEN)
            return false;
        switch (req.op) {
        case GPU_OPEN:
            if (initialized)
                return false;
            if (req.probe)
                reply.error = probe_hardware(&reply);
            initialized = true;
            break;
        case GPU_REVERSE_ALLOCATOR: {
            int pair[2];
            if (w->ctx->appine_allocator || req.route.cpu_type >= 32 || req.route.gpu_type >= 32 ||
                socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair))
                return false;
            struct timeval timeout = {.tv_sec = 5};
            if (setsockopt(pair[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
                setsockopt(pair[0], SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout))) {
                close(pair[0]);
                close(pair[1]);
                return false;
            }
            w->allocator.fd = pair[0];
            w->allocator.route = req.route;
            w->ctx->appine_allocator = &w->allocator;
            fd = pair[1];
            break;
        }
        case GPU_CREATE: {
            struct virgl_context_blob blob;
            if (!vkr_context_create_resource(w->ctx, req.id, req.blob, req.size, 1, &blob)) {
                reply.error = ENOMEM;
            } else {
                fd = blob.type == VIRGL_RESOURCE_OPAQUE_HANDLE ? -1 : blob.u.fd;
                reply.type = blob.type;
                if (blob.type == VIRGL_RESOURCE_FD_OPAQUE)
                    reply.info = blob.vulkan_info;
            }
            break;
        }
        case GPU_RELEASE:
            vkr_context_destroy_resource(w->ctx, req.id);
            break;
        case GPU_SUBMIT:
            if (req.ring >= GPU_RING_COUNT || req.size > GPU_MAX_COMMAND_SIZE)
                return false;
            if (!submit_commands(w->ctx, socket, req.size))
                return false;
            if (req.fence) {
                fd = submit_fence(w, req.ring);
                if (fd < 0)
                    return false;
            }
            break;
        default:
            return false;
        }
        bool ok = fd < 0 ? render_socket_send_reply(socket, &reply, sizeof(reply))
                         : render_socket_send_reply_with_fds(socket, &reply, sizeof(reply), &fd, 1);
        if (fd >= 0)
            close(fd);
        if (!ok)
            return false;
    }
    return true;
}

static pthread_once_t once = PTHREAD_ONCE_INIT;
static bool ready;
static void initialize(void) {
    ready = vkr_renderer_init(VKR_RENDERER_THREAD_SYNC | VKR_RENDERER_ASYNC_FENCE_CB, &callbacks);
}

void appine_venus_worker(int fd) {
    // Queue threads inherit this mask. A guest can close a fence before
    // retirement.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &set, NULL);
    struct render_socket socket = {.fd = fd};
    struct worker w = {.allocator = {.fd = -1, .lock = PTHREAD_MUTEX_INITIALIZER}};
    for (size_t i = 0; i < GPU_RING_COUNT; i++)
        w.tails[i] = &w.fences[i];
    pthread_once(&once, initialize);
    pthread_mutex_lock(&fence_lock);
    if (ready && next_id != UINT32_MAX)
        w.id = ++next_id;
    pthread_mutex_unlock(&fence_lock);
    if (w.id)
        w.ctx = vkr_context_create(w.id, retire, 6, "appine");
    if (w.ctx) {
        pthread_mutex_lock(&fence_lock);
        w.next = workers;
        workers = &w;
        pthread_mutex_unlock(&fence_lock);
        run(&w, &socket);
        vkr_context_destroy(w.ctx);
        pthread_mutex_lock(&fence_lock);
        struct worker **link = &workers;
        while (*link != &w)
            link = &(*link)->next;
        *link = w.next;
        pthread_mutex_unlock(&fence_lock);
    }
    if (w.allocator.fd >= 0)
        close(w.allocator.fd);
    pthread_mutex_destroy(&w.allocator.lock);
    close(fd);
    for (size_t i = 0; i < GPU_RING_COUNT; i++) {
        while (w.fences[i]) {
            struct pending *f = w.fences[i];
            w.fences[i] = f->next;
            close(f->writer);
            free(f);
        }
    }
}
