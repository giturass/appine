#include <jni.h>
#include <stdlib.h>
#include "probe.h"

JNIEXPORT jstring JNICALL Java_io_github_mthli_appine_gpuprobe_Probe_roundTrip(JNIEnv *env, jclass cls,
                                                                               jint path) {
    (void)cls;
    if (path < DMA_BUF || path > CPU_EXPORT_BLOB)
        return (*env)->NewStringUTF(env, "Unknown GPU probe path");
    char *report = NULL;
    size_t size = 0;
    FILE *out = open_memstream(&report, &size);
    if (!out)
        return (*env)->NewStringUTF(env, "FAIL open_memstream");
    appine_gpu_probe(out, path);
    fclose(out);
    jstring result = (*env)->NewStringUTF(env, report);
    free(report);
    return result;
}
