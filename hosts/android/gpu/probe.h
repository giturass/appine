#pragma once
#include <stdbool.h>
#include <stdio.h>
#include "reverse.h"
enum path { DMA_BUF, OPAQUE_FD, DEDICATED_CONTROL, ANDROID_BLOB, CPU_EXPORT_BLOB };
bool appine_gpu_probe(FILE *out, enum path path);
bool appine_gpu_probe_reverse(FILE *out, struct gpu_route *route);
