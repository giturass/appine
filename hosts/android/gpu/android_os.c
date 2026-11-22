// The upstream Android Mesa utility implementation uses private platform headers.
// Venus only needs these two functions from it in an NDK application.
#include <android/log.h>
#include <stdlib.h>

const char *os_get_option(const char *name) { return getenv(name); }

void os_log_message(const char *message) { __android_log_write(ANDROID_LOG_WARN, "appine-venus", message); }
