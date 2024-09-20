#include <cinttypes>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <android/log.h>
#include <cstdarg>
#include <link.h>
#include <sys/auxv.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <cerrno>
#include <cstring>

#include <vector>

#include "zygisk_next_api.h"

// An example module which inject to adbd and hook some functions

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "ZnAdbRoot", __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "ZnAdbRoot", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "ZnAdbRoot", __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "ZnAdbRoot", __VA_ARGS__)
#define PLOGE(fmt, args...) LOGE(fmt " failed with %d: %s", ##args, errno, strerror(errno))

static int my_log_debuggable() {
    return 1;
}

// this function will be called only if --root-seclabel is specified
// https://cs.android.com/android/platform/superproject/main/+/main:packages/modules/adb/daemon/main.cpp;l=169;drc=8b9705698014252b6d42b9c2d469fe92f6ffc56e
static int (*orig_setcon)(const char* c);
static int my_setcon(const char *c) {
    if (getuid() != 0) return orig_setcon(c);
    int r = orig_setcon("u:r:magisk:s0");
    if (r == -1) {
        PLOGE("set magisk");
        // retry with ksu
        errno = 0;
        r = orig_setcon("u:r:su:s0");
        if (r == -1) {
            PLOGE("set ksu");
            errno = 0;
            r = orig_setcon(c);
        }
    }

    int e = errno;

    int fd = open("/proc/self/attr/sockcreate", O_RDWR | O_CLOEXEC);
    if (fd >= 0) {
        if (write(fd, "u:r:adbd:s0", sizeof("u:r:adbd:s0") - 1) == -1) {
            PLOGE("set sock con");
        }
        close(fd);
    }

    errno = e;
    return r;
}

void onModuleLoaded(void* self_handle, const struct ZygiskNextAPI* api) {
    LOGI("module loaded");

    // get base address of adbd
    void* base = nullptr;
    dl_iterate_phdr([](struct dl_phdr_info* info, size_t sz, void* data) -> int {
        auto linker_base = (uintptr_t) getauxval(AT_BASE);
        if (linker_base == info->dlpi_addr)
            return 0;
        *reinterpret_cast<void**>(data) = (void*) info->dlpi_addr;
        return 1;
    }, &base);

    LOGI("adbd base %p", base);

    // plt hook adbd
    if (api->pltHook(base, "__android_log_is_debuggable", (void*) my_log_debuggable, nullptr) == ZN_SUCCESS
    &&  api->pltHook(base, "selinux_android_setcon", (void*) my_setcon, (void**) &orig_setcon) == ZN_SUCCESS) {
        LOGI("plt hook success");
    } else {
        LOGI("plt hook failed");
    }
}

// declaration of the zygisk next module
__attribute__((visibility("default"), unused))
struct ZygiskNextModule zn_module = {
        .target_api_version = ZYGISK_NEXT_API_VERSION_1,
        .onModuleLoaded = onModuleLoaded
};
