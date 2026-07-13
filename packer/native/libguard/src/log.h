#ifndef GUARD_LOG_H
#define GUARD_LOG_H

#include <android/log.h>

#define GUARD_TAG "libguard"

#define GUARD_LOGI(...) __android_log_print(ANDROID_LOG_INFO, GUARD_TAG, __VA_ARGS__)
#define GUARD_LOGW(...) __android_log_print(ANDROID_LOG_WARN, GUARD_TAG, __VA_ARGS__)
#define GUARD_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, GUARD_TAG, __VA_ARGS__)

#endif /* GUARD_LOG_H */
