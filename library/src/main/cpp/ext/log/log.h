#pragma once
#define LOG_ALWAYS_FATAL(...) do { } while(0)
#define LOG_ALWAYS_FATAL_IF(c, ...) do { if ((c)) {} } while(0)
#define ALOGV(...) do { } while(0)
#define ALOGD(...) do { } while(0)
#define ALOGI(...) do { } while(0)
#define ALOGW(...) do { } while(0)
#define ALOGE(...) do { } while(0)
#define ALOG_ASSERT(c, ...) do { if (!(c)) {} } while(0)
