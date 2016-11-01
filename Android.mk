LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := hijack-app_process64
LOCAL_SRC_FILES := \
	hijack-app_process64.c
LOCAL_CFLAGS += -DDEBUG
LOCAL_SHARED_LIBRARIES := liblog libcutils libselinux
LOCAL_LDLIBS := -llog -lselinux -lcutils
include $(BUILD_EXECUTABLE)
