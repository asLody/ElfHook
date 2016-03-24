LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook
LOCAL_LDLIBS := -L$(SYSROOT)/usr/lib -llog
LOCAL_SRC_FILES := \
                src/ElfCommon.cpp \
                src/ElfHooker.cpp \
				src/ElfModule.cpp \
				src/main.cpp

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := \
				-fPIE \
				-pie

#LOCAL_STATIC_LIBRARIES :=
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DELFHOOKER_STANDALONE=1
include $(BUILD_SHARED_LIBRARY)
####################################

# include $(BUILD_EXECUTABLE)
