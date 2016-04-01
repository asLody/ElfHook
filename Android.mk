LOCAL_PATH := $(call my-dir)


include $(CLEAR_VARS)

LOCAL_MODULE := libElfHook_static

LOCAL_SRC_FILES := \
                src/elf_common.cpp \
                src/elf_hooker.cpp \
                src/elf_module.cpp

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS :=

#LOCAL_STATIC_LIBRARIES :=
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -Werror

include $(BUILD_STATIC_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cpp

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS :=

LOCAL_STATIC_LIBRARIES := ElfHook_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DELFHOOK_STANDALONE=0
include $(BUILD_SHARED_LIBRARY)

####################################

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook.out
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/main.cpp

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS := -fPIC -pie

LOCAL_STATIC_LIBRARIES := ElfHook_static
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DELFHOOK_STANDALONE=1

include $(BUILD_EXECUTABLE)
