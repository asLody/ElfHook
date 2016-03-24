LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := ElfHook
LOCAL_LDLIBS := -llog
LOCAL_SRC_FILES := \
                src/elf_common.cpp \
                src/elf_hooker.cpp \
				src/elf_module.cpp \
				src/main.cpp

LOCAL_C_INCLUDES :=

LOCAL_LDFLAGS :=

#LOCAL_STATIC_LIBRARIES :=
LOCAL_SHARED_LIBRARIES := stdc++

LOCAL_CFLAGS := \
                -Wno-write-strings \
                -DHAVE_LITTLE_ENDIAN \
                -DELFHOOK_STANDALONE=0
include $(BUILD_SHARED_LIBRARY)

####################################

#### include $(BUILD_EXECUTABLE)
