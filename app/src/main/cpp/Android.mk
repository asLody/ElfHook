LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
SO_NAME  := ElfHook
LOCAL_MODULE            := ElfHook
LOCAL_SRC_FILES         := elf_common.cpp \
                        elf_hooker.cpp \
                        elf_module.cpp
LOCAL_C_INCLUDES        := $(LOCAL_PATH)
LOCAL_LDLIBS            := -llog
include $(BUILD_SHARED_LIBRARY)
