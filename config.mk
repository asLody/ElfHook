

######### 安装路径 ##########

ifndef PREFIX
PREFIX        = /usr
endif

EXEC          =

ANDROID_NDK  =  /Users/wuxin/Library/Android/ndk
CROSS_PREFIX =	arm-linux-androideabi-
SYSROOT      = $(ANDROID_NDK)/platforms/android-19/arch-arm

STL_PORT     = $(ANDROID_NDK)/sources/cxx-stl/stlport

CC           = $(CROSS_PREFIX)gcc
AR           = $(CROSS_PREFIX)ar
LD           = $(CROSS_PREFIX)gcc
RANLIB       = $(CROSS_PREFIX)ranlib
STRIP        =	$(CROSS_PREFIX)strip
CFLAGS       += -fPIE -Werror --sysroot=$(SYSROOT) -DELFHOOK_STANDALONE=1
CFLAGS       += -I$(STL_PORT)/stlport
LDFLAGS      += --sysroot=$(SYSROOT)
LDFLAGS      += $(STL_PORT)/libs/armeabi-v7a/libstlport_static.a
LDFLAGS      += -fPIE -pie -lstdc++
JNIFLAGS     = APP_BUILD_SCRIPT=./Android.mk
JNIFLAGS     += APP_ABI=arm64-v8a,armeabi-v7a
JNIFLAGS     += APP_PLATFORM=android-23
JNIFLAGS     += APP_STL=stlport_static
EXTRA_OBJS   +=
