

######### 检查安装路径  ##########
ifndef PREFIX
PREFIX        = /usr
endif
			
EXEC          =	

ANDROID_NDK  =  /Users/wuxin/workspace/android/android-ndk-r10b
CROSS_PREFIX =	arm-linux-androideabi-
SYSROOT      = $(ANDROID_NDK)/platforms/android-19/arch-arm

STL_PORT     = $(ANDROID_NDK)/sources/cxx-stl/stlport

CC           = $(CROSS_PREFIX)gcc
AR           = $(CROSS_PREFIX)ar
LD           = $(CROSS_PREFIX)gcc
RANLIB       = $(CROSS_PREFIX)ranlib
STRIP        =	$(CROSS_PREFIX)strip
CFLAGS       += -Wall --sysroot=$(SYSROOT) 
CFLAGS       += -I$(STL_PORT)/stlport
LDFLAGS	     += --sysroot=$(SYSROOT) 
LDFLAGS      += $(STL_PORT)/libs/armeabi-v7a/libstlport_static.a
LDFLAGS      += -lstdc++ 
EXTRA_OBJS   += 
