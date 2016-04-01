

SRC_DIR = ./src
OBJ_DIR = ./objs
BIN_DIR = ./bin


JNIFLAGS     = APP_BUILD_SCRIPT=./Android.mk
JNIFLAGS     += APP_ABI=arm64-v8a,armeabi-v7a
JNIFLAGS     += APP_PLATFORM=android-23
JNIFLAGS     += APP_STL=stlport_static

JNILIBPATH   = ./Demo/app/src/main/jniLibs


all:
	@echo '\n  [NDK-BUILD] '$(PWD)'\n\n';ndk-build NDK_PROJECT_PATH=. NDK_OUT=$(OBJ_DIR) NDK_LIBS_OUT=$(BIN_DIR) $(JNIFLAGS)

clean:
	@echo '\n  [NDK-BUILD] clean'$(PWD)'\n\n';ndk-build clean NDK_PROJECT_PATH=. NDK_OUT=$(OBJ_DIR) NDK_LIBS_OUT=$(BIN_DIR) $(JNIFLAGS)

install :  all
		@echo '[CP] ' $(BIN_DIR)/armeabi-v7a/libElfHook.so $(JNILIBPATH)/armeabi-v7a/libElfHook.so; cp  $(BIN_DIR)/armeabi-v7a/libElfHook.so  $(JNILIBPATH)/armeabi-v7a/libElfHook.so
		@echo '[CP] ' $(BIN_DIR)/arm64-v8a/libElfHook.so $(JNILIBPATH)/arm64-v8a/libElfHook.so; cp  $(BIN_DIR)/arm64-v8a/libElfHook.so  $(JNILIBPATH)/arm64-v8a/libElfHook.so
