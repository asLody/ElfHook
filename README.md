## 0x01 Brief About ElfHook

&emsp;&emsp;这份ElfHook的代码参考boyliang的AllHookInOne, 修复AllHookInOne的
ElfHook中的一些问题，同时也解决我们项目中遇到的一些问题。

- .dynmaic中不使用DT_HAST，而是使用.gun.hash。

- .dynmaic中没有DT_REL和DT_RELSZ, 而实用DT_ANDROID_REL和DT_ANDROID_RELSZ。

- 计算动态库加载的base_addr是错误的，应该使用bias_addr来计算出ehdr、phdr和shdr之外的所有地址。

- 替换函数时，修改page的读写权限时，在SEAndroid上PROT_EXEC和PROT_WRITE同时设置**可能**会导致异常，

- hook "dlopen" 函数，在新的dlopen再去hook新加载的动态库时如何得到新动态库的base_addr


ref:

&emsp;AllHookInOne : [https://github.com/boyliang/AllHookInOne.git]

&emsp;AllHookInOne说明 : [http://bbs.pediy.com/showthread.php?p=1328038]

&emsp;bionic : [https://android.googlesource.com/platform/bionic]


## 0x02 How To Make

#### Export android ndk path

> export -p PATH=$PATH:$ANDROID_NDK/toolchains/arm-linux-androideabi-4.6/prebuilt/darwin-x86_64/bin

#### Build executable run in "adb shell", output file is "./bin/ElfHook"

> make

> make clean

#### Build jni library, output file is "./bin/armeabi/libElfHook.so"

> make jni

> make jni-clean
