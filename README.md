## 0x01 Brief About ElfHook

&emsp;&emsp;这份ElfHook的代码参考boyliang的AllHookInOne, 修复AllHookInOne的
ElfHook中的一些问题，同时也解决我们项目中遇到的一些问题。

- **NOT** DT_HAST in .dynmaic section，but .gun.hash instead.

- **NOT** DT_REL and DT_RELSZ in .dynmaic section, but DT_ANDROID_REL and DT_ANDROID_RELSZ instead.

- 计算动态库加载的base_addr是错误的，应该使用bias_addr来计算出ehdr、phdr和shdr之外的所有地址。

- 替换函数时，修改page的读写权限时，在SEAndroid上PROT_EXEC和PROT_WRITE同时设置**可能**会导致异常，

- after hook "dlopen" function, how to get base_addr from return value of old dlopen in new dlopen function.

- support aarch64 (arm64-v8a)

ref:

&emsp;AllHookInOne : [https://github.com/boyliang/AllHookInOne.git]

&emsp;AllHookInOne说明 : [http://bbs.pediy.com/showthread.php?p=1328038]

&emsp;bionic : [https://android.googlesource.com/platform/bionic]


## 0x02 How To Build

#### Export android ndk path

> export -p PATH=$PATH:$ANDROID_NDK


#### Build

> make

> make clean

> make install  # copy libElfHook.so to jniLibs dir in Demo. 

#### or

> ndk-build NDK_PROJECT_PATH=. NDK_OUT=./objs NDK_LIBS_OUT=./bin APP_BUILD_SCRIPT=./Android.mk APP_PLATFORM=android-23 APP_ABI=arm64-v8a,armeabi-v7a APP_STL=stlport_static

## 0x03 How To Use


elf_module is a shared library or executable, elf_hooker is wrapper of hook function.

- bool elf_hooker::phrase_proc_maps()

phrase /proc/self/maps to create all elf modules have been loadded

- void elf_hooker::dump_module_list()

print all elf moudle's info, base addr and full path.

- void elf_hooker::set_prehook_cb( prehook_cb ):

set a callback function, which would be invoked before hooked. if it return false,  prehook_cb function like  this:

> bool prehook_cb(const char* module_name, const char* func_name);

> &emsp;module_name: the full filename of shared library or executable.

> &emsp;func_name: function name would be hooked.

- void elf_hooker::hook_all_modules(const char \*func_name, void \*pfn_new, void\*\* ppfn_old)

hook a function of all the modules, **MUST** call phrase_proc_maps() before hook_all_modules()

> &emsp;func_name: the name of function that will be hooked.

> &emsp;pfn_new: new function pointer

> &emsp;ppfn_old: return raw function pointer, ppfn_old **MUST NOT** be NULL

- bool elf_hooker::hook(elf_module \*module, const char\* func_name, void \*pfn_new, void \*\*ppfn_old)

hook a function of a single module.

> &emsp;module: pointer of elf_module.

> &emsp;other parameters is the same as hook_all_modules()
