#if !defined (__ELF_COMMON_H__)
#define __ELF_COMMON_H__

#include "elf.h"

#include <stdio.h>
#include <stdlib.h>
#include <android/log.h>

#if (ELFHOOK_STANDALONE)

#define log_info(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_error(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_warn(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_fatal(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)

#if 1
#define log_dbg(...)    do{ } while(0)
#else
#define log_dbg(...)    do{ fprintf(stdout, __VA_ARGS__); } while(0)
#endif

#else

#define sTag ("ELFKooH")
#define log_info(...)   do{ __android_log_print(ANDROID_LOG_INFO,   sTag,  __VA_ARGS__); }while(0)
#define log_error(...)  do{ __android_log_print(ANDROID_LOG_ERROR,  sTag,  __VA_ARGS__); }while(0)
#define log_warn(...)   do{ __android_log_print(ANDROID_LOG_WARN,   sTag,  __VA_ARGS__); }while(0)
#define log_dbg(...)    do{ __android_log_print(ANDROID_LOG_DEBUG,  sTag,  __VA_ARGS__); }while(0)
#define log_fatal(...)  do{ __android_log_print(ANDROID_LOG_FATAL,  sTag,  __VA_ARGS__); }while(0)

#endif


#if defined(__LP64__)
#define ElfW(type) Elf64_ ## type
static inline ElfW(Word) elf_r_sym(ElfW(Xword) info) { return ELF64_R_SYM(info); }
static inline ElfW(Xword) elf_r_type(ElfW(Xword) info) { return ELF64_R_TYPE(info); }
#else
#define ElfW(type) Elf32_ ## type
static inline ElfW(Word) elf_r_sym(ElfW(Word) info) { return ELF32_R_SYM(info); }
static inline ElfW(Word) elf_r_type(ElfW(Word) info) { return ELF32_R_TYPE(info); }
#endif

#if defined(__arm__)
#define R_GENERIC_JUMP_SLOT R_ARM_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_ARM_GLOB_DAT
#define R_GENERIC_RELATIVE  R_ARM_RELATIVE
#define R_GENERIC_IRELATIVE R_ARM_IRELATIVE
#define R_GENERIC_ABS       R_ARM_ABS32
#elif defined(__aarch64__)
#define R_GENERIC_JUMP_SLOT R_AARCH64_JUMP_SLOT
#define R_GENERIC_GLOB_DAT  R_AARCH64_GLOB_DAT
#define R_GENERIC_RELATIVE  R_AARCH64_RELATIVE
#define R_GENERIC_IRELATIVE R_AARCH64_IRELATIVE
#define R_GENERIC_ABS       R_AARCH64_ABS64
#endif




#define powerof2(x)     ((((x)-1)&(x))==0)
#define SOINFO_NAME_LEN (128)

inline static int GetTargetElfMachine()
{
#if defined(__arm__)
    return EM_ARM;
#elif defined(__aarch64__)
    return EM_AARCH64;
#elif defined(__i386__)
    return EM_386;
#elif defined(__mips__)
    return EM_MIPS;
#elif defined(__x86_64__)
    return EM_X86_64;
#endif
}

#endif
