#if !defined (__ELF_COMMON_H__)
#define __ELF_COMMON_H__



#if 0

#define sTag ("ELFKooH")
#define log_info(...)   do{ __android_log_print(ANDROID_LOG_INFO,   sTag,  __VA_ARGS__); }while(0)
#define log_error(...)  do{ __android_log_print(ANDROID_LOG_ERROR,  sTag,  __VA_ARGS__); }while(0)
#define log_warn(...)   do{ __android_log_print(ANDROID_LOG_WARN,   sTag,  __VA_ARGS__); }while(0)
#define log_dbg(...)    do{ __android_log_print(ANDROID_LOG_DEBUG,  sTag,  __VA_ARGS__); }while(0)
#define log_fatal(...)  do{ __android_log_print(ANDROID_LOG_FATAL,  sTag,  __VA_ARGS__); }while(0)

#else

#define log_info(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_error(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_warn(...)   do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_dbg(...)    do{ fprintf(stdout, __VA_ARGS__); } while(0)
#define log_fatal(...)  do{ fprintf(stdout, __VA_ARGS__); } while(0)
#endif


#define ElfW(type) Elf32_ ## type
//#define ElfW(type) Elf64_ ## type

#define powerof2(x)     ((((x)-1)&(x))==0)

#endif
