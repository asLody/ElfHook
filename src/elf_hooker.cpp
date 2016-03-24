
#include <unistd.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "elf_hooker.h"
#include "elf_common.h"

elf_hooker::elf_hooker()
{
}

elf_hooker::~elf_hooker()
{
    m_module_list.clear();
}

bool elf_hooker::phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr)
{
    char* split = strchr(addr, '-');
    if (split != NULL) {
        if (pbase_addr != NULL)
        {
            *pbase_addr = (void *) strtoul(addr, NULL, 16);
        }
        if (pend_addr != NULL)
        {
            *pend_addr = (void *) strtoul(split + 1, NULL, 16);
        }
        return true;
    }
    return false;
}

bool elf_hooker::phrase_proc_maps()
{
    m_module_list.clear();
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            const char *sep = "\t \r\n";
            char *line = NULL;
            char* addr = strtok_r(buff, sep, &line);
            if (!addr)
            {
                continue;
            }
            char* flags = strtok_r(NULL, sep, &line);
            if (!flags || flags[2] != 'x')
            {
                continue;
            }
            strtok_r(NULL, sep, &line);  // offsets
            strtok_r(NULL, sep, &line);  // dev
            strtok_r(NULL, sep, &line);  // node

            char* moduleName = strtok_r(NULL, sep, &line); //module name
            void* baseAddr = NULL;
            void* endAddr = NULL;
            if (phrase_proc_base_addr(addr, &baseAddr, &endAddr))
            {
                elf_module module((uint32_t)baseAddr, moduleName);
                m_module_list.push_back(module);
            }
            //if (strstr())
        }
        return 0;
    }
    return -1;

}

void elf_hooker::dump_module_list()
{
    for (std::vector<elf_module>::iterator itor = m_module_list.begin();
                itor != m_module_list.end();
                itor ++)
    {
        log_info("BaseAddr: %X ModuleName: %s\n", itor->get_base_addr(), itor->get_module_name());
    }
}

void* (*old_dlopen)(const char* filename, int flag);

extern "C"
void* nativehook_impl_dlopen(const char* filename, int flag)
{
    log_info("nativehook_impl_dlopen ->\n");
    void* res = old_dlopen(filename, flag);
    return res;
}

void elf_hooker::hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old)
{
    old_dlopen = NULL;
    for (std::vector<elf_module>::iterator itor = m_module_list.begin();
                itor != m_module_list.end();
                itor ++)
    {
        const char* moduleName = "/system/lib/libart.so";
//        const char* moduleName = "/data/ElfHook";
        if (strncmp(itor->get_module_name(), moduleName, strlen(moduleName)) != 0)
        {
            continue;
        }
        log_info("Hook Module : %s\n", itor->get_module_name());
        this->hook(itor, func_name, pfn_new, ppfn_old);

    }
    return;
}



// #include <dlfcn.h>
//
// void elf_hooker::testDLOpen()
// {
//
//     void* h = dlopen("libart.so", RTLD_LAZY);
//     void* f = dlsym(h,"artAllocObjectFromCodeResolvedRegion");
//     log_info("artAllocObjectFromCodeResolvedRegion : %p\n", f);
//     //dlclose(h);
// }

//        this->hook(itor, "dlopen", (void*)nativehook_impl_dlopen, (void**)&old_dlopen);
//        this->hook(itor, "artAllocObjectFromCodeResolvedRegion", (void*)nativehook_impl_dlopen, (void**)&old_dlopen);
