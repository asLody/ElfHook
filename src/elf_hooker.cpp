
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
    this->m_prehook_cb = NULL;
}

elf_hooker::~elf_hooker()
{
    m_modules.clear();
    this->m_prehook_cb = NULL;
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

bool elf_hooker::phrase_dev_num(char* devno, int *pmajor, int *pminor)
{
    *pmajor = 0;
    *pminor = 0;
    if (devno != NULL && strlen(devno) == 5 && devno[2] == ':')
    {
        *pmajor = strtoul(devno + 0, NULL, 16);
        *pminor = strtoul(devno + 3, NULL, 16);
        return true;
    }
    return false;
}

bool elf_hooker::phrase_proc_maps()
{
    log_info("phrase_proc_maps() -->\n");
    m_modules.clear();
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            const char *sep = "\t \r\n";
            char *line = NULL;
            char* addr = strtok_r(buff, sep, &line);
            if (!addr) {
                continue;
            }

            char *flags = strtok_r(NULL, sep, &line);
            if (!flags || flags[0] != 'r' || flags[3] == 's') {
                //
                /*
                    1. mem section cound NOT be read, without 'r' flag.
                    2. read from base addr of /dev/mail module would crash.
                       i dont know how to handle it, just skip it.

                       1f5573000-1f58f7000 rw-s 1f5573000 00:0c 6287 /dev/mali0

                */
                continue;
            }
            strtok_r(NULL, sep, &line);  // offsets
            char *dev = strtok_r(NULL, sep, &line);  // dev number.
            int major = 0, minor = 0;
            if (!phrase_dev_num(dev, &major, &minor) || major == 0) {
                /*
                    if dev major number equal to 0, mean the module must NOT be
                    a shared or executable object loaded from disk.
                    e.g:
                    lookup symbol from [vdso] would crash.
                    7f7b48a000-7f7b48c000 r-xp 00000000 00:00 0  [vdso]
                */
                continue;
            }

            strtok_r(NULL, sep, &line);  // node

            char* filename = strtok_r(NULL, sep, &line); //module name
            if (!filename) {
                continue;
            }
            std::string module_name = filename;
            std::map<std::string, elf_module>::iterator itor = m_modules.find(module_name);
            if (itor == m_modules.end())
            {
                void* base_addr = NULL;
                void* end_addr = NULL;
                if (phrase_proc_base_addr(addr, &base_addr, &end_addr) && elf_module::is_elf_module(base_addr))
                {
                    elf_module module(reinterpret_cast<ElfW(Addr)>
                    (base_addr), module_name.c_str());
                    m_modules.insert(std::pair<std::string, elf_module>(module_name, module));
                }
            }
        }
        fclose(fd);
        return 0;
    }
    return -1;

}

void elf_hooker::dump_module_list()
{
    for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                    itor != m_modules.end();
                    itor++ )
    {
        log_info("BaseAddr: %lx ModuleName: %s\n", (unsigned long)itor->second.get_base_addr(), itor->second.get_module_name());
    }
}

void elf_hooker::hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old)
{
    for (std::map<std::string, elf_module>::iterator itor = m_modules.begin();
                    itor != m_modules.end();
                    itor++ )
    {
        if (this->m_prehook_cb && !this->m_prehook_cb(itor->second.get_module_name(), func_name))
        {
            continue;
        }
        log_info("Hook Module : %s\n", itor->second.get_module_name());
        this->hook(&itor->second, func_name, pfn_new, ppfn_old);
    }
    return;
}

void elf_hooker::dump_proc_maps()
{
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd > 0)
    {
        char buff[2048+1];
        while(fgets(buff, 2048, fd) != NULL)
        {
            log_info("%s\n", buff);
        }
        fclose(fd);
    }
    return;
}
// void* elf_hooker::caculate_base_addr_from_soinfo_pointer(void* soinfo_addr)
// {
//     uint32_t
//     if (soinfo_addr == NULL) {
//         return NULL;
//     }
// }
