
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
//    m_module_list.clear();
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

bool elf_hooker::phrase_proc_maps()
{
//    m_module_list.clear();
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
            if (!flags || flags[0] != 'r') {
                // mem section cound NOT be read..
                continue;
            }
            strtok_r(NULL, sep, &line);  // offsets
            strtok_r(NULL, sep, &line);  // dev
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
//                    log_info("insert module: %p, %s\n", base_addr, module_name.c_str());
                    elf_module module((uint32_t)base_addr, module_name.c_str());
                    m_modules.insert(std::pair<std::string, elf_module>(module_name, module));
                }
            }
        }
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
        log_info("BaseAddr: %X ModuleName: %s\n", itor->second.get_base_addr(), itor->second.get_module_name());
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
