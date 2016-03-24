#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <vector>
#include <string>

#include "elf_module.h"

class elf_hooker {

public:
    elf_hooker();
    ~elf_hooker();

    bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);
    bool phrase_proc_maps();
    void dump_module_list();

    inline bool hook(elf_module* module, const char *symbol, void *replace_func, void **old_func) 
    {
         return module->hook(symbol, replace_func, old_func);
    }


    void hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old);

protected:
    std::vector<elf_module> m_module_list;
};

#endif
