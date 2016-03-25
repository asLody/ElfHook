#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <map>
#include <string>

#include "elf_module.h"

class elf_hooker {

public:
    elf_hooker();
    ~elf_hooker();


    bool phrase_proc_maps();
    void dump_module_list();

    /* *
        prehook_cb invoked before really hook,
        if prehook_cb NOT set or return true, this module will be hooked,
        if prehook_cb set and return false, this module will NOT be hooked,
    */
    inline void set_prehook_cb(bool (*pfn)(const char*, const char*)) { this->m_prehook_cb = pfn; }
    inline bool hook(elf_module* module, const char *symbol, void *replace_func, void **old_func)
    {
         return module->hook(symbol, replace_func, old_func);
    }

    void hook_all_modules(const char* func_name, void* pfn_new, void** ppfn_old);

protected:

    bool phrase_proc_base_addr(char* addr, void** pbase_addr, void** pend_addr);

protected:
//    std::vector<elf_module> m_module_list;
    std::map<std::string, elf_module> m_modules;
    bool (*m_prehook_cb)(const char* module_name, const char* func_name);
};

#endif
