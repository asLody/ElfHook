#if !defined(__ELF_HOOKER_H__)
#define __ELF_HOOKER_H__


#include <vector>
#include <string>

#include "ElfModule.h"

class ElfHooker {

public:
    ElfHooker();
    ~ElfHooker();
    bool phraseProcMaps();
    void dumpModuleList();

    int modifyMemAccess(void *addr, int prots);
    int clearCache(void *addr, size_t len);
    int replaceFunc(void *addr, void *replace_func, void **old_func);
    int hook(ElfModule* module, const char *symbol, void *replace_func, void **old_func);
    void hookAllModules();
    void testDLOpen();
protected:
    std::vector<ElfModule> moduleList;
};

#endif
