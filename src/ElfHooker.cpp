
#include <unistd.h>
#include <sys/mman.h>
#include <assert.h>
#include <errno.h>
#include <sys/syscall.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ElfHooker.h"
#include "ElfCommon.h"

ElfHooker::ElfHooker()
{
}

ElfHooker::~ElfHooker()
{
    moduleList.clear();
}

bool phraseProcBaseAddr(char* addr, void** pbase_addr, void** pend_addr)
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

bool ElfHooker::phraseProcMaps()
{
    moduleList.clear();
    FILE* fd = fopen("/proc/self/maps", "r");
    if (fd != NULL)
    {
        char buff[512];
        while(fgets(buff, sizeof(buff), fd) != NULL)
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
            if (phraseProcBaseAddr(addr, &baseAddr, &endAddr))
            {
                ElfModule module((uint32_t)baseAddr, moduleName);
                moduleList.push_back(module);
            }
        }
        return 0;
    }
    return -1;

}

void ElfHooker::dumpModuleList()
{
    for (std::vector<ElfModule>::iterator itor = moduleList.begin();
                itor != moduleList.end();
                itor ++)
    {
        log_info("BaseAddr: %X ModuleName: %s\n", itor->getBaseAddr(), itor->getModuleName());
    }
}


#define PAGE_START(addr) (~(getpagesize() - 1) & (addr))

int ElfHooker::modifyMemAccess(void *addr, int prots)
{
	void *page_start_addr = (void *)PAGE_START((uint32_t)addr);
	return mprotect(page_start_addr, getpagesize(), prots);
}

int ElfHooker::clearCache(void *addr, size_t len)
{
	void *end = (uint8_t *)addr + len;
	return syscall(0xf0002, addr, end);
}

int ElfHooker::replaceFunc(void *addr, void *replace_func, void **old_func)
{
	int res = 0;

	if(*(void **)addr == replace_func)
    {
		log_warn("addr %p had been replace.\n", addr);
		goto fail;
	}

	if(!*old_func){
		*old_func = *(void **)addr;
	}

	if(modifyMemAccess((void *)addr, PROT_EXEC|PROT_READ|PROT_WRITE))
    {
        log_error("[-] modifymemAccess fails, error %s.\n", strerror(errno));
		res = 1;
		goto fail;
	}

	*(void **)addr = replace_func;
	clearCache(addr, getpagesize());
	log_info("[+] old_func is %p, replace_func is %p, new_func %p.\n", *old_func, replace_func, (void*)(*(uint32_t *)addr));

fail:
	return res;
}

#define R_ARM_ABS32 0x02
#define R_ARM_GLOB_DAT 0x15
#define R_ARM_JUMP_SLOT 0x16

int ElfHooker::hook(ElfModule* module, const char *symbol, void *replace_func, void **old_func) {

	assert(old_func);
	assert(replace_func);
	assert(symbol);

//module->getElfBySectionView();
	if (!module->getElfBySegmentView()) {
        return 0;
    }
	Elf32_Sym *sym = NULL;
	int symidx = 0;
    uint32_t _baseAddr = (uint32_t)NULL;

	module->findSymByName(symbol, &sym, &symidx);

	if(!sym){
		log_error("[-] Could not find symbol %s\n", symbol);
		goto fail;
	}else{
		log_info("[+] sym %p, symidx %d.\n", sym, symidx);
	}


    if (!module->isExec) {
        _baseAddr = module->baseAddr;
    }
	for (uint32_t i = 0; i < module->relpltsz; i++) {
		Elf32_Rel& rel = module->relplt[i];
		if (ELF32_R_SYM(rel.r_info) == symidx && ELF32_R_TYPE(rel.r_info) == R_ARM_JUMP_SLOT) {

			void *addr = (void *) (_baseAddr + rel.r_offset);
			if (replaceFunc(addr, replace_func, old_func))
				goto fail;
			//only once
			break;
		}
	}

	for (uint32_t i = 0; i < module->reldynsz; i++) {
		Elf32_Rel& rel = module->reldyn[i];
		if (ELF32_R_SYM(rel.r_info) == symidx &&
				(ELF32_R_TYPE(rel.r_info) == R_ARM_ABS32
						|| ELF32_R_TYPE(rel.r_info) == R_ARM_GLOB_DAT)) {

			void *addr = (void *) (_baseAddr + rel.r_offset);
			if (replaceFunc(addr, replace_func, old_func))
				goto fail;
		}
	}

fail:
	return 0;
}



void* (*old_dlopen)(const char* filename, int flag);

extern "C"
void* nativehook_impl_dlopen(const char* filename, int flag)
{
    log_info("nativehook_impl_dlopen ->\n");
    void* res = old_dlopen(filename, flag);
    return res;
}

void ElfHooker::hookAllModules()
{
    old_dlopen = NULL;
    for (std::vector<ElfModule>::iterator itor = moduleList.begin();
                itor != moduleList.end();
                itor ++)
    {
        const char* moduleName = "/system/lib/libart.so";
//        const char* moduleName = "/data/ElfHook";
        if (strncmp(itor->getModuleName(), moduleName, strlen(moduleName)) != 0) {
            continue;
        }
        log_info("Hook Module : %s\n", itor->getModuleName());
        this->hook(itor, "dlopen", (void*)nativehook_impl_dlopen, (void**)&old_dlopen);
        log_info("Old Func Addr:%p\n", old_dlopen);

    }
    return;
}

#include <dlfcn.h>

void ElfHooker::testDlOpen()
{
    void* h = dlopen("libart.so", RTLD_LAZY);
    void* f = dlsym(h,"_ZN3art9NanoSleepEy");
    log_info("_ZN3art9NanoSleepEy : %p\n", f);
    //dlclose(h);
}
