#if !defined(__ELFHOOK_H__)
#define __ELFHOOK_H__

#include <elf.h>
#include <string>
#include "ElfCommon.h"

class ElfModule {

public:
    ElfModule(uint32_t baseAddr, const char* moduleName);
    ~ElfModule();

    inline const char* getModuleName()
    {
         return this->moduleName.c_str();
    }
    inline uint32_t getBaseAddr()
    {
        return this->baseAddr;
    }
    inline int getSpaceSize()
    {
        return this->spaceSize;
    }
    inline void setSpaceSize(int spaceSize)
    {
        this->spaceSize = spaceSize;
    }

    ElfW(Addr) getElfExecLoadBias(const ElfW(Ehdr)* elf);

    unsigned elfHash(const char *name);
    void getElfBySectionView(void);
    bool getElfBySegmentView(void);
    ElfW(Phdr)* findSegmentByType(const ElfW(Word) type);
    ElfW(Shdr)* findSectionByName(const char *sname);
    void findSymByName(const char *symbol, ElfW(Sym) **sym, int *symidx);
    template<class T>
    void getElfSegmentInfo(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data);
    template<class T>
    void getElfSectionInfo(const char *name, Elf32_Word *pSize, Elf32_Shdr **ppShdr, T *data);
    void dumpSections();
    void dumpSections2();
    void dumpSegments();
    void dumpDynamics();
    void dumpSymbols();
    void dumpRelInfo();

    const char* convertDynTagToName(int d_tag);
    bool loadModuleFile(void);

protected:
    bool        isExec;
    uint32_t    baseAddr;
    uint32_t    biasAddr;
    int         spaceSize;
    bool        fromFile;
    std::string moduleName;
    void*       fileBase;
protected:

    Elf32_Ehdr  *ehdr;
    Elf32_Phdr  *phdr;
    Elf32_Shdr  *shdr;

    Elf32_Dyn   *dyn;
    Elf32_Word  dynsz;

    Elf32_Sym   *sym;
    Elf32_Word  symsz;

    Elf32_Rel   *relplt;
    Elf32_Word  relpltsz;
    Elf32_Rel   *reldyn;
    Elf32_Word  reldynsz;

    uint32_t    nbucket;
    uint32_t    nchain;

    uint32_t    *bucket;
    uint32_t    *chain;

    const char  *shstr;
    const char  *symstr;

    friend class ElfHooker;
};


#endif
