#if !defined(__ELFHOOK_H__)
#define __ELFHOOK_H__

#include <elf.h>
#include <string>

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

    unsigned elfHash(const char *name);
    void getElfBySectionView(void);
    bool getElfBySegmentView(void);
    Elf32_Phdr* findSegmentByType(const Elf32_Word type);
    Elf32_Shdr* findSectionByName(const char *sname);
    void findSymByName(const char *symbol, Elf32_Sym **sym, int *symidx);
    template<class T>
    void getElfSegmentInfo(const Elf32_Word type, Elf32_Phdr **ppPhdr, Elf32_Word *pSize, T *data);
    template<class T>
    void getElfSectionInfo(const char *name, Elf32_Word *pSize, Elf32_Shdr **ppShdr, T *data);
    void dumpSections();
    void dumpSegments();
    void dumpDynamics();
    void dumpSymbols();
    void dumpRelInfo();

protected:
    bool        isExec;
    uint32_t    baseAddr;
    int         spaceSize;
    bool        fromFile;
    std::string moduleName;

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
