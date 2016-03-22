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
    inline ElfW(Addr) getBaseAddr()
    {
        return this->baseAddr;
    }
    inline ElfW(Addr) getBiasAddr()
    {
        return this->biasAddr;
    }

    ElfW(Addr) getElfExecLoadBias(const ElfW(Ehdr)* elf);

    uint32_t elfHash(const char *name);
    uint32_t gnuHash(const char *name);


    bool getElfBySegmentView(void);

    ElfW(Phdr)* findSegmentByType(const ElfW(Word) type);
    ElfW(Shdr)* findSectionByName(const char *sname);

    bool gnuLookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
    bool elfLookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
    bool findSymByName(const char *symbol, ElfW(Sym) **sym, int *symidx);

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

protected:

    ElfW(Addr)      baseAddr;
    ElfW(Addr)      biasAddr;
    std::string     moduleName;

protected:

    ElfW(Ehdr)  *ehdr;
    ElfW(Phdr)  *phdr;
    ElfW(Shdr)  *shdr;

    ElfW(Dyn)   *dyn;
    ElfW(Word)  dynsz;

    ElfW(Sym)    *sym;
    ElfW(Word)   symsz;


//    ElfW(Versym) *versym;

    ElfW(Rel)   *relplt;
    ElfW(Word)  relpltsz;
    ElfW(Rel)   *reldyn;
    ElfW(Word)  reldynsz;

protected:
    //for elf hash
    uint32_t    nbucket;
    uint32_t    nchain;
    uint32_t    *bucket;
    uint32_t    *chain;

    //for gnu hash
    uint32_t   gnu_nbucket;
    uint32_t   gnu_symndx;
    uint32_t   gnu_maskwords;
    uint32_t   gnu_shift2;
    uint32_t   *gnu_bucket;
    uint32_t   *gnu_chain;
    ElfW(Addr) *gnu_bloom_filter;

    bool is_gnu_hash;

protected:


    const char  *shstr;
    const char  *symstr;

    friend class ElfHooker;
};


#endif
