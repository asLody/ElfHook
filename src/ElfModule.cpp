

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "errno.h"
#include "ElfModule.h"
#include "ElfCommon.h"

#define DT_GNU_HASH      ((int)0x6ffffef5)
#define DT_ANDROID_REL   ((int)0x6000000f)
#define DT_ANDROID_RELSZ ((int)0x60000010)

//static const ElfW(Versym) kVersymNotNeeded = 0;
//static const ElfW(Versym) kVersymGlobal    = 1;

ElfModule::ElfModule(uint32_t baseAddr, const char* moduleName)
{
    this->baseAddr   = baseAddr;
    this->moduleName = moduleName;
    this->biasAddr   = 0;

    this->ehdr = NULL;
    this->phdr = NULL;
    this->shdr = NULL;

    this->dyn   = NULL;
    this->dynsz = 0;

    this->sym   = NULL;
    this->symsz = 0;

    this->relplt    = NULL;
    this->relpltsz  = 0;
    this->reldyn    = NULL;
    this->reldynsz  = 0;

    this->symstr    = NULL;
    this->shstr     = NULL;
    return;
}

ElfModule::~ElfModule()
{
    return;
}

ElfW(Addr) ElfModule::getElfExecLoadBias(const ElfW(Ehdr)* elf) {
  ElfW(Addr) offset = elf->e_phoff;
  const ElfW(Phdr)* phdr_table =
      reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
  const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

  for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++) {
    if (phdr->p_type == PT_LOAD) {
      return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
    }
  }
  return 0;
}

bool ElfModule::getElfBySegmentView(void)
{
	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);

    this->biasAddr = this->getElfExecLoadBias(this->ehdr);
    if (this->ehdr->e_type == ET_EXEC || this->ehdr->e_type == ET_DYN) {
        log_error("[+] Executable File or Shared Object, ElfHook Process..\n");
    } else {
        log_error("[-] (%d) Elf object, NOT Need Process..\n", this->ehdr->e_type);
        return false
        ;
    }

	this->shstr = NULL;

	ElfW(Phdr) *dynamic = NULL;
	ElfW(Word) size = 0;
	getElfSegmentInfo(PT_DYNAMIC, &dynamic, &size, &this->dyn);
	if(!dynamic){
		log_error("[-] could't find PT_DYNAMIC segment\n");
		return false;
	}

    this->is_gnu_hash = false;
	this->dynsz = size / sizeof(Elf32_Dyn);
	for(int i = 0; i < (int)this->dynsz; i += 1, dyn += 1)
    {
		switch(dyn->d_tag)
        {
		case DT_SYMTAB:
			this->sym = reinterpret_cast<ElfW(Sym) *>(this->biasAddr + dyn->d_un.d_ptr);
			break;
		case DT_STRTAB:
			this->symstr = reinterpret_cast<const char *>(this->biasAddr + dyn->d_un.d_ptr);
			break;
		case DT_REL:
        case DT_ANDROID_REL:
			this->reldyn = reinterpret_cast<ElfW(Rel) *>(this->biasAddr + dyn->d_un.d_ptr);
			break;
		case DT_RELSZ:
        case DT_ANDROID_RELSZ:
			this->reldynsz = dyn->d_un.d_val / sizeof(ElfW(Rel));
			break;
		case DT_JMPREL:
			this->relplt = reinterpret_cast<ElfW(Rel) *>(this->biasAddr + dyn->d_un.d_ptr);
			break;
		case DT_PLTRELSZ:
			this->relpltsz = dyn->d_un.d_val / sizeof(ElfW(Rel));
			break;
		case DT_HASH:
            {
        		uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->biasAddr + dyn->d_un.d_ptr);
        		this->nbucket = rawdata[0];
        		this->nchain  = rawdata[1];
        		this->bucket  = rawdata + 2;
        		this->chain   = this->bucket + this->nbucket;
        		this->symsz   = this->nchain;
                log_info("nbucket: %d, nchain: %d, bucket: %p, chain:%p\n", this->nbucket, this->nchain, this->bucket, this->chain);
        		break;
            }
        case DT_GNU_HASH:
            {
                uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->biasAddr + dyn->d_un.d_ptr);
                this->gnu_nbucket      = rawdata[0];
                this->gnu_symndx       = rawdata[1];
                this->gnu_maskwords    = rawdata[2];
                this->gnu_shift2       = rawdata[3];
                this->gnu_bloom_filter = rawdata + 4;
                this->gnu_bucket       = reinterpret_cast<uint32_t*>(this->gnu_bloom_filter + this->gnu_maskwords);
                this->gnu_chain        = this->gnu_bucket + this->gnu_nbucket - this->gnu_symndx;


                if (!powerof2(this->gnu_maskwords)) {
                    log_error("[-] invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                            this->gnu_maskwords, getModuleName());
                    return false;
                }
                this->gnu_maskwords -= 1;
                is_gnu_hash = true;

                log_info("bbucket(%d), symndx(%d), maskworks(%d), shift2(%d)\n",
                        this->gnu_nbucket,   this->gnu_symndx,
                        this->gnu_maskwords, this->gnu_shift2);
                break;
            }
		}
	}

    this->dumpSymbols();
    return true;
}



#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)
template<class T>
void ElfModule::getElfSectionInfo(const char *name, Elf32_Word *pSize, Elf32_Shdr **ppShdr, T *data)
{
	Elf32_Shdr *_shdr = findSectionByName(name);

	if(_shdr){
		SAFE_SET_VALUE(pSize, _shdr->sh_size / _shdr->sh_entsize);
		SAFE_SET_VALUE(data, reinterpret_cast<T>(this->biasAddr + _shdr->sh_offset));
	}else{
		log_error("[-] Could not found section %s\n", name);
		exit(-1);
	}

	SAFE_SET_VALUE(ppShdr, _shdr);
}


template<class T>
void ElfModule::getElfSegmentInfo(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data)
{

	ElfW(Phdr)* _phdr = findSegmentByType(type);
    ElfW(Addr) _biasAddr = this->biasAddr;
	if(_phdr){
		SAFE_SET_VALUE(data, reinterpret_cast<T>(_biasAddr + _phdr->p_vaddr));
		SAFE_SET_VALUE(pSize, _phdr->p_memsz);
	}else{
		log_error("[-] Could not found segment type is %d\n", type);
		exit(-1);
	}
	SAFE_SET_VALUE(ppPhdr, _phdr);
}

ElfW(Shdr)* ElfModule::findSectionByName(const char *sname)
{
	ElfW(Shdr) *target = NULL;
	ElfW(Shdr) *shdr = this->shdr;
	for(int i = 0; i < this->ehdr->e_shnum; i += 1)
    {
		const char *name = (const char *)(shdr[i].sh_name + this->shstr);
		if(!strncmp(name, sname, strlen(sname)))
        {
			target = (ElfW(Shdr)*)(shdr + i);
			break;
		}
	}
	return target;
}

ElfW(Phdr) *ElfModule::findSegmentByType(const ElfW(Word) type)
{
	ElfW(Phdr) *target = NULL;
	ElfW(Phdr) *phdr = this->phdr;

	for(int i = 0; i < this->ehdr->e_phnum; i += 1)
    {
		if(phdr[i].p_type == type)
        {
			target = phdr + i;
			break;
		}
	}
	return target;
}



uint32_t ElfModule::elfHash(const char *name) {
	const unsigned char *tmp = (const unsigned char *) name;
	unsigned h = 0, g;

	while (*tmp) {
		h = (h << 4) + *tmp++;
		g = h & 0xf0000000;
		h ^= g;
		h ^= g >> 24;
	}
	return h;
}

uint32_t ElfModule::gnuHash (const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h;
}

bool ElfModule::elfLookup(char const* symbol, ElfW(Sym) **sym, int *symidx) {
    ElfW(Sym) *target = NULL;

    uint32_t hash = elfHash(symbol);
    uint32_t index = this->bucket[hash % this->nbucket];

    if (!strcmp(this->symstr + this->sym[index].st_name, symbol)) {
        target = this->sym + index;
    }
    if (!target) {
        do {
            index = this->chain[index];
            if (!strcmp(this->symstr + this->sym[index].st_name, symbol)) {
                target = this->sym + index;
                break;
            }
        } while (index != 0);
    }
    if(target){
        SAFE_SET_VALUE(sym, target);
        SAFE_SET_VALUE(symidx, index);
        return true;
    }
    return false
    ;
}

bool ElfModule::gnuLookup(char const* symbol, ElfW(Sym) **sym, int *symidx)
{
    uint32_t hash = this->gnuHash(symbol);
    uint32_t h2 = hash >> this->gnu_shift2;

    uint32_t bloom_mask_bits = sizeof(ElfW(Addr))*8;
    uint32_t word_num = (hash / bloom_mask_bits) & this->gnu_maskwords;
    ElfW(Addr) bloom_word = this->gnu_bloom_filter[word_num];

    *sym = NULL;
    *symidx = 0;

    log_info("[+] Search %s in %s@%p (gnu)\n",
                symbol,
                this->getModuleName(),
                reinterpret_cast<void*>(this->baseAddr));

    log_info("word_num(%d), bloom_word(%x), hash(%08x), h2(%x), bloom_mask_bits(%x)\n", word_num, bloom_word, hash, h2, bloom_mask_bits);
    log_info("%x; %x, %x, %x\n",  (hash % bloom_mask_bits) ,
                        (bloom_word >> (hash % bloom_mask_bits)),
                        (h2 % bloom_mask_bits),
                        (bloom_word >> (h2 % bloom_mask_bits)));
    // test against bloom filter
    if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
        log_warn("[-] NOT Found %s in %s@%p 1\n",
                    symbol,
                    this->getModuleName(),
                    reinterpret_cast<void*>(this->baseAddr));

        return false;
    }

    // bloom test says "probably yes"...
    uint32_t n = this->gnu_bucket[hash % this->gnu_nbucket];

    if (n == 0) {
        log_warn("[-] NOT Found %s in %s@%p 2\n",
            symbol,
            this->getModuleName(),
            reinterpret_cast<void*>(this->baseAddr));

        return false;
    }

    do {
        ElfW(Sym)* s = this->sym + n;
        if (((this->gnu_chain[n] ^ hash) >> 1) == 0 &&
                    strcmp((this->symstr + s->st_name), symbol) == 0) {
            log_info("[+] Found %s in %s (%p) %zd\n",
                            symbol,
                            this->getModuleName(),
                            reinterpret_cast<void*>(s->st_value),
                            static_cast<size_t>(s->st_size));
            *symidx = n;
            *sym = s;
            return true;
        }
        log_dbg("test : %s\n", (this->symstr + s->st_name));
    } while ((this->gnu_chain[n++] & 1) == 0);

    log_warn("[-] NOT Found %s in %s@%p 3\n",
              symbol,
              this->getModuleName(),
              reinterpret_cast<void*>(this->baseAddr));

    return false;
}

bool ElfModule::findSymByName(const char *symbol, ElfW(Sym) **sym, int *symidx) {
    if (this->is_gnu_hash) {
        bool result = gnuLookup(symbol, sym, symidx);
        if (!result) {
            for(int i = 0; i < (int)this->gnu_symndx; i++) {
                char const* symName = reinterpret_cast<char const *>(this->sym[i].st_name + this->symstr);
                if (strcmp(symName, symbol) == 0) {
                    // found symbol
                    *symidx = i;
                    *sym = this->sym + i;
                    result = true;
                    log_info("[+] Found %s in %s (%p) %zd\n",
                                    symbol,
                                    this->getModuleName(),
                                    reinterpret_cast<void*>((*sym)->st_value),
                                    static_cast<size_t>((*sym)->st_size));
                }
            }
        }
        return result;
    }
    return elfLookup(symbol, sym, symidx);
}

void ElfModule::dumpSections(void){
	Elf32_Half shnum = this->ehdr->e_shnum;
	Elf32_Shdr *shdr = this->shdr;

	log_info("Sections: :%d\n",shnum);
	for(int i = 0; i < shnum; i += 1, shdr += 1) {
		const char *name = shdr->sh_name == 0 || !this->shstr ? "UNKOWN" :  (const char *)(shdr->sh_name + this->shstr);
		log_info("[%.2d] %-20s 0x%.8x\n", i, name, shdr->sh_addr);
	}

    log_info("Sections: end\n");
}

void ElfModule::dumpSections2() {
    ElfW(Half) shnum = this->ehdr->e_shnum;
    ElfW(Shdr) *shdr = this->shdr;

    log_info("Sections: :%d\n",shnum);
    for(int i = 0; i < shnum; i += 1, shdr += 1) {
        log_info("Name(%08X);Type(%08X);Addr(%08X);offset(%08X);entSize(%08X)\n",
            shdr->sh_name, shdr->sh_type, shdr->sh_addr, shdr->sh_offset, shdr->sh_entsize);
    }
    log_info("Sections: end\n");
}

void ElfModule::dumpSegments(void)
{
	ElfW(Phdr) *phdr = this->phdr;
	ElfW(Half) phnum = this->ehdr->e_phnum;

	log_info("Segments: \n");
	for(int i = 0; i < phnum; i++){
        log_info("[%.2d] %-.8x 0x%-.8x 0x%-.8x %-8d %-8d\n", i,
		 		phdr[i].p_type, phdr[i].p_vaddr,
		 		phdr[i].p_paddr, phdr[i].p_filesz,
		 		phdr[i].p_memsz);
	}
}
const static struct dynNameMapItem{
    const char* dyn_name;
    int dyn_tag;
}sDynNameMaps[28] = {
    {"DT_NULL",    0},
    {"DT_NEEDED",  1},
    {"DT_PLTRELSZ",2},
    {"DT_PLTGOT",  3},
    {"DT_HASH",    4},
    {"DT_STRTAB",  5},
    {"DT_SYMTAB",  6},
    {"DT_RELA",    7},
    {"DT_RELASZ",  8},
    {"DT_RELAENT", 9},
    {"DT_STRSZ",   10},
    {"DT_SYMENT",  11},
    {"DT_INIT",    12},
    {"DT_FINI",    13},
    {"DT_SONAME",  14},
    {"DT_RPATH",   15},
    {"DT_SYMBOLIC",16},
    {"DT_REL",     17},
    {"DT_RELSZ",   18},
    {"DT_RELENT",  19},
    {"DT_PLTREL",  20},
    {"DT_DEBUG",   21},
    {"DT_TEXTREL", 22},
    {"DT_JMPREL",  23},
    {"DT_LOPROC",  0x70000000},
    {"DT_HIPROC",  0x7fffffff},
    {"DT_GNU_HASH", DT_GNU_HASH},
    {NULL, 0}
};

const char* ElfModule::convertDynTagToName(int d_tag)
{
    for(int i = 0; sDynNameMaps[i].dyn_name != NULL; i++) {
        if (sDynNameMaps[i].dyn_tag == d_tag) {
            return sDynNameMaps[i].dyn_name;
        }
    }
    return "UNKNOW";
}

void ElfModule::dumpDynamics(void)
{
	ElfW(Dyn) *dyn = this->dyn;

	log_info(".dynamic section info:\n");
	const char *type = NULL;

	for(int i = 0; i < (int)this->dynsz; i++)
    {
        type = convertDynTagToName(dyn[i].d_tag);
        log_info("[%.2d] %-14s 0x%-.8x 0x%-.8x\n", i, type,  dyn[i].d_tag, dyn[i].d_un.d_val);
		if(dyn[i].d_tag == DT_NULL){
			break;
		}
	}
    return;
}

void ElfModule::dumpSymbols(void)
{
	ElfW(Sym) *sym = this->sym;

	log_info("dynsym section info: \n");
    if (this->is_gnu_hash) {

    } else {
        for(int i=0; i< (int)this->symsz; i++)
        {
    		log_info("[%2d] %-20s\n", i, sym[i].st_name + this->symstr);
    	}
    }

    return;
}


void ElfModule::dumpRelInfo(void){
	ElfW(Rel)* rels[] = {this->reldyn, this->relplt};
	ElfW(Word) resszs[] = {this->reldynsz, this->relpltsz};

	ElfW(Sym) *sym = this->sym;

	log_info("rel section info:\n");
	for(int i = 0; i < (int)(sizeof(rels)/sizeof(rels[0])); i++)
    {
		ElfW(Rel) *rel = rels[i];
		ElfW(Word) relsz = resszs[i];

		for(int j = 0; j < (int)
        relsz; j += 1)
        {
            const char *name = sym[ELF32_R_SYM(rel[j].r_info)].st_name + this->symstr;
            log_info("[%.2d-%.4d] 0x%-.8x 0x%-.8x %-10s\n", i, j, rel[j].r_offset, rel[j].r_info, name);
		}
	}
    return;
}


/*

void ElfModule::getElfBySectionView(void)
{
	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);

    if (this->ehdr->e_type == ET_EXEC || this->ehdr->e_type == ET_DYN) {
        log_error("[+] Executable File or Shared Object, ElfHook Process..\n");
    } else {
        log_error("[-] (%d) Elf object, NOT Need Process..\n", this->ehdr->e_type);
        return;
    }

	Elf32_Shdr *shstr = (Elf32_Shdr *)(this->shdr + this->ehdr->e_shstrndx);
	this->shstr = reinterpret_cast<char *>(0 + shstr->sh_offset);

	getElfSectionInfo(".dynstr",  NULL,            NULL,      &this->symstr);
	getElfSectionInfo(".dynamic", &this->dynsz,    NULL,      &this->dyn);
	getElfSectionInfo(".dynsym",  &this->symsz,    NULL,      &this->sym);
	getElfSectionInfo(".rel.dyn", &this->reldynsz, NULL,      &this->reldyn);
	getElfSectionInfo(".rel.plt", &this->relpltsz, NULL,      &this->relplt);

	Elf32_Shdr *hash = findSectionByName(".hash");
	if(hash){
		uint32_t *rawdata = reinterpret_cast<uint32_t *>(_baseAddr + hash->sh_offset);
		this->nbucket = rawdata[0];
		this->nchain  = rawdata[1];
		this->bucket  = rawdata + 2;
		this->chain = this->bucket + this->nbucket;
	}
}
*/
