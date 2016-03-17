

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "errno.h"
#include "ElfModule.h"
#include "ElfCommon.h"

#define DT_GNU_HASH (0x6ffffef5)

ElfModule::ElfModule(uint32_t baseAddr, const char* moduleName)
{
    this->baseAddr   = baseAddr;
    this->moduleName = moduleName;
    this->spaceSize  = 0;
    this->fromFile   = false;
    this->fileBase   = NULL;

    sym = NULL;
    symstr = NULL;

}

ElfModule::~ElfModule()
{
    if (this->fileBase != NULL && this->spaceSize > 0) {
        munmap(this->fileBase, this->spaceSize);
    }
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

void ElfModule::getElfBySectionView(void)
{
    uint32_t _baseAddr = (uint32_t)NULL;

	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);
    if (this->ehdr->e_type == ET_EXEC) {
        this->isExec = true;
        log_error("[+] Executable File, ElfHook Process..\n");
    } else if (this->ehdr->e_type == ET_DYN) {
        this->isExec = false;
        _baseAddr = this->baseAddr;
        log_error("[+] Shared Object, ElfHook Process..\n");
    } else {
        log_error("[-] (%d) Elf object, NOT Need Process..\n", this->ehdr->e_type);
        return ;//false;
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

unsigned ElfModule::elfHash(const char *name) {
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

uint32_t dl_new_hash (const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
        h = h * 33 + c;
    return h;
}

bool ElfModule::getElfBySegmentView(void)
{
	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);

    this->biasAddr = this->getElfExecLoadBias(this->ehdr);
    if (this->ehdr->e_type == ET_EXEC) {
        this->isExec = true;
        log_error("[+] Executable File, ElfHook Process..\n");
    } else if (this->ehdr->e_type == ET_DYN) {
        this->isExec = false;
        log_error("[+] Shared Object, ElfHook Process..\n");
    } else {
        log_error("[-] (%d) Elf object, NOT Need Process..\n", this->ehdr->e_type);
        return false;
    }

	this->shstr = NULL;

	ElfW(Phdr) *dynamic = NULL;
	ElfW(Word) size = 0;
	getElfSegmentInfo(PT_DYNAMIC, &dynamic, &size, &this->dyn);
	if(!dynamic){
		log_error("[-] could't find PT_DYNAMIC segment\n");
		return false;
	}
log_info("base:%p, dyn:%p\n",this->baseAddr, this->dyn);

	this->dynsz = size / sizeof(Elf32_Dyn);
this->dumpDynamics();

	for(int i = 0; i < (int)this->dynsz; i += 1, dyn += 1)
    {
//        log_info("d_tag: %08x\n", dyn->d_tag);
		switch(dyn->d_tag)
        {
		case DT_SYMTAB:
			this->sym = reinterpret_cast<Elf32_Sym *>(this->biasAddr + dyn->d_un.d_ptr);
			break;

		case DT_STRTAB:
			this->symstr = reinterpret_cast<const char *>(this->biasAddr + dyn->d_un.d_ptr);
			break;

		case DT_REL:
			this->reldyn = reinterpret_cast<Elf32_Rel *>(this->biasAddr + dyn->d_un.d_ptr);
			break;

		case DT_RELSZ:
			this->reldynsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_JMPREL:
			this->relplt = reinterpret_cast<Elf32_Rel *>(this->biasAddr + dyn->d_un.d_ptr);
			break;

		case DT_PLTRELSZ:
			this->relpltsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;
		case DT_HASH:
        {
			uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->biasAddr + dyn->d_un.d_ptr);
			this->nbucket = rawdata[0];
			this->nchain  = rawdata[1];
			this->bucket  = rawdata + 2;
			this->chain = this->bucket + this->nbucket;
			this->symsz = this->nchain;
            log_info("nbucket: %d, nchain: %d, bucket: %p, chain:%p\n", this->nbucket, this->nchain, this->bucket, this->chain);

			break;
        }
        case (int)DT_GNU_HASH:
        {
            uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->biasAddr + dyn->d_un.d_ptr);
            log_info("base:%p, ptr:%p, rawdata:%p\n", this->biasAddr, dyn->d_un.d_ptr, rawdata);
            log_info("%08x, %08x, %08x, %08x\n", rawdata[0], rawdata[1], rawdata[2], rawdata[3]);
            break;
        }
		}
	}
    if (this->sym != NULL && this->symstr != NULL) {
        log_info("sym:%p, symstr:%p\n", this->sym, this->symstr);
        log_info("%s\n%s\n%s\n",
                            sym[0].st_name + this->symstr,
                            sym[1].st_name + this->symstr,
                            sym[10].st_name + this->symstr);
    }
    return true;
}

#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)


template<class T>
void ElfModule::getElfSectionInfo(const char *name, Elf32_Word *pSize, Elf32_Shdr **ppShdr, T *data)
{
	Elf32_Shdr *_shdr = findSectionByName(name);
    uint32_t _baseAddr = (uint32_t)NULL;
    if (!this->isExec) {
        _baseAddr = this->baseAddr;
    }

	if(_shdr){
		SAFE_SET_VALUE(pSize, _shdr->sh_size / _shdr->sh_entsize);
		SAFE_SET_VALUE(data, reinterpret_cast<T>(_baseAddr + _shdr->sh_offset));
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
			target = (Elf32_Shdr *)(shdr + i);
			break;
		}
	}
	return target;
}

Elf32_Phdr *ElfModule::findSegmentByType(const Elf32_Word type)
{
	Elf32_Phdr *target = NULL;
	Elf32_Phdr *phdr = this->phdr;

	for(int i = 0; i < this->ehdr->e_phnum; i += 1)
    {
		if(phdr[i].p_type == type)
        {
			target = phdr + i;
			break;
		}
	}
//log_info("phdr: %p, type:%d, target:%p \n", phdr, type, target);
	return target;
}


void ElfModule::findSymByName(const char *symbol, ElfW(Sym) **sym, int *symidx) {
	ElfW(Sym) *target = NULL;

	unsigned hash = elfHash(symbol);
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
	}
    return;
}

bool ElfModule::loadModuleFile() {
    if (this->fileBase == NULL) {
    	int fd = open(this->getModuleName(), O_RDONLY);
    	if (fd < 0) {
    		log_error("[-] open (%s) fails. error: %s\n",
                        this->getModuleName(),
                        strerror(errno));
    		return false;
    	}

    	struct stat fs;
    	fstat(fd, &fs);

    	this->fileBase = mmap(NULL, fs.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    	if (this->fileBase == MAP_FAILED) {
    		log_error("[-] mmap fails.\n");
            close(fd);
    		return false;
    	}
    	close(fd);
    	this->spaceSize = fs.st_size;
    }
    return true;
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
    Elf32_Half shnum = this->ehdr->e_shnum;
    Elf32_Shdr *shdr = this->shdr;

    log_info("Sections: :%d\n",shnum);
    for(int i = 0; i < shnum; i += 1, shdr += 1) {
        log_info("Name(%08X);Type(%08X);Addr(%08X);offset(%08X);entSize(%08X)\n",
            shdr->sh_name, shdr->sh_type, shdr->sh_addr, shdr->sh_offset, shdr->sh_entsize);
    }
    log_info("Sections: end\n");
}

void ElfModule::dumpSegments(void)
{
	Elf32_Phdr *phdr = this->phdr;
	Elf32_Half phnum = this->ehdr->e_phnum;

	log_info("Segments: \n");
	for(int i=0; i<phnum; i++){
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
    return "Unknow";
}

void ElfModule::dumpDynamics(void)
{
	Elf32_Dyn *dyn = this->dyn;

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
	Elf32_Sym *sym = this->sym;

	log_info("dynsym section info:\n");
	for(int i=0; i< (int)this->symsz; i++)
    {
		log_info("[%2d] %-20s\n", i, sym[i].st_name + this->symstr);
	}
}


void ElfModule::dumpRelInfo(void){
	Elf32_Rel* rels[] = {this->reldyn, this->relplt};
	Elf32_Word resszs[] = {this->reldynsz, this->relpltsz};

	Elf32_Sym *sym = this->sym;

	log_info("rel section info:\n");
	for(int i = 0; i < (int)(sizeof(rels)/sizeof(rels[0])); i++)
    {
		Elf32_Rel *rel = rels[i];
		Elf32_Word relsz = resszs[i];

		for(int j = 0; j < (int)
        relsz; j += 1)
        {
            const char *name = sym[ELF32_R_SYM(rel[j].r_info)].st_name + this->symstr;
            log_info("[%.2d-%.4d] 0x%-.8x 0x%-.8x %-10s\n", i, j, rel[j].r_offset, rel[j].r_info, name);
		}
	}
}
