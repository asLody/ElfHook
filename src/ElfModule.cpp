
#include "ElfModule.h"
#include "ElfCommon.h"



ElfModule::ElfModule(uint32_t baseAddr, const char* moduleName)
{
    this->baseAddr   = baseAddr;
    this->moduleName = moduleName;
    this->spaceSize  = 1;
    this->fromFile   = false;
}

ElfModule::~ElfModule()
{


}
void ElfModule::getElfBySectionView(void)
{
    uint32_t _baseAddr = (uint32_t)NULL;
    if (!this->isExec) {
        _baseAddr = this->baseAddr;
    }
	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);

	Elf32_Shdr *shstr = (Elf32_Shdr *)(this->shdr + this->ehdr->e_shstrndx);
	this->shstr = reinterpret_cast<char *>(_baseAddr + shstr->sh_offset);

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


bool ElfModule::getElfBySegmentView(void)
{

	this->ehdr = reinterpret_cast<Elf32_Ehdr *>(this->baseAddr);

	// may be wrong
	this->shdr = reinterpret_cast<Elf32_Shdr *>(this->baseAddr + this->ehdr->e_shoff);
	this->phdr = reinterpret_cast<Elf32_Phdr *>(this->baseAddr + this->ehdr->e_phoff);

    uint32_t _baseAddr = (uint32_t)NULL;
    if (this->ehdr->e_type == ET_EXEC) {
        this->isExec = true;
        log_error("[+] Executable File, ElfHook Process..\n");
    } else if (this->ehdr->e_type == ET_DYN) {
        this->isExec = false;
        _baseAddr = this->baseAddr;
        log_error("[+] Shared Object, ElfHook Process..\n");
    } else {
        log_error("[-] (%d) Elf object, NOT Need Process..\n", this->ehdr->e_type);
        return false;
    }

	this->shstr = NULL;

	Elf32_Phdr *dynamic = NULL;
	Elf32_Word size = 0;

	getElfSegmentInfo(PT_DYNAMIC, &dynamic, &size, &this->dyn);
	if(!dynamic){
		log_error("[-] could't find PT_DYNAMIC segment\n");
		return false;
	}

	this->dynsz = size / sizeof(Elf32_Dyn);
	Elf32_Dyn *dyn = this->dyn;
	for(int i = 0; i < (int)this->dynsz; i += 1, dyn += 1)
    {
		switch(dyn->d_tag)
        {
		case DT_SYMTAB:
			this->sym = reinterpret_cast<Elf32_Sym *>(_baseAddr + dyn->d_un.d_ptr);
			break;

		case DT_STRTAB:
			this->symstr = reinterpret_cast<const char *>(_baseAddr + dyn->d_un.d_ptr);
			break;

		case DT_REL:
			this->reldyn = reinterpret_cast<Elf32_Rel *>(_baseAddr + dyn->d_un.d_ptr);
			break;

		case DT_RELSZ:
			this->reldynsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_JMPREL:
			this->relplt = reinterpret_cast<Elf32_Rel *>(_baseAddr + dyn->d_un.d_ptr);
			break;

		case DT_PLTRELSZ:
			this->relpltsz = dyn->d_un.d_val / sizeof(Elf32_Rel);
			break;

		case DT_HASH:
//        log_info("DT_HASH->:%p\n", dyn->d_un.d_ptr);
			uint32_t *rawdata = reinterpret_cast<uint32_t *>(_baseAddr + dyn->d_un.d_ptr);
			this->nbucket = rawdata[0];
			this->nchain = rawdata[1];
			this->bucket = rawdata + 2;
			this->chain = this->bucket + this->nbucket;
			this->symsz = this->nchain;
			break;
		}
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
void ElfModule::getElfSegmentInfo(const Elf32_Word type, Elf32_Phdr **ppPhdr, Elf32_Word *pSize, T *data)
{

	Elf32_Phdr *_phdr = findSegmentByType(type);

    uint32_t _baseAddr = (uint32_t)NULL;
    if (!this->isExec) {
        _baseAddr = this->baseAddr;
    }
	if(_phdr){

		if(this->fromFile){ //文件读取
			SAFE_SET_VALUE(data, reinterpret_cast<T>(_baseAddr + _phdr->p_offset));
			SAFE_SET_VALUE(pSize, _phdr->p_filesz);
		}else{ //从内存读取
			SAFE_SET_VALUE(data, reinterpret_cast<T>(_baseAddr + _phdr->p_vaddr));
			SAFE_SET_VALUE(pSize, _phdr->p_memsz);
		}

	}else{
		log_error("[-] Could not found segment type is %d\n", type);
		exit(-1);
	}
	SAFE_SET_VALUE(ppPhdr, _phdr);
}

Elf32_Shdr *ElfModule::findSectionByName(const char *sname)
{
	Elf32_Shdr *target = NULL;
	Elf32_Shdr *shdr = this->shdr;
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


void ElfModule::findSymByName(const char *symbol, Elf32_Sym **sym, int *symidx) {
	Elf32_Sym *target = NULL;

	unsigned hash = elfHash(symbol);
    // log_info("hash:%u, symbol:%s\n", hash, symbol);
    // log_info("nbucket:%d, %d\n", this->nbucket, hash % this->nbucket);
    //  log_info("this->bucket: %p\n", this->bucket);
	uint32_t index = this->bucket[hash % this->nbucket];
//log_info("symstr: %p, %p, index:%d\n", this->symstr, this->sym, index);

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

void ElfModule::dumpSections(void){
	Elf32_Half shnum = this->ehdr->e_shnum;
	Elf32_Shdr *shdr = this->shdr;

	log_info("Sections: \n");
	for(int i = 0; i < shnum; i += 1, shdr += 1){
		const char *name = shdr->sh_name == 0 || !this->shstr ? "UNKOWN" :  (const char *)(shdr->sh_name + this->shstr);
		log_info("[%.2d] %-20s 0x%.8x\n", i, name, shdr->sh_addr);
	}
}

void ElfModule::dumpSegments(void)
{
	Elf32_Phdr *phdr = this->phdr;
	Elf32_Half phnum = this->ehdr->e_phnum;

	log_info("Segments: \n");
	for(int i=0; i<phnum; i++){
        log_info("[%.2d] %-20d 0x%-.8x 0x%-.8x %-8d %-8d\n", i,
		 		phdr[i].p_type, phdr[i].p_vaddr,
		 		phdr[i].p_paddr, phdr[i].p_filesz,
		 		phdr[i].p_memsz);
	}
}

void ElfModule::dumpDynamics(void)
{
	Elf32_Dyn *dyn = this->dyn;

	log_info(".dynamic section info:\n");
	const char *type = NULL;

	for(int i = 0; i < (int)this->dynsz; i++)
    {
		switch(dyn[i].d_tag)
        {
		case DT_INIT:
			type = "DT_INIT";
			break;
		case DT_FINI:
			type = "DT_FINI";
			break;
		case DT_NEEDED:
			type = "DT_NEEDED";
			break;
		case DT_SYMTAB:
			type = "DT_SYMTAB";
			break;
		case DT_SYMENT:
			type = "DT_SYMENT";
			break;
		case DT_NULL:
			type = "DT_NULL";
			break;
		case DT_STRTAB:
			type= "DT_STRTAB";
			break;
		case DT_REL:
			type = "DT_REL";
			break;
		case DT_SONAME:
			type = "DT_SONAME";
			break;
		case DT_HASH:
			type = "DT_HASH";
			break;
		default:
			type = NULL;
			break;
		}

		// we only printf that we need.
		if(type)
        {
            log_info("[%.2d] %-10s 0x%-.8x 0x%-.8x\n", i, type,  dyn[i].d_tag, dyn[i].d_un.d_val);
		}

		if(dyn[i].d_tag == DT_NULL){
			break;
		}
	}
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
