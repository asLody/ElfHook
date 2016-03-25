

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>

#include <assert.h>

#include "elf_common.h"
#include "elf_module.h"

#define DT_GNU_HASH      ((int)0x6ffffef5)
#define DT_ANDROID_REL   ((int)0x6000000f)
#define DT_ANDROID_RELSZ ((int)0x60000010)

#define R_ARM_ABS32      (0x02)
#define R_ARM_GLOB_DAT   (0x15)
#define R_ARM_JUMP_SLOT  (0x16)


#define PAGE_START(addr) (~(getpagesize() - 1) & (addr))
#define PAGE_END(addr)   PAGE_START((addr) + (PAGE_SIZE-1))

#define SAFE_SET_VALUE(t, v) if(t) *(t) = (v)

#define MAYBE_MAP_FLAG(x, from, to)  (((x) & (from)) ? (to) : 0)
#define PFLAGS_TO_PROT(x)            (MAYBE_MAP_FLAG((x), PF_X, PROT_EXEC) | \
                                      MAYBE_MAP_FLAG((x), PF_R, PROT_READ) | \
                                      MAYBE_MAP_FLAG((x), PF_W, PROT_WRITE))

elf_module::elf_module(ElfW(Addr) base_addr, const char* module_name)
{
    this->m_base_addr   = base_addr;
    this->m_module_name = module_name;
    this->m_bias_addr   = 0;
    this->m_is_loaded   = false;

    this->m_ehdr          = NULL;
    this->m_phdr          = NULL;
    this->m_shdr          = NULL;

    this->m_dyn_ptr       = NULL;
    this->m_dyn_size      = 0;

    this->m_sym_ptr       = NULL;
    this->m_sym_size      = 0;

    this->m_relplt_ptr    = NULL;
    this->m_relplt_size   = 0;
    this->m_reldyn_ptr    = NULL;
    this->m_reldyn_size   = 0;

    this->m_symstr_ptr    = NULL;
    this->m_shstr_ptr     = NULL;

    return;
}

elf_module::~elf_module()
{
    this->m_is_loaded   = false;
    return;
}

bool elf_module::is_elf_module(void* base_addr)
{
    ElfW(Ehdr) *ehdr = reinterpret_cast<ElfW(Ehdr) *>(base_addr);

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
        return false;
    }
    int elf_class = ehdr->e_ident[EI_CLASS];
#if defined(__LP64__)
    if (elf_class != ELFCLASS64) {
        return false;
    }
#else
    if (elf_class != ELFCLASS32) {
        return false;
    }
#endif
    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        return false;
    }
    if (ehdr->e_version != EV_CURRENT) {
        return false;
    }
    if (ehdr->e_machine != GetTargetElfMachine()) {
        return false;
    }
    return true;
}

ElfW(Addr) elf_module::caculate_bias_addr(const ElfW(Ehdr)* elf)
{
    ElfW(Addr) offset = elf->e_phoff;
    const ElfW(Phdr)* phdr_table = reinterpret_cast<const ElfW(Phdr)*>(reinterpret_cast<uintptr_t>(elf) + offset);
    const ElfW(Phdr)* phdr_end = phdr_table + elf->e_phnum;

    for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            return reinterpret_cast<ElfW(Addr)>(elf) + phdr->p_offset - phdr->p_vaddr;
        }
    }
    return 0;
}

bool elf_module::get_segment_view(void)
{
    this->m_ehdr = reinterpret_cast<Elf32_Ehdr *>(this->get_base_addr());
    this->m_shdr = reinterpret_cast<Elf32_Shdr *>(this->get_base_addr() + this->m_ehdr->e_shoff);
    this->m_phdr = reinterpret_cast<Elf32_Phdr *>(this->get_base_addr() + this->m_ehdr->e_phoff);

//    log_dbg("ehdr:%p, phdr:%p, shdr:%p\n", this->m_ehdr, this->m_phdr, this->m_shdr);
//    this->dump_elf_header();

    if (!this->m_bias_addr)
    {
        this->m_bias_addr = this->caculate_bias_addr(this->m_ehdr);
    }

    if (this->m_ehdr->e_type == ET_EXEC || this->m_ehdr->e_type == ET_DYN)
    {
        log_error("[+] Executable File or Shared Object, ElfHook Process..\n");
    }
    else
    {
        log_error("[-] (%08x) Elf object, NOT Need Process..\n", this->m_ehdr->e_type);
        return false;
    }

    this->m_shstr_ptr = NULL;

    ElfW(Phdr) *dynamic = NULL;
    ElfW(Word) size = 0;
    this->get_segment_info(PT_DYNAMIC, &dynamic, &size, &this->m_dyn_ptr);
    if(!dynamic)
    {
        log_error("[-] could't find PT_DYNAMIC segment\n");
        return false;
    }

    ElfW(Dyn) *dyn = this->m_dyn_ptr;
    this->set_is_gnu_has(false);
    this->m_dyn_size = size / sizeof(Elf32_Dyn);
    for(int i = 0; i < (int)this->m_dyn_size; i += 1, dyn += 1)
    {
        switch(dyn->d_tag)
        {
        case DT_SYMTAB:
            this->m_sym_ptr = reinterpret_cast<ElfW(Sym) *>(this->get_bias_addr() + dyn->d_un.d_ptr);
            break;
        case DT_STRTAB:
            this->m_symstr_ptr = reinterpret_cast<const char *>(this->get_bias_addr() + dyn->d_un.d_ptr);
            break;
        case DT_REL:
        case DT_ANDROID_REL:
            this->m_reldyn_ptr = reinterpret_cast<ElfW(Rel) *>(this->get_bias_addr() + dyn->d_un.d_ptr);
            break;
        case DT_RELSZ:
        case DT_ANDROID_RELSZ:
            this->m_reldyn_size = dyn->d_un.d_val / sizeof(ElfW(Rel));
            break;
        case DT_JMPREL:
            this->m_relplt_ptr = reinterpret_cast<ElfW(Rel) *>(this->get_bias_addr() + dyn->d_un.d_ptr);
            break;
        case DT_PLTRELSZ:
            this->m_relplt_size = dyn->d_un.d_val / sizeof(ElfW(Rel));
            break;
        case DT_HASH:
            {
                uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                this->m_nbucket = rawdata[0];
                this->m_nchain  = rawdata[1];
                this->m_bucket  = rawdata + 2;
                this->m_chain   = this->m_bucket + this->m_nbucket;
                this->m_sym_size   = this->m_nchain;
                log_info("nbucket: %d, nchain: %d, bucket: %p, chain:%p\n", this->m_nbucket, this->m_nchain, this->m_bucket, this->m_chain);
                break;
            }
        case DT_GNU_HASH:
            {
                uint32_t *rawdata = reinterpret_cast<uint32_t *>(this->get_bias_addr() + dyn->d_un.d_ptr);
                this->m_gnu_nbucket      = rawdata[0];
                this->m_gnu_symndx       = rawdata[1];
                this->m_gnu_maskwords    = rawdata[2];
                this->m_gnu_shift2       = rawdata[3];
                this->m_gnu_bloom_filter = rawdata + 4;
                this->m_gnu_bucket       = reinterpret_cast<uint32_t*>(this->m_gnu_bloom_filter + this->m_gnu_maskwords);
                this->m_gnu_chain        = this->m_gnu_bucket + this->m_gnu_nbucket - this->m_gnu_symndx;


                if (!powerof2(this->m_gnu_maskwords)) {
                    log_error("[-] invalid maskwords for gnu_hash = 0x%x, in \"%s\" expecting power to two",
                            this->m_gnu_maskwords, get_module_name());
                    return false;
                }
                this->m_gnu_maskwords -= 1;
                this->set_is_gnu_has(true);

                log_dbg("bbucket(%d), symndx(%d), maskworks(%d), shift2(%d)\n",
                        this->m_gnu_nbucket,   this->m_gnu_symndx,
                        this->m_gnu_maskwords, this->m_gnu_shift2);
                break;
            }
        }
    }

//    this->dump_symbols();
    return true;
}

template<class T>
void elf_module::get_section_info(const char *name, ElfW(Shdr) **ppShdr, ElfW(Word) *pSize, T *data)
{
    Elf32_Shdr *_shdr = this->find_section_by_name(name);

    if(_shdr){
        SAFE_SET_VALUE(pSize, _shdr->sh_size / _shdr->sh_entsize);
        SAFE_SET_VALUE(data, reinterpret_cast<T>(this->get_bias_addr() + _shdr->sh_offset));
    }else{
        log_error("[-] Could not found section %s\n", name);
        exit(-1);
    }

    SAFE_SET_VALUE(ppShdr, _shdr);
}

template<class T>
void elf_module::get_segment_info(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data)
{

    ElfW(Phdr)* _phdr = find_segment_by_type(type);
    if(_phdr){
        SAFE_SET_VALUE(data, reinterpret_cast<T>(this->get_bias_addr() + _phdr->p_vaddr));
        SAFE_SET_VALUE(pSize, _phdr->p_memsz);
    }else{
        log_error("[-] Could not found segment type is %d\n", type);
        exit(-1);
    }
    SAFE_SET_VALUE(ppPhdr, _phdr);
}

ElfW(Shdr)* elf_module::find_section_by_name(const char *sname)
{
    ElfW(Shdr) *target = NULL;
    ElfW(Shdr) *shdr = this->m_shdr;
    for(int i = 0; i < this->m_ehdr->e_shnum; i += 1)
    {
        const char *name = (const char *)(shdr[i].sh_name + this->m_shstr_ptr);
        if(!strncmp(name, sname, strlen(sname)))
        {
            target = (ElfW(Shdr)*)(shdr + i);
            break;
        }
    }
    return target;
}

ElfW(Phdr) *elf_module::find_segment_by_type(const ElfW(Word) type)
{
    ElfW(Phdr) *target = NULL;
    ElfW(Phdr) *phdr = this->m_phdr;

    for(int i = 0; i < this->m_ehdr->e_phnum; i += 1)
    {
        if(phdr[i].p_type == type)
        {
            target = phdr + i;
            break;
        }
    }
    return target;
}

uint32_t elf_module::elf_hash(const char *name)
{
    const unsigned char *tmp = (const unsigned char *) name;
    uint32_t h = 0, g;
    while (*tmp) {
        h = (h << 4) + *tmp++;
        g = h & 0xf0000000;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

uint32_t elf_module::gnu_hash (const char *s)
{
    uint32_t h = 5381;
    for (unsigned char c = *s; c != '\0'; c = *++s)
    {
        h = h * 33 + c;
    }
    return h;
}

bool elf_module::elf_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx)
{
    ElfW(Sym) *target = NULL;

    uint32_t hash = elf_hash(symbol);
    uint32_t index = this->m_bucket[hash % this->m_nbucket];

    if (!strcmp(this->m_symstr_ptr + this->m_sym_ptr[index].st_name, symbol)) {
        target = this->m_sym_ptr + index;
    }
    if (!target) {
        do {
            index = this->m_chain[index];
            if (!strcmp(this->m_symstr_ptr + this->m_sym_ptr[index].st_name, symbol)) {
                target = this->m_sym_ptr + index;
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

bool elf_module::gnu_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx)
{
    uint32_t hash = this->gnu_hash(symbol);
    uint32_t h2 = hash >> this->m_gnu_shift2;

    uint32_t bloom_mask_bits = sizeof(ElfW(Addr))*8;
    uint32_t word_num = (hash / bloom_mask_bits) & this->m_gnu_maskwords;
    ElfW(Addr) bloom_word = this->m_gnu_bloom_filter[word_num];

    *sym = NULL;
    *symidx = 0;

    log_info("[+] Search %s in %s@%p (gnu)\n",
                symbol,
                this->get_module_name(),
                reinterpret_cast<void*>(this->get_base_addr()));

    // log_dbg("word_num(%d), bloom_word(%x), hash(%08x), h2(%x), bloom_mask_bits(%x)\n", word_num, bloom_word, hash, h2, bloom_mask_bits);
    // log_dbg("%x; %x, %x, %x\n",  (hash % bloom_mask_bits) ,
    //                     (bloom_word >> (hash % bloom_mask_bits)),
    //                     (h2 % bloom_mask_bits),
    //                     (bloom_word >> (h2 % bloom_mask_bits)));
    // test against bloom filter
    if ((1 & (bloom_word >> (hash % bloom_mask_bits)) & (bloom_word >> (h2 % bloom_mask_bits))) == 0) {
        log_dbg("[-] NOT Found %s in %s@%p 1\n",
                    symbol,
                    this->get_module_name(),
                    reinterpret_cast<void*>(this->get_base_addr()));

        return false;
    }

    // bloom test says "probably yes"...
    uint32_t n = this->m_gnu_bucket[hash % this->m_gnu_nbucket];

    if (n == 0) {
        log_dbg("[-] NOT Found %s in %s@%p 2\n",
            symbol,
            this->get_module_name(),
            reinterpret_cast<void*>(this->get_base_addr()));

        return false;
    }

    do {
        ElfW(Sym)* s = this->m_sym_ptr + n;
        if (((this->m_gnu_chain[n] ^ hash) >> 1) == 0 &&
                    strcmp((this->m_symstr_ptr + s->st_name), symbol) == 0) {
            log_info("[+] Found %s in %s (%p) %zd\n",
                            symbol,
                            this->get_module_name(),
                            reinterpret_cast<void*>(s->st_value),
                            static_cast<size_t>(s->st_size));
            *symidx = n;
            *sym = s;
            return true;
        }
        log_dbg("test : %s\n", (this->m_symstr_ptr + s->st_name));
    } while ((this->m_gnu_chain[n++] & 1) == 0);

    log_warn("[-] NOT Found %s in %s@%p 3\n",
              symbol,
              this->get_module_name(),
              reinterpret_cast<void*>(this->get_base_addr()));

    return false;
}

bool elf_module::find_symbol_by_name(const char *symbol, ElfW(Sym) **sym, int *symidx)
{
    if (this->m_is_gnu_hash) {
        bool result = gnu_lookup(symbol, sym, symidx);
        if (!result) {
            for(int i = 0; i < (int)this->m_gnu_symndx; i++) {
                char const* symName = reinterpret_cast<char const *>(this->m_sym_ptr[i].st_name + this->m_symstr_ptr);
                if (strcmp(symName, symbol) == 0) {
                    // found symbol
                    *symidx = i;
                    *sym = this->m_sym_ptr + i;
                    result = true;
                    log_info("[+] Found %s in %s (%p) %zd\n",
                                    symbol,
                                    this->get_module_name(),
                                    reinterpret_cast<void*>((*sym)->st_value),
                                    static_cast<size_t>((*sym)->st_size));
                }
            }
        }
        return result;
    }
    return elf_lookup(symbol, sym, symidx);
}

bool elf_module::hook(const char *symbol, void *replace_func, void **old_func)
{
    ElfW(Sym) *sym = NULL;
    int symidx = 0;

    assert(old_func);
    assert(replace_func);
    assert(symbol);

    if (!this->m_is_loaded) {
        this->m_is_loaded = this->get_segment_view();
        if (!this->m_is_loaded) {
            return false;
        }
    }

    this->find_symbol_by_name(symbol, &sym, &symidx);
    if(!sym)
    {
        log_error("[-] Could not find symbol %s\n", symbol);
        goto fail;
    }
    else
    {
        log_info("[+] sym %p, symidx %d.\n", sym, symidx);
    }

    for (uint32_t i = 0; i < this->m_relplt_size; i++)
    {
        ElfW(Rel)& rel = this->m_relplt_ptr[i];
        if (ELF32_R_SYM(rel.r_info) == symidx && ELF32_R_TYPE(rel.r_info) == R_ARM_JUMP_SLOT)
        {

            void *addr = (void *) (this->get_bias_addr() + rel.r_offset);
            if (this->replace_function(addr, replace_func, old_func))
            {
                goto fail;
            }
            break;
        }
    }

    for (uint32_t i = 0; i < this->m_reldyn_size; i++)
    {
        ElfW(Rel)& rel = this->m_reldyn_ptr[i];
        if (ELF32_R_SYM(rel.r_info) == symidx &&
                (ELF32_R_TYPE(rel.r_info) == R_ARM_ABS32
                        || ELF32_R_TYPE(rel.r_info) == R_ARM_GLOB_DAT))
        {

            void *addr = (void *) (this->get_bias_addr() + rel.r_offset);
            if (this->replace_function(addr, replace_func, old_func))
            {
                goto fail;
            }
        }
    }
    return true;
fail:
    return false;
}

int elf_module::set_mem_access(ElfW(Addr) addr, int prots)
{
    void *page_start_addr = (void *)PAGE_START((uint32_t)addr);
    return mprotect(page_start_addr, getpagesize(), prots);
}

int elf_module::get_mem_access(ElfW(Addr) addr, uint32_t* pprot)
{
    int result = -1;

    const ElfW(Phdr)* phdr_table = this->m_phdr;
    const ElfW(Phdr)* phdr_end = phdr_table + this->m_ehdr->e_phnum;

    for (const ElfW(Phdr)* phdr = phdr_table; phdr < phdr_end; phdr++)
    {
        if (phdr->p_type == PT_LOAD)
        {
            ElfW(Addr) seg_start = this->get_bias_addr() + phdr->p_vaddr;
            ElfW(Addr) seg_end   = seg_start + phdr->p_memsz;

            ElfW(Addr) seg_page_start = PAGE_START(seg_start);
            ElfW(Addr) seg_page_end   = PAGE_END(seg_end);

            if (addr >= seg_page_start && addr < seg_page_end)
            {
                *pprot = PFLAGS_TO_PROT(phdr->p_flags),
                result = 0;
            }
        }
    }
    return result;
}

int elf_module::clear_cache(void* addr, size_t len)
{
    void *end = (uint8_t *)addr + len;
    return syscall(0xf0002, addr, end);
}


bool elf_module::replace_function(void* addr, void *replace_func, void **old_func)
{
    bool res = false;
    uint32_t old_prots = PROT_READ;
    uint32_t prots = old_prots;
    if(*(void **)addr == replace_func)
    {
        log_warn("addr %p had been replace.\n", addr);
        goto fail;
    }

    if(!*old_func){
        *old_func = *(void **)addr;
    }

    if (get_mem_access(reinterpret_cast<ElfW(Addr)>(addr), &old_prots)) {
        log_error("[-] read mem access fails, error %s.\n", strerror(errno));
        res = true;
        goto fail;
    }

    prots = old_prots | PROT_WRITE;
    if ((prots & PROT_WRITE) != 0) { // make sure we're never simultaneously writable / executable
        prots &= ~PROT_EXEC;
    }

    if(set_mem_access(reinterpret_cast<ElfW(Addr)>(addr), prots))
    {
        log_error("[-] modify mem access fails, error %s.\n", strerror(errno));
        res = true;
        goto fail;
    }

    *(void **)addr = replace_func;
    clear_cache(addr, getpagesize());
    log_info("[+] old_func is %p, replace_func is %p, new_func %p.\n", *old_func, replace_func, (void*)(*(uint32_t *)addr));

fail:
    return res;
}


void elf_module::dump_elf_header(void)
{
    static char alpha_tab[17] = "0123456789ABCDEF";
    char buff[EI_NIDENT*3+1];

    ElfW(Ehdr)* ehdr = this->m_ehdr;

    log_info("Elf Header :\n");
    for(int i = 0; i < EI_NIDENT; i++) {
        uint8_t ch = ehdr->e_ident[i];
        buff[i*3 + 0] = alpha_tab[(int)((ch >> 4) & 0x0F)];
        buff[i*3 + 1] = alpha_tab[(int)(ch & 0x0F)];
        buff[i*3 + 2] = ' ';
    }
    buff[EI_NIDENT*3] = '\0';

    log_info("e_ident: %s\n",       buff);
    log_info("e_type: %x\n",        ehdr->e_type);
    log_info("e_machine: %x\n",     ehdr->e_machine);
    log_info("e_version: %x\n",     ehdr->e_version);
    log_info("e_entry: %x\n",       ehdr->e_entry);
    log_info("e_phoff: %x\n",       ehdr->e_phoff);
    log_info("e_shoff: %x\n",       ehdr->e_shoff);
    log_info("e_flags: %x\n",       ehdr->e_flags);
    log_info("e_ehsize: %x\n",      ehdr->e_ehsize);
    log_info("e_phentsize: %x\n",   ehdr->e_phentsize);
    log_info("e_phnum: %x\n",       ehdr->e_phnum);
    log_info("e_shentsize: %x\n",   ehdr->e_shentsize);
    log_info("e_shnum: %x\n",       ehdr->e_shnum);
    log_info("e_shstrndx: %x\n",    ehdr->e_shstrndx);
}

void elf_module::dump_sections(void)
{
    Elf32_Half shnum = this->m_ehdr->e_shnum;
    Elf32_Shdr *shdr = this->m_shdr;

    log_info("Sections: :%d\n",shnum);
    for(int i = 0; i < shnum; i += 1, shdr += 1) {
        const char *name = shdr->sh_name == 0 || !this->m_shstr_ptr ? "UNKOWN" :  (const char *)(shdr->sh_name + this->m_shstr_ptr);
        log_info("[%.2d] %-20s 0x%.8x\n", i, name, shdr->sh_addr);
    }

    log_info("Sections: end\n");
}

void elf_module::dump_sections2() {
    ElfW(Half) shnum = this->m_ehdr->e_shnum;
    ElfW(Shdr) *shdr = this->m_shdr;

    log_info("Sections: :%d\n",shnum);
    for(int i = 0; i < shnum; i += 1, shdr += 1) {
        log_info("Name(%08X);Type(%08X);Addr(%08X);offset(%08X);entSize(%08X)\n",

            shdr->sh_name, shdr->sh_type, shdr->sh_addr, shdr->sh_offset, shdr->sh_entsize);
    }
    log_info("Sections: end\n");
}

void elf_module::dump_segments(void)
{
    ElfW(Phdr) *phdr = this->m_phdr;
    ElfW(Half) phnum = this->m_ehdr->e_phnum;

    log_info("Segments: \n");
    for(int i = 0; i < phnum; i++){
        log_info("[%.2d] %-.8x 0x%-.8x 0x%-.8x %-8d %-8d\n", i,
                 phdr[i].p_type, phdr[i].p_vaddr,
                 phdr[i].p_paddr, phdr[i].p_filesz,
                 phdr[i].p_memsz);
    }
}
const static struct dyn_name_map_t{
    const char* dyn_name;
    int dyn_tag;
}dyn_name_maps[30] = {
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
    {"DT_ANDROID_REL", DT_ANDROID_REL},
    {"DT_ANDROID_RELSZ",DT_ANDROID_RELSZ},
    {NULL, 0}
};

const char* elf_module::convert_dynamic_tag_to_name(int d_tag)
{
    for(int i = 0; dyn_name_maps[i].dyn_name != NULL; i++) {
        if (dyn_name_maps[i].dyn_tag == d_tag) {
            return dyn_name_maps[i].dyn_name;
        }
    }
    return "UNKNOW";
}

void elf_module::dump_dynamics(void)
{
    ElfW(Dyn) *dyn = this->m_dyn_ptr;

    log_info(".dynamic section info:\n");
    const char *type = NULL;

    for(int i = 0; i < (int)this->m_dyn_size; i++)
    {
        type = convert_dynamic_tag_to_name(dyn[i].d_tag);
        log_info("[%.2d] %-14s 0x%-.8x 0x%-.8x\n", i, type,  dyn[i].d_tag, dyn[i].d_un.d_val);
        if(dyn[i].d_tag == DT_NULL){
            break;
        }
    }
    return;
}

void elf_module::dump_symbols(void)
{
    ElfW(Sym) *sym = this->m_sym_ptr;

    log_info("dynsym section info: \n");
    if (this->get_is_gnu_hash()) {

    } else {
        for(int i=0; i< (int)this->m_sym_size; i++)
        {
            log_info("[%2d] %-20s\n", i, sym[i].st_name + this->m_symstr_ptr);
        }
    }

    return;
}

void elf_module::dump_rel_info(void)
{
    ElfW(Rel)* rels[] = {this->m_reldyn_ptr, this->m_relplt_ptr};
    ElfW(Word) resszs[] = {this->m_reldyn_size, this->m_relplt_size};

    ElfW(Sym) *sym = this->m_sym_ptr;

    log_info("rel section info:\n");
    for(int i = 0; i < (int)(sizeof(rels)/sizeof(rels[0])); i++)
    {
        ElfW(Rel) *rel = rels[i];
        ElfW(Word) relsz = resszs[i];

        for(int j = 0; j < (int)relsz; j += 1)
        {
            const char *name = sym[ELF32_R_SYM(rel[j].r_info)].st_name + this->m_symstr_ptr;
            log_info("[%.2d-%.4d] 0x%-.8x 0x%-.8x %-10s\n", i, j, rel[j].r_offset, rel[j].r_info, name);
        }
    }
    return;
}
