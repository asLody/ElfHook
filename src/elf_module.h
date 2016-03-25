#if !defined(__ELFHOOK_H__)
#define __ELFHOOK_H__

#include <elf.h>
#include <string>
#include "elf_common.h"


class elf_module {

public:
    elf_module(ElfW(Addr) base_addr, const char* module_name);
    ~elf_module();

    static bool is_elf_module(void* base_addr);

    inline const char* get_module_name() { return this->m_module_name.c_str(); }
    inline ElfW(Addr) get_base_addr() { return this->m_base_addr; }
    inline ElfW(Addr) get_bias_addr() { return this->m_bias_addr; }
    inline bool get_is_gnu_hash() { return this->m_is_gnu_hash; }
    inline void set_is_gnu_has(bool flag) { this->m_is_gnu_hash = flag; }
    bool hook(const char *symbol, void *replace_func, void **old_func);

    void dump_elf_header(void);
    void dump_sections();
    void dump_sections2();
    void dump_segments();
    void dump_dynamics();
    void dump_symbols();
    void dump_rel_info();

protected:

    ElfW(Addr) caculate_bias_addr(const ElfW(Ehdr)* elf);

    uint32_t elf_hash(const char *name);
    uint32_t gnu_hash(const char *name);

    bool get_segment_view(void);

    ElfW(Phdr)* find_segment_by_type(const ElfW(Word) type);
    ElfW(Shdr)* find_section_by_name(const char *sname);

    bool gnu_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
    bool elf_lookup(char const* symbol, ElfW(Sym) **sym, int *symidx);
    bool find_symbol_by_name(const char *symbol, ElfW(Sym) **sym, int *symidx);

    template<class T>
    void get_segment_info(const ElfW(Word) type, ElfW(Phdr) **ppPhdr, ElfW(Word) *pSize, T *data);
    template<class T>
    void get_section_info(const char *name, ElfW(Shdr) **ppShdr, ElfW(Word) *pSize, T *data);

    int  clear_cache(void *addr, size_t len);
    int  get_mem_access(ElfW(Addr) addr, uint32_t* pprot);
    int  set_mem_access(ElfW(Addr)
    addr, int prots);
    bool replace_function(void *addr, void *replace_func, void **old_func);



    const char* convert_dynamic_tag_to_name(int d_tag);

protected:

    ElfW(Addr)      m_base_addr;
    ElfW(Addr)      m_bias_addr;
    std::string     m_module_name;
    bool            m_is_loaded;
protected:

    ElfW(Ehdr)  *m_ehdr;
    ElfW(Phdr)  *m_phdr;
    ElfW(Shdr)  *m_shdr;

    ElfW(Dyn)   *m_dyn_ptr;
    ElfW(Word)  m_dyn_size;

    ElfW(Sym)    *m_sym_ptr;
    ElfW(Word)   m_sym_size;

    ElfW(Rel)   *m_relplt_ptr;
    ElfW(Rel)   *m_reldyn_ptr;
    ElfW(Word)  m_relplt_size;
    ElfW(Word)  m_reldyn_size;

protected:
    //for elf hash
    uint32_t    m_nbucket;
    uint32_t    m_nchain;
    uint32_t    *m_bucket;
    uint32_t    *m_chain;

    //for gnu hash
    uint32_t   m_gnu_nbucket;
    uint32_t   m_gnu_symndx;
    uint32_t   m_gnu_maskwords;
    uint32_t   m_gnu_shift2;
    uint32_t   *m_gnu_bucket;
    uint32_t   *m_gnu_chain;
    ElfW(Addr) *m_gnu_bloom_filter;

    bool m_is_gnu_hash;

protected:

    const char  *m_shstr_ptr;
    const char  *m_symstr_ptr;
};


#endif
