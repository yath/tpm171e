#ifndef _PATCHER_PAYLOAD_H
#define _PATCHER_PAYLOAD_H 1

/*** Definitions missing from gcc-arm-none-eabi’s C headers. ***/

/** mprotect() - unused, but handy for making .text +w. **/

#define PROT_NONE    0x00
#define PROT_READ    0x04
#define PROT_WRITE   0x02
#define PROT_EXEC    0x01
extern int mprotect(void *addr, size_t len, int prot);

/** dl_iterate_phdr() and accompanying structs. Taken from glibc’s elf/elf.h. **/

#define PF_X        (1 << 0)    /* Segment is executable */
#define PF_W        (1 << 1)    /* Segment is writable */
#define PF_R        (1 << 2)    /* Segment is readable */

#define PF_RW (PF_R|PF_W) /* not in glibc */

#define PT_NULL     0       /* Program header table entry unused */
#define PT_LOAD     1       /* Loadable program segment */
#define PT_DYNAMIC  2       /* Dynamic linking information */
/* etc. - we only really use PT_LOAD. */

struct elf32_phdr {
    uint32_t type;    /* Segment type */
    uint32_t offset;  /* Segment file offset */
    uint32_t vaddr;   /* Segment virtual address */
    uint32_t paddr;   /* Segment physical address */
    uint32_t filesz;  /* Segment size in file */
    uint32_t memsz;   /* Segment size in memory */
    uint32_t flags;   /* Segment flags */
    uint32_t align;   /* Segment alignment */
};

struct dl_phdr_info {
    void *addr;                    /* Base address of object */
    const char *name;              /* Name of object */
    const struct elf32_phdr *phdr; /* Pointer to array of ELF program headers */
    uint16_t phnum;                /* # of items in phdr */
    /* glibc >= 2.4 has additional fields that we don’t care about. */
};

extern int dl_iterate_phdr(void *callback, void *data);

/** dlopen() and friends. From glibc’s {bits,dlfcn}/dlfcn.h. */

/* dlopen flags. */
#define RTLD_LAZY   0x00001 /* Lazy function call binding.  */
#define RTLD_NOW    0x00002 /* Immediate function call binding.  */
#define RTLD_BINDING_MASK   0x3 /* Mask of binding time value.  */
#define RTLD_NOLOAD 0x00004 /* Do not load the object.  */
#define RTLD_DEEPBIND   0x00008 /* Use deep binding.  */

/* special dlsym handles. */
#define RTLD_NEXT ((void *) -1l)
#define RTLD_DEFAULT ((void *) 0) /* The code uses NULL actually. */

extern void *dlsym(void *hdl, const char *name);
extern void *dlopen(const char *, int);
extern int dlclose(void *);
char *dlerror(void);

#endif /* _PATCHER_PAYLOAD_H */
