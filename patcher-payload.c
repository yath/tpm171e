#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#define LOGFILE "/data/local/tmp/patcher-payload.log"
#define LOGFILE_MODE "w" // fopen() mode; 'a'ppend or 'w'rite (with truncation).

static FILE *logf = NULL;

__attribute__((format(printf, 3, 4)))
static void do_log(const char *filename, int lineno, const char *format, ...) {
    if (!logf)
        return;

    char tsbuf[256] = {0};
    time_t t = time(NULL);
    if (!strftime(tsbuf, sizeof(tsbuf)-1, "[%F %T] ", localtime(&t)))
        tsbuf[0] = '\0';
    fprintf(logf, "%s%s:%d: ", tsbuf, filename, lineno);

    va_list args;
    va_start(args, format);
    vfprintf(logf, format, args);
    va_end(args);

    if (*format && format[strlen(format)-1] != '\n')
        fputc('\n', logf);

    fflush(logf);
}

#define log(...) do_log(__FILE__, __LINE__, __VA_ARGS__)

#define PROT_NONE    0x00
#define PROT_READ    0x04
#define PROT_WRITE   0x02
#define PROT_EXEC    0x01
extern int mprotect(void *addr, size_t len, int prot);

#define PF_X        (1 << 0)    /* Segment is executable */
#define PF_W        (1 << 1)    /* Segment is writable */
#define PF_R        (1 << 2)    /* Segment is readable */

#define PF_RW (PF_R|PF_W)

#define PT_NULL     0       /* Program header table entry unused */
#define PT_LOAD     1       /* Loadable program segment */
#define PT_DYNAMIC  2       /* Dynamic linking information */
/* […] rest omitted for brevity */

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
};

extern int dl_iterate_phdr(void *callback, void *data);

#define RTLD_LAZY   0x00001 /* Lazy function call binding.  */
#define RTLD_NOW    0x00002 /* Immediate function call binding.  */
#define RTLD_BINDING_MASK   0x3 /* Mask of binding time value.  */
#define RTLD_NOLOAD 0x00004 /* Do not load the object.  */
#define RTLD_DEEPBIND   0x00008 /* Use deep binding.  */

extern void *dlsym(void *hdl, const char *name);
extern void *dlopen(const char *, int);
extern int dlclose(void *);

#define UNUSED __attribute__((unused))

static char *(*orig_getval)(int16_t grp, char *cfg, int32_t *value) = NULL;

struct patch_got_req {
    void *oldval;
    void *newval;
};

struct undo_item {
    uint32_t *addr;
    uint32_t oldval;
};

static struct undo_item undo[256];
static unsigned int nundo = 0;

static char *my_getval(int16_t grp, char *cfg, int32_t *value) {
    char *ret = orig_getval(grp, cfg, value);
    log("orig_getval(grp=%d, cfg=%s, *value=%ld) = %s", grp, cfg, (value?*value:0xDEAD), ret);
    return ret;
}

static int patch_got(void *start, void *end, const char *filename, struct patch_got_req *req) {
    if (!*filename)
        filename = "dtv_svc";

    uint32_t *off = NULL;

    for (uint32_t *p = start; p < (uint32_t *)end; p++) {
        if (*p != (uint32_t)req->oldval)
            continue;
        if (off) {
            log("patch_got(%p, %p): found old value twice (%p and %p), not patching.", start, end, off, p);
            return -1;
        }
        off = p;
    }

    if (!off)
        return 0;

    if (++nundo > sizeof(undo)) {
        log("can't store more than %d undo items", sizeof(undo));
        return -1;
    }

    undo[nundo-1].addr = off;
    undo[nundo-1].oldval = *off;
    *off = (uint32_t)req->newval;
    log("Patched %p 0x%08lx -> 0x%08lx", off, undo[nundo-1].oldval, *off);

    return 0;
}

static int find_got_phdr(struct dl_phdr_info *info, size_t size UNUSED, struct patch_got_req *req) {
    for (int i = 0; i < info->phnum; i++) {
        if (info->phdr[i].type != PT_LOAD || (info->phdr[i].flags & PF_RW) != PF_RW)
            continue;

        void *start = info->addr + info->phdr[i].vaddr;
        void *end = start + info->phdr[i].memsz;

        if (patch_got(start, end, info->name, req) < 0)
            return -1;
    }

    return 0;
}


__attribute__((constructor)) static void init() {
    if (logf)
        fclose(logf);

    logf = fopen(LOGFILE, LOGFILE_MODE);
    if (!logf)
        return;

    log("Initializing");

    if (orig_getval) {
        log("orig_getval already points to %p, skipping GOT patching", orig_getval);
        return;
    }

    void *hdl = dlopen("libmtkapp.so", 6);
    const char *symname = "a_mtktvapi_config_get_value";
    orig_getval = dlsym(hdl, symname);

    if (hdl)
        dlclose(hdl);

    if (!orig_getval) {
        log("Can't find %s in hdl %p", symname, hdl);
        return;
    }

    log("Patching GOTs referencing %s = %p", symname, orig_getval);
    struct patch_got_req req = {
        .oldval = orig_getval,
        .newval = my_getval,
    };
    dl_iterate_phdr(find_got_phdr, &req);


    log("Initialized");
}

__attribute__((destructor)) static void fini() {
    log("Tearing down.");

    while (nundo > 0) {
        *(undo[nundo-1].addr) = undo[nundo-1].oldval;
        log("Undid GOT patch at %p", undo[nundo-1].addr);
        nundo--;
    }

    if (fclose(logf) == 0)
        logf = NULL;
}
