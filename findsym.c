#include <stddef.h>

extern int printk(const char*, ...);

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

static void *brute_lookup(char *name) {
    int len = strlen(name)+1;

    char *start = (char *)0xc0008000;
    char *end = (char *)(0xc0008000+0x1000000);

    char *strp = memmem(start, end, name, len, 1);
    if (!strp)
        return NULL;

    void *pp = memmem(start, strp, (char*)&strp, sizeof(char*), -1);
    if (!pp)
        return NULL;

    void **fp = pp-sizeof(char*);
    return *fp;
}

int ohai() {
    void *(*kallsyms_lookup_name)(char *) = brute_lookup("kallsyms_lookup_name");
    printk("\n\n<1>Found kallsyms_lookup_name at %p\n\n", kallsyms_lookup_name);
    if (!kallsyms_lookup_name)
        return 1;

    void (*dump_stack)() = kallsyms_lookup_name("dump_stack");
    if (!dump_stack)
        return 1;

    printk("\n\n<1>kallsyms_lookup_name(\"dump_stack\") = %p, invoking:\n", dump_stack);
    dump_stack();

    printk("\n\n<1>bye!\n\n");

    return 0;
}
