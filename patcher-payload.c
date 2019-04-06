extern int creat(const char *, int);
extern int write(int, char *, int);
extern int close(int);
extern void _exit(int);
extern int time(int *);
extern void *localtime(const int *);
extern int strftime(char *s, int, const char *, const void *);
extern int strlen(const char *);
#define NULL ((void *)0)

volatile void *unload_handle __attribute__((section(".text")));
static int fd = -1;

__attribute__((constructor)) static void yathtest() {
    char buf[256];

    int t = time(NULL);
    void *lt = localtime(&t);
    strftime(buf, sizeof(buf), "[%F %T] ohai\n", lt);

    fd = creat("/data/local/tmp/yath.log", 0666);
    if (fd < 0)
        return;
    write(fd, buf, strlen(buf));
}

__attribute__((destructor)) static void bye() {
    char buf[256];

    if (fd < 0)
        return;

    int t = time(NULL);
    void *lt = localtime(&t);
    strftime(buf, sizeof(buf), "[%F %T] cu\n", lt);

    write(fd, buf, strlen(buf));
    close(fd);
}
