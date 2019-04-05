extern int creat(const char *, int);
extern int write(int, char *, int);
extern int close(int);
extern void _exit(int);
extern int time(int *);
extern void *localtime(const int *);
extern int strftime(char *s, int, const char *, const void *);
extern int strlen(const char *);
#define NULL ((void *)0)

__attribute__((constructor)) void yathtest() {
    char buf[256];

    int t = time(NULL);
    void *lt = localtime(&t);
    strftime(buf, sizeof(buf), "[%F %T] ohai\n", lt);

    int fd = creat("/data/local/tmp/yath.log", 0666);
    if (fd < 0)
        return;
    write(fd, buf, strlen(buf));
    close(fd);
}
