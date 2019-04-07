#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

#define LOGFILE "/data/local/tmp/patcher-payload.log"
#define LOGFILE_MODE "w" // fopen() mode; 'a'ppend or 'w'rite (with truncation).

static FILE *logf = NULL;

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

__attribute__((constructor)) static void init() {
    if (logf)
        fclose(logf);

    logf = fopen(LOGFILE, LOGFILE_MODE);
    if (!logf)
        return;
    log("Initialized.");
}

__attribute__((destructor)) static void fini() {
    log("Tearing down.");

    if (fclose(logf) == 0)
        logf = NULL;
}
