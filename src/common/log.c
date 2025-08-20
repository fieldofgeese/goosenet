#include "log.h"

#include <stdio.h>
#include <stdarg.h>
#include <stdint.h>
#include <assert.h>

static FILE *fd;
static bool mirror_to_stdout = true;

static void log(const char *severity, const char *fmt, va_list args) {
    if (mirror_to_stdout) {
        va_list copy;
        va_copy(copy, args);
        fprintf(stdout, "%s", severity);
        vfprintf(stdout, fmt, copy);
        fputc('\n', stdout);
    }

    fprintf(fd, "%s", severity);
    vfprintf(fd, fmt, args);
    fputc('\n', fd);
}

void log_init(FILE *_fd, bool _mirror_to_stdout) {
    fd = _fd;
    setvbuf(fd, NULL, _IONBF, 0);
    mirror_to_stdout = _mirror_to_stdout;
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log("\033[31;1m[error]\033[0m ", fmt, args);
    va_end(args);
}

void log_warning(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log("\033[33;1m[warning]\033[0m ", fmt, args);
    va_end(args);
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    log("\033[36;1m[info]\033[0m ", fmt, args);
    va_end(args);
}
