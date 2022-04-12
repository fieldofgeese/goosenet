#include "log.h"

#include <stdio.h>
#include <stdarg.h>

void log_error(const char *fmt, ...) {
    fprintf(stderr, "\033[31;1m[error]\033[0m ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    fputc('\n', stderr);
}

void log_warning(const char *fmt, ...) {
    fprintf(stdout, "\033[33;1m[warning]\033[0m ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fputc('\n', stdout);
}

void log_info(const char *fmt, ...) {
    fprintf(stdout, "\033[36;1m[info]\033[0m ");

    va_list args;
    va_start(args, fmt);
    vfprintf(stdout, fmt, args);
    va_end(args);

    fputc('\n', stdout);
}
