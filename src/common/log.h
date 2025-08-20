#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct _IO_FILE FILE;

void log_init(FILE *fd, bool mirror_to_stdout);

void log_error(const char *fmt, ...);
void log_warning(const char *fmt, ...);
void log_info(const char *fmt, ...);
