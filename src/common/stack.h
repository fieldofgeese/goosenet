#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <assert.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

struct stack {
    uint8_t *memory;
    size_t size;
    size_t top;
};

static inline void stack_ensure_init(struct stack *s) {
    if (s->memory == NULL) {
        assert(s->size > 0);
        void *memory = malloc(s->size);
        assert(memory);
        s->memory = memory;
        s->top = 0;
    }
}

static inline void *stack_alloc(struct stack *s, size_t size) {
    stack_ensure_init(s);

    assert(size <= s->size - s->top);
    uint8_t *ptr = s->memory + s->top;
    s->top += size;

    return ptr;
}

#define stack_push_value(stack, type, value)                     \
    do {                                                         \
        type tmp = value;                                        \
        stack_push_bytes(stack, (uint8_t *) &tmp, sizeof(type)); \
    } while(0)

static inline void *stack_push_bytes(struct stack *s, const uint8_t *data, size_t size) {
    uint8_t *ptr = stack_alloc(s, size);
    memcpy(ptr, data, size);
    return ptr;
}

#define pop_value(ptr, type) \
    (*(type *)pop_bytes(ptr, sizeof(type)))

static inline uint8_t *pop_bytes(uint8_t **ptr, size_t size) {
    uint8_t *res = *ptr;
    *ptr += size;
    return res;
}

static inline void stack_deinit(struct stack *s) {
    assert(s->memory);
    free(s->memory);
}

static inline uint8_t *stack_top(struct stack *s) {
    stack_ensure_init(s);
    assert(s->top < s->size);
    return s->memory + s->top;
}

static inline size_t stack_free_size(struct stack *s) {
    stack_ensure_init(s);
    assert(s->top <= s->size);
    return s->size - s->top;
}

static inline void stack_clear(struct stack *s) {
    assert(s->memory);
    s->top = 0;
}

static inline const char *stack_fmt(struct stack *s, const char *fmt, ...) {
    stack_ensure_init(s);

    char *ptr = (char *)(s->memory + s->top);
    const size_t maxsize = s->size - s->top;

    va_list args;
    va_start(args, fmt);
    int written = vsnprintf(ptr, maxsize, fmt, args);
    va_end(args);

    assert((size_t)written < maxsize);
    s->top += written + 1;

    return ptr;
}
