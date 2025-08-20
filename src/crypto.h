#pragma once

struct stack;

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

bool crypto_init(const char *dir, const char *pass);
void crypto_deinit();

enum key_type {
    KEY_PRIVATE = 0,
    KEY_PUBLIC,
};

enum keypair_type {
    KEYPAIR_USER = 0,
    KEYPAIR_SESSION,
    KEYPAIR_SERVER,
};

bool crypto_encrypt(struct stack *stack,
                    const char *name,
                    enum keypair_type keypair_type,
                    const uint8_t *buf, size_t len,
                    uint8_t **out, size_t *out_len);

bool crypto_decrypt(struct stack *stack,
                    const uint8_t *buf, size_t len,
                    uint8_t **out, size_t *out_len);

void crypto_add_key(struct stack *stack, const uint8_t *buf, size_t len, enum key_type key_type);

struct keypair_paths {
    const char *pub;
    const char *prv;
};

const char *crypto_get_uid(struct stack *stack, const char *name, enum keypair_type keypair_type);

struct keypair_paths crypto_get_paths(struct stack *stack, const char *uid);

bool crypto_load_keypair(struct stack *stack, struct keypair_paths paths);

void crypto_generate_or_load_keypair(struct stack *stack,
                                     const char *name,
                                     enum keypair_type keypair_type);

int crypto_generate_keypair(struct stack *stack,
                            const char *uid,
                            struct keypair_paths paths);

const uint8_t *crypto_get_key(struct stack *stack,
                              const char *name,
                              enum keypair_type keypair_type,
                              enum key_type key_type,
                              size_t *out_len);
