#include "crypto.h"
#include "common/log.h"
#include "common/stack.h"

#include <rnp/rnp.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>

#define RNP_SUCCESS 0

static rnp_ffi_t ffi = NULL;

static const char *keydir = ".";
static const char *password = "password";

static const char *CURVE_25519_KEY_DESC_FMT = "{\
    'primary': {\
        'type': 'EDDSA',\
        'userid': '%s',\
        'expiration': 0,\
        'usage': ['sign'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    },\
    'sub': {\
        'type': 'ECDH',\
        'curve': 'Curve25519',\
        'expiration': 15768000,\
        'usage': ['encrypt'],\
        'protection': {\
            'cipher': 'AES256',\
            'hash': 'SHA256'\
        }\
    }\
}";

/* basic pass provider implementation, which always return 'password' for key protection.
You may ask for password via stdin, or choose password based on key properties, whatever else
*/
static bool
example_pass_provider(rnp_ffi_t        ffi,
                      void *           app_ctx,
                      rnp_key_handle_t key,
                      const char *     pgp_context,
                      char             buf[],
                      size_t           buf_len)
{
    log_info("requesting pass: %s", pgp_context);
    (void)ffi;
    (void)app_ctx;
    (void)key;
    if (!strcmp(pgp_context, "decrypt")) {
        strncpy(buf, password, buf_len);
        return true;
    }
    if (!strcmp(pgp_context, "protect")) {
        strncpy(buf, password, buf_len);
        return true;
    }
    return false;
}

static bool load_single_key(const char *path, uint32_t flags) {
    rnp_input_t keyfile = NULL;
    bool result = false;

    /* load keyrings */
    if (rnp_input_from_path(&keyfile, path) != RNP_SUCCESS) {
        goto finish;
    }

    /* actually, we may use 0 instead of RNP_LOAD_SAVE_PUBLIC_KEYS, to not check key types */
    if (rnp_load_keys(ffi, "GPG", keyfile, flags) != RNP_SUCCESS) {
        goto finish;
    }

    result = true;

finish:
    rnp_input_destroy(keyfile);
    return result;
}

bool crypto_encrypt(struct stack *stack,
                    const char *name,
                    enum keypair_type keypair_type,
                    const uint8_t *buf, size_t len,
                    uint8_t **out, size_t *out_len) {
    rnp_op_encrypt_t encrypt = NULL;
    rnp_key_handle_t key = NULL;
    rnp_input_t      input = NULL;
    rnp_output_t     output = NULL;
    bool             result = false;

    const char *uid = crypto_get_uid(stack, name, keypair_type);

    /* create memory input and file output objects for the message and encrypted message */
    if (rnp_input_from_memory(&input, buf, len, false) != RNP_SUCCESS) {
        log_error("failed to create input object");
        goto finish;
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS) {
        log_error("failed to create output memory");
        goto finish;
    }

    /* create encryption operation */
    if (rnp_op_encrypt_create(&encrypt, ffi, input, output) != RNP_SUCCESS) {
        log_error("failed to create encrypt operation");
        goto finish;
    }

    /* setup encryption parameters */
    rnp_op_encrypt_set_file_mtime(encrypt, (uint32_t) time(NULL));
    rnp_op_encrypt_set_compression(encrypt, "ZIP", 6);
    rnp_op_encrypt_set_cipher(encrypt, RNP_ALGNAME_AES_256);
    rnp_op_encrypt_set_aead(encrypt, "None");

    if (rnp_locate_key(ffi, "userid", uid, &key) != RNP_SUCCESS || key == NULL) {
        log_error("failed to locate recipient key");
        goto finish;
    }

    if (rnp_op_encrypt_add_recipient(encrypt, key) != RNP_SUCCESS) {
        log_error("failed to add recipient");
        goto finish;
    }
    rnp_key_handle_destroy(key);
    key = NULL;

    /* execute encryption operation */
    if (rnp_op_encrypt_execute(encrypt) != RNP_SUCCESS) {
        log_error("encryption failed");
        goto finish;
    }

    uint8_t *tmp_buf;
    size_t tmp_len;
    if (rnp_output_memory_get_buf(output, &tmp_buf, &tmp_len, false) != RNP_SUCCESS) {
        goto finish;
    }

    *out = stack_alloc(stack, tmp_len);
    memcpy(*out, tmp_buf, tmp_len);
    *out_len = tmp_len;

    result = true;
finish:
    rnp_op_encrypt_destroy(encrypt);
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    rnp_key_handle_destroy(key);
    return result;
}

bool crypto_decrypt(struct stack *stack,
                    const uint8_t *buf, size_t len,
                    uint8_t **out, size_t *out_len) {
    rnp_input_t  input = NULL;
    rnp_output_t output = NULL;
    bool         result = false;

    if (rnp_ffi_set_pass_provider(ffi, example_pass_provider, NULL) != RNP_SUCCESS) {
        goto finish;
    }

    /* create memory input and file output objects for the message and encrypted message */
    if (rnp_input_from_memory(&input, buf, len, false) != RNP_SUCCESS) {
        log_error("failed to create input object");
        goto finish;
    }

    if (rnp_output_to_memory(&output, 0) != RNP_SUCCESS) {
        log_error("failed to create output memory");
        goto finish;
    }

    rnp_result_t res = rnp_decrypt(ffi, input, output);
    if (res != RNP_SUCCESS) {
        log_error("decryption failed: %s", rnp_result_to_string(res));
        goto finish;
    }

    uint8_t *tmp_buf;
    size_t tmp_len;
    if (rnp_output_memory_get_buf(output, &tmp_buf, &tmp_len, false) != RNP_SUCCESS) {
        goto finish;
    }

    *out = stack_alloc(stack, tmp_len);
    memcpy(*out, tmp_buf, tmp_len);
    *out_len = tmp_len;

    result = true;
finish:
    rnp_input_destroy(input);
    rnp_output_destroy(output);
    return result;
}

void crypto_add_key(struct stack *stack, const uint8_t *buf, size_t len, enum key_type key_type) {
    rnp_input_t keyfile = NULL;
    if (rnp_input_from_memory(&keyfile, buf, len, false) != RNP_SUCCESS) {
        log_error("Failed adding key");
        goto finish;
    }
    uint32_t flags = (key_type == KEY_PUBLIC) ? RNP_LOAD_SAVE_PUBLIC_KEYS : RNP_LOAD_SAVE_SECRET_KEYS;
    if (rnp_load_keys(ffi, "GPG", keyfile, flags) != RNP_SUCCESS) {
        log_error("Failed loading key");
        goto finish;
    }
finish:
    rnp_input_destroy(keyfile);
}

bool crypto_load_keypair(struct stack *stack, struct keypair_paths paths) {
    /* load keyrings */
    if (!load_single_key(paths.pub, RNP_LOAD_SAVE_PUBLIC_KEYS)) {
        return false;
    }
    if (!load_single_key(paths.prv, RNP_LOAD_SAVE_SECRET_KEYS)) {
        return false;
    }

    return true;
}

const uint8_t *crypto_get_key(struct stack *stack,
                              const char *name,
                              enum keypair_type keypair_type,
                              enum key_type key_type,
                              size_t *out_len) {
    rnp_output_t     keydata = NULL;
    rnp_key_handle_t key = NULL;
    uint32_t         flags = RNP_KEY_EXPORT_SUBKEYS;
    const uint8_t *  result = NULL;

    const char *uid = crypto_get_uid(stack, name, keypair_type);

    /* you may search for the key via userid, keyid, fingerprint, grip */
    if (rnp_locate_key(ffi, "userid", uid, &key) != RNP_SUCCESS || key == NULL) {
        return result;
    }

    if (!key) {
        return result;
    }

    /* create in-memory output structure to later use buffer */
    if (rnp_output_to_memory(&keydata, 0) != RNP_SUCCESS) {
        goto finish;
    }

    flags = flags | (key_type == KEY_PRIVATE ? RNP_KEY_EXPORT_SECRET : RNP_KEY_EXPORT_PUBLIC);
    if (rnp_key_export(key, keydata, flags) != RNP_SUCCESS) {
        goto finish;
    }

    /* get key's contents from the output structure */
    uint8_t *buf;
    size_t len;
    if (rnp_output_memory_get_buf(keydata, &buf, &len, false) != RNP_SUCCESS) {
        goto finish;
    }

    uint8_t *out = stack_alloc(stack, len);
    memcpy(out, buf, len);
    if (out_len != NULL) {
        *out_len = len;
    }
    result = out;

finish:
    rnp_key_handle_destroy(key);
    rnp_output_destroy(keydata);
    return result;
}

bool crypto_init(const char *dir, const char *pass) {
    keydir = dir;

    password = pass;

    /* initialize FFI object */
    if (rnp_ffi_create(&ffi, "GPG", "GPG") != RNP_SUCCESS) {
        return false;
    }
    return true;
}

void crypto_deinit() {
    rnp_ffi_destroy(ffi);
}

const char *crypto_get_uid(struct stack *stack, const char *name, enum keypair_type keypair_type) {
    const char *prefix = NULL;
    switch (keypair_type) {
    case KEYPAIR_USER:
        prefix = "user-";
        break;
    case KEYPAIR_SESSION:
    case KEYPAIR_SERVER:
        prefix = "";
        break;
    default:
        assert(false);
    }
    return stack_fmt(stack, "%s%s", prefix, name);
}

struct keypair_paths crypto_get_paths(struct stack *stack, const char *uid) {
    return (struct keypair_paths) {
        .pub = stack_fmt(stack, "%s/%s-pub.pgp", keydir, uid),
        .prv = stack_fmt(stack, "%s/%s-prv.pgp", keydir, uid),
    };
}


void crypto_generate_or_load_keypair(struct stack *stack,
                                     const char *name,
                                     enum keypair_type keypair_type) {
    const char *uid = crypto_get_uid(stack, name, keypair_type);
    struct keypair_paths paths = crypto_get_paths(stack, uid);
    if (!crypto_load_keypair(stack, paths)) {
        log_info("Generating new keypair for %s", name);
        crypto_generate_keypair(stack, uid, paths);
    }
}

int crypto_generate_keypair(struct stack *stack,
                            const char *uid,
                            struct keypair_paths paths) {
    rnp_output_t keyfile = NULL;
    char *       key_grips = NULL;
    int          result = 1;

    /* set password provider */
    if (rnp_ffi_set_pass_provider(ffi, example_pass_provider, NULL)) {
        goto finish;
    }

    const char *key_desc = stack_fmt(stack, CURVE_25519_KEY_DESC_FMT, uid);

    /* generate EDDSA/X25519 keypair */
    if (rnp_generate_key_json(ffi, key_desc, &key_grips) != RNP_SUCCESS) {
        log_error("failed to generate eddsa key");
        goto finish;
    }

    /* destroying key_grips buffer is our obligation */
    rnp_buffer_destroy(key_grips);
    key_grips = NULL;

    /* create file output object and save public keyring with generated keys, overwriting
     * previous file if any. You may use rnp_output_to_memory() here as well. */
    if (rnp_output_to_path(&keyfile, paths.pub) != RNP_SUCCESS) {
        log_error("failed to initialize %s writing", paths.pub);
        goto finish;
    }

    if (rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_PUBLIC_KEYS) != RNP_SUCCESS) {
        log_error("failed to save pubring");
        goto finish;
    }

    rnp_output_destroy(keyfile);
    keyfile = NULL;

    /* create file output object and save secret keyring with generated keys */
    if (rnp_output_to_path(&keyfile, paths.prv) != RNP_SUCCESS) {
        log_error("failed to initialize %s writing", paths.prv);
        goto finish;
    }

    if (rnp_save_keys(ffi, "GPG", keyfile, RNP_LOAD_SAVE_SECRET_KEYS) != RNP_SUCCESS) {
        log_error("failed to save secring");
        goto finish;
    }

    rnp_output_destroy(keyfile);
    keyfile = NULL;

    result = 0;
finish:
    rnp_buffer_destroy(key_grips);
    rnp_output_destroy(keyfile);
    return result;
}
