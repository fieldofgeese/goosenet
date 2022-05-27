#pragma once

#include "log.h"
#include <stdint.h>
#include <string.h>

#define GOOSE_MAGIC 0b10011001

struct __attribute__((packed)) header {
    uint8_t magic;
    uint16_t size; // Size of the payload
};

struct packet {
    const char *name;
    const uint8_t *data;
    uint16_t data_size;
};

static inline size_t payload_size(struct packet *p) {
    return (strlen(p->name)+1) + p->data_size;
}

static inline size_t packet_size(struct packet *p) {
    return sizeof(struct header) + payload_size(p);
}

static inline void packet_encode(struct packet *p, uint8_t *bytes) {
    struct header h = {
        .magic = GOOSE_MAGIC,
        .size = payload_size(p),
    };

    // Copy in header
    memcpy(bytes, &h, sizeof(struct header));
    bytes += sizeof(struct header);

    // Copy in name with NULL terminator
    size_t name_size = strlen(p->name) + 1;
    memcpy(bytes, p->name, name_size);
    bytes += name_size;

    // Copy data
    memcpy(bytes, p->data, p->data_size);
}

static inline int packet_decode(const uint8_t *bytes, const size_t size, struct packet *p) {
    struct header *h = (struct header *) bytes;
    if (h->magic != GOOSE_MAGIC) {
        log_error("Dropping packet, invalid magic!");
        return 1;
    } else if (h->size > size) {
        log_error("Dropping packet, we don't handle partial packets!");
        log_error("\theader size: %u", h->size);
        log_error("\tbytes size: %u", size);
        return 1;
    }
    bytes += sizeof(struct header);

    p->name = (const char *) bytes;
    size_t name_size = strlen(p->name) + 1;
    bytes += name_size;

    p->data = bytes;
    p->data_size = h->size - (uint16_t) name_size;

    return 0;
}
