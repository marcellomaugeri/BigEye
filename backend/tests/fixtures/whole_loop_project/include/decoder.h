#ifndef DECODER_H
#define DECODER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t kind;
    size_t payload_size;
    uint32_t checksum;
} DecoderRecord;

/*
 * Decode one record in the form KIND ':' PAYLOAD.
 *
 * Contract: output must not be NULL. Input may be NULL only when size is zero.
 * The return value is 1 for a decoded record, 0 for empty input, and -1 for a
 * malformed record.
 */
int decoder_decode(const uint8_t *input, size_t size, DecoderRecord *output);

#endif
