#ifndef BIGEYE_FIXTURE_PARSER_H
#define BIGEYE_FIXTURE_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t kind;
    uint8_t payload_length;
    uint32_t checksum;
} BigEyeRecord;

/* Contract: output must not be NULL. Input may be NULL only when size is zero. */
int bigeye_parse(const uint8_t *input, size_t size, BigEyeRecord *output);

#endif
