#include "decoder.h"

#include <string.h>

#if defined(__clang__) || defined(__GNUC__)
#define DECODER_NOINLINE __attribute__((noinline))
#else
#define DECODER_NOINLINE
#endif

static volatile unsigned int path_marker = 0U;

static DECODER_NOINLINE void mark_kind_b(void) {
    path_marker ^= 0x42U;
}

static DECODER_NOINLINE void mark_kind_c(void) {
    path_marker ^= 0x43U;
}

static DECODER_NOINLINE uint32_t decode_payload(
    uint8_t kind, const uint8_t *payload, size_t payload_size
) {
    uint8_t decoded[8] = {0U};
    size_t copy_size = payload_size < sizeof(decoded) ? payload_size : sizeof(decoded);

    if (payload_size > sizeof(decoded) && (kind == (uint8_t)'B' || kind == (uint8_t)'C')) {
        if (kind == (uint8_t)'B') {
            mark_kind_b();
        } else {
            mark_kind_c();
        }
        /* Deliberate fixture defect: the copy is not bounded for these two kinds. */
        copy_size = payload_size;
    }
    memcpy(decoded, payload, copy_size);

    uint32_t checksum = 2166136261U;
    for (size_t index = 0U; index < sizeof(decoded); ++index) {
        checksum = (checksum ^ decoded[index]) * 16777619U;
    }
    return checksum;
}

int decoder_decode(const uint8_t *input, size_t size, DecoderRecord *output) {
    output->kind = 0U;
    output->payload_size = 0U;
    output->checksum = 0U;

    if (size == 0U) {
        return 0;
    }
    if (input == NULL || size < 2U || input[1] != (uint8_t)':') {
        return -1;
    }

    output->kind = input[0];
    output->payload_size = size - 2U;
    output->checksum = decode_payload(input[0], input + 2U, size - 2U);
    return 1;
}
