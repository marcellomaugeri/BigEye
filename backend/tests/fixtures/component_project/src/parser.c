#include "parser.h"

int bigeye_parse(const uint8_t *input, size_t size, BigEyeRecord *output) {
    output->kind = 0U;
    output->payload_length = 0U;
    output->checksum = 0U;

    if (size == 0U) {
        return 0;
    }
    if (input == NULL || size < 2U) {
        return -1;
    }

    size_t payload_length = input[1];
    if (payload_length > size - 2U) {
        return -1;
    }
    output->kind = input[0];
    output->payload_length = input[1];
    for (size_t index = 0U; index < payload_length; ++index) {
        output->checksum = (output->checksum * 16777619U) ^ input[index + 2U];
    }
    return 1;
}
