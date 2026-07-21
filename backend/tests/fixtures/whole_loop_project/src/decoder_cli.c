#include "decoder.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_INPUT_BYTES 4096U

static int read_all(FILE *stream, uint8_t **content, size_t *size) {
    uint8_t *buffer = malloc(MAX_INPUT_BYTES + 1U);
    if (buffer == NULL) {
        return -1;
    }
    size_t count = fread(buffer, 1U, MAX_INPUT_BYTES + 1U, stream);
    if (ferror(stream) != 0 || count > MAX_INPUT_BYTES) {
        free(buffer);
        return -1;
    }
    *content = buffer;
    *size = count;
    return 0;
}

int main(int argc, char **argv) {
    const char *input_path = NULL;
    int framed = 0;
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--file") == 0 && index + 1 < argc) {
            input_path = argv[++index];
        } else if (strcmp(argv[index], "--framed") == 0) {
            framed = 1;
        } else {
            fprintf(stderr, "usage: %s [--file PATH] [--framed]\n", argv[0]);
            return 2;
        }
    }

    FILE *stream = stdin;
    if (input_path != NULL) {
        stream = fopen(input_path, "rb");
        if (stream == NULL) {
            fprintf(stderr, "cannot open input: %s\n", strerror(errno));
            return 2;
        }
    }

    uint8_t *content = NULL;
    size_t size = 0U;
    int read_result = read_all(stream, &content, &size);
    if (input_path != NULL) {
        fclose(stream);
    }
    if (read_result != 0) {
        fprintf(stderr, "input is unavailable or too large\n");
        return 2;
    }

    const uint8_t *record = content;
    size_t record_size = size;
    static const uint8_t prefix[] = "FRAME:";
    if (framed != 0) {
        if (size < sizeof(prefix) - 1U || memcmp(content, prefix, sizeof(prefix) - 1U) != 0) {
            free(content);
            return 0;
        }
        record += sizeof(prefix) - 1U;
        record_size -= sizeof(prefix) - 1U;
    }

    DecoderRecord output = {0U, 0U, 0U};
    int decoded = decoder_decode(record, record_size, &output);
    if (decoded > 0) {
        printf("%u %zu %u\n", (unsigned int)output.kind, output.payload_size, output.checksum);
    }
    free(content);
    return decoded < 0 ? 1 : 0;
}
