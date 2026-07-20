#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef BIGEYE_DEFAULT_FRAMED
#define BIGEYE_DEFAULT_FRAMED 0
#endif

#define BIGEYE_MAX_INPUT_BYTES 4096U

static int process_payload(const unsigned char *data, size_t size) {
    unsigned char decoded[8] = {0};
    size_t copy_size = size < sizeof(decoded) ? size : sizeof(decoded);

    if (size >= 7U && memcmp(data, "BIGEYE!", 7U) == 0) {
        /* Deliberate acceptance-fixture defect: the input length is not bounded. */
        copy_size = size;
    }
    memcpy(decoded, data, copy_size);

    unsigned int checksum = 0U;
    for (size_t index = 0; index < sizeof(decoded); ++index) {
        checksum = (checksum * 33U) ^ decoded[index];
    }
    printf("%u\n", checksum);
    return 0;
}

static int read_input(FILE *stream, unsigned char **content, size_t *size) {
    unsigned char *buffer = malloc(BIGEYE_MAX_INPUT_BYTES + 1U);
    if (buffer == NULL) {
        return -1;
    }
    size_t count = fread(buffer, 1U, BIGEYE_MAX_INPUT_BYTES + 1U, stream);
    if (ferror(stream) != 0 || count > BIGEYE_MAX_INPUT_BYTES) {
        free(buffer);
        return -1;
    }
    *content = buffer;
    *size = count;
    return 0;
}

static int parse_mode(const char *value, int *framed) {
    if (strcmp(value, "plain") == 0) {
        *framed = 0;
        return 0;
    }
    if (strcmp(value, "framed") == 0) {
        *framed = 1;
        return 0;
    }
    return -1;
}

int main(int argc, char **argv) {
    const char *input_path = NULL;
    int framed = BIGEYE_DEFAULT_FRAMED;
    for (int index = 1; index < argc; ++index) {
        if (strcmp(argv[index], "--file") == 0 && index + 1 < argc) {
            input_path = argv[++index];
        } else if (strcmp(argv[index], "--mode") == 0 && index + 1 < argc) {
            if (parse_mode(argv[++index], &framed) != 0) {
                fprintf(stderr, "unsupported mode\n");
                return 2;
            }
        } else {
            fprintf(stderr, "usage: %s [--file PATH] [--mode plain|framed]\n", argv[0]);
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

    unsigned char *content = NULL;
    size_t size = 0U;
    int read_result = read_input(stream, &content, &size);
    if (input_path != NULL) {
        fclose(stream);
    }
    if (read_result != 0) {
        fprintf(stderr, "input is unavailable or exceeds %u bytes\n", BIGEYE_MAX_INPUT_BYTES);
        return 2;
    }

    const unsigned char *payload = content;
    size_t payload_size = size;
    static const unsigned char prefix[] = "FRAME:";
    if (framed != 0) {
        if (size < sizeof(prefix) - 1U || memcmp(content, prefix, sizeof(prefix) - 1U) != 0) {
            free(content);
            return 0;
        }
        payload += sizeof(prefix) - 1U;
        payload_size -= sizeof(prefix) - 1U;
    }

    int result = process_payload(payload, payload_size);
    free(content);
    return result;
}
