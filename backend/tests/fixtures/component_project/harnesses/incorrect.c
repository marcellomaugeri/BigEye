#include <stddef.h>
#include <stdint.h>

#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    (void)bigeye_parse(data, size, NULL);
    return 0;
}
