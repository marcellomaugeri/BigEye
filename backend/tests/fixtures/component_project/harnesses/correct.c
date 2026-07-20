#include <stddef.h>
#include <stdint.h>

#include "parser.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    BigEyeRecord record = {0U, 0U, 0U};
    (void)bigeye_parse(data, size, &record);
    return 0;
}
