#include "uint256.h"
#include <stdbool.h>
#include <os.h>
#include "key_and_signatures.h"
#include "base_conversion.h"
#include "common_macros.h"

size_t to_string_uint256(
    uint256_t *uint256,
    char *outstr,
    const size_t outstr_length
) {
    assert(outstr_length == UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    return convert_byte_buffer_into_decimal(uint256->bytes, 32, outstr);
}
