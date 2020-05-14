#include "UnsignedInteger256.h"
#include <stdbool.h>
#include <os.h>
#include "radix.h"
#include "base_conversion.h"

size_t to_string_uint256(
    UnsignedInteger256 *uint256,
    char *outstr,
    const size_t outstr_length
) {
    assert(outstr_length == UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    size_t de_facto_length = convertByteBufferIntoDigitsWithBase(uint256->bytes, 32, outstr, 10);
	outstr[de_facto_length] = '\0'; // NULL terminate
    return de_facto_length;
}
