#include "TokenAmount.h"
#include <os.h>

void printTokenAmount(TokenAmount *tokenAmount) {
    const size_t max_length = (UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    char dec_string[max_length];
    to_string_uint256(tokenAmount, dec_string, max_length);
    PRINTF("%s", dec_string);
}