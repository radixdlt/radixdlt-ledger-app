#include "token_amount.h"
#include <os.h>

void print_token_amount(token_amount_t *token_amount) {
    const size_t max_length = (UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    char dec_string[max_length];
    to_string_uint256(token_amount, dec_string, max_length);
    PRINTF("%s", dec_string);
}