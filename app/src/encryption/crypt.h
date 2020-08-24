#include "stdint.h"

// Returns the actual size of the cipher text, or 0 if operation failed.
size_t crypt_decrypt(
    const uint8_t *iv,
    size_t iv_length,

    const uint8_t *data_to_decrypt,
    size_t data_to_decrypt_length,

    const uint8_t *key,
    size_t key_length,

    uint8_t *plain_text_output,
    size_t plain_text_output_max_size
);