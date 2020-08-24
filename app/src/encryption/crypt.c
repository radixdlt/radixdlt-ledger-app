#include "stdint.h"
#include "stddef.h"
#include "pkcs7_padding.h"
#include "aes.h"
#include "os.h"
#include "common_macros.h"

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
) {
    assert(plain_text_output_max_size >= data_to_decrypt_length);
    os_memcpy(plain_text_output, data_to_decrypt, data_to_decrypt_length);

    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, key, iv);
    AES_CBC_decrypt_buffer(&aes_ctx, plain_text_output, data_to_decrypt_length);

    int actual_data_length = pkcs7_padding_data_length(
        plain_text_output, 
        data_to_decrypt_length,
        AES_BLOCKLEN
    );

    if (actual_data_length == 0) {
        FATAL_ERROR("Failed to pad decrypted plaintext\n");
    } else {
        PRINTF("SUCCESS, plain text without padding is: %d\n", actual_data_length);
    }

    return actual_data_length;
}