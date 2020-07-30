#include "stdint.h"
#include "stddef.h"
#include "pkcs7_padding.h"
#include "aes.h"
#include "os.h"
#include "common_macros.h"

// Returns the actual size of the cipher text, or 0 if operation failed.
size_t crypt_encrypt(
    const uint8_t *iv,
    size_t iv_length,

    const uint8_t *data_to_encrypt,
    size_t data_to_encrypt_length,

    const uint8_t *key,
    size_t key_length,

    uint8_t *cipher_text_output,
    size_t cipher_text_output_max_size
) {

    int blocks = (data_to_encrypt_length / AES_BLOCKLEN) + 1; 
    // int blocksALTERNATIVE_SOLUTION = (data_to_encrypt_length / AES_BLOCKLEN) + 1 + (data_to_encrypt_length % AES_BLOCKLEN ? 1 : 0); 
    // int blocksALTERNATIVE_SOLUTION2 = (data_to_encrypt_length / AES_BLOCKLEN) + (data_to_encrypt_length % AES_BLOCKLEN ? 1 : 0); 

    int cipherText_len = blocks * AES_BLOCKLEN;
    assert(cipher_text_output_max_size >= cipherText_len);

    uint8_t cipherCBC[cipherText_len];

    os_memcpy(cipherCBC, data_to_encrypt, sizeof(cipherCBC));
    os_memset(cipherCBC + data_to_encrypt_length, 0x00, 1);

    PRINTF("AES-256-CBC encryption test\n");
    PRINTF("Adding PKCS7 padding:...");

    int padBytes = pkcs7_padding_pad_buffer(
        cipherCBC, 
        data_to_encrypt_length,
        sizeof(cipherCBC),
        AES_BLOCKLEN
    );

    if (padBytes == 0) {
        PRINTF("FAIL\n");
    } else {
        PRINTF("SUCCESS %d\n", padBytes);
    }

    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, key, iv);
    AES_CBC_encrypt_buffer(&aes_ctx, cipherCBC, sizeof(cipherCBC));

    PRINTF("Cipher text (length: %d)\n", sizeof(cipherCBC));
    PRINTF("%.*h\n", sizeof(cipherCBC), cipherCBC);
    assert(cipher_text_output_max_size >= sizeof(cipherCBC));
    os_memcpy(cipher_text_output, cipherCBC, sizeof(cipherCBC));
    return sizeof(cipherCBC);
}


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
        PRINTF("FAIL\n");
        return 0;
    } else {
        PRINTF("SUCCESS, plain text without padding is: %d\n", actual_data_length);
    }

    return actual_data_length;
}