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

    int blocks = (data_to_decrypt_length / AES_BLOCKLEN) + 1; 
    // int blocksALTERNATIVE_SOLUTION = (data_to_encrypt_length / AES_BLOCKLEN) + 1 + (data_to_encrypt_length % AES_BLOCKLEN ? 1 : 0); 
    // int blocksALTERNATIVE_SOLUTION2 = (data_to_encrypt_length / AES_BLOCKLEN) + (data_to_encrypt_length % AES_BLOCKLEN ? 1 : 0); 

    int plain_text_output_len = blocks * AES_BLOCKLEN;
    assert(plain_text_output_max_size >= plain_text_output_len);

    uint8_t plainTextUTF8Encoded[plain_text_output_len];

    os_memcpy(plainTextUTF8Encoded, data_to_decrypt, sizeof(plainTextUTF8Encoded));
    os_memset(plainTextUTF8Encoded + data_to_decrypt_length, 0x00, 1);

    PRINTF("AES-256-CBC decryption test\n");
    PRINTF("Adding PKCS7 padding:...");

    int actual_data_length = pkcs7_padding_pad_buffer(
        plainTextUTF8Encoded, 
        data_to_decrypt_length,
        sizeof(plainTextUTF8Encoded),
        AES_BLOCKLEN
    );

    if (actual_data_length == 0) {
        PRINTF("FAIL\n");
    } else {
        PRINTF("SUCCESS %d\n", actual_data_length);
    }

    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, key, iv);
    AES_CBC_decrypt_buffer(&aes_ctx, plainTextUTF8Encoded, sizeof(plainTextUTF8Encoded));

    PRINTF("Plain text (UTF8-enc) (length: %d)\n", actual_data_length);
    PRINTF("%.*h\n", actual_data_length, plainTextUTF8Encoded);
    assert(plain_text_output_max_size >= actual_data_length);
    os_memcpy(plain_text_output, plainTextUTF8Encoded, actual_data_length);
    return actual_data_length;
}