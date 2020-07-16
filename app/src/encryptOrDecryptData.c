#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"

static encryptDecryptDataContext_t *ctx = &global.encryptDecryptDataContext;

void handleEncryptOrDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
     PRINTF("Encrypt or decrypt! Cool!\n");
    // bool encrypt = p1 == 1;

    // if (encrypt) {
    //     PRINTF("Should encrypt\n");
    size_t data_len = p1;
    size_t iv_len = p2;
    assert(iv_len == AES_BLOCKLEN);
    size_t keyE_len = dataLength - data_len - iv_len;

    PRINTF("'data_len': %d\n'iv_len': %d\n'keyE_len': %d\n", data_len, iv_len, keyE_len);

    PRINTF("Whole 'databuffer' (length %d):\n", dataLength);
    PRINTF("%.*H", dataLength, dataBuffer);

    size_t offset = 0;

    uint8_t data[data_len];
    os_memcpy(
        data, 
        dataBuffer + offset,
        data_len
    );
    offset += data_len;

    PLOC();
    PRINTF("Finished parsing 'data'\n");
    PRINTF("%.*H", data_len, data);

    // uint8_t uncompressed_public_key[PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT];
    // os_memcpy(uncompressed_public_key, dataBuffer + data_len, PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);












    uint8_t keyDataE[keyE_len];
    os_memcpy(
        keyDataE, 
        dataBuffer + offset,
        keyE_len
    );
    offset += keyE_len;
    PLOC();
    PRINTF("Finished parsing 'keyDataE'\n");
    PRINTF("%.*H\n", keyE_len, keyDataE);
  


    uint8_t iv[iv_len];
    os_memcpy(
        iv, 
        dataBuffer + offset,
        iv_len
    );
    offset += iv_len;

    PLOC();
    PRINTF("Finished parsing 'iv'\n");
    PRINTF("%.*H\n", iv_len, iv);

    PRINTF("Calling `AES_CBC_encrypt_buffer`");
// // fer( uint8_t *buffer,  size_t data_length, size_t buffer_size, uint8_t modulus );
//     if (!pkcs7_padding_pad_buffer(data, data_len, AES_BLOCKLEN)) {
//         FATAL_ERROR("FAILED TO PAD\n");
//     }

            
    // int valid_key_len_padded = pkcs7_padding_valid(keyDataE, keyE_len, sizeof(keyDataE), AES_BLOCKLEN);
    // printf("Is the pkcs7 padding valid, key = %d\n", valid_key_len_padded);
    // int valid2 = pkcs7_padding_valid( kexarray, klen, sizeof(kexarray), AES_BLOCKLEN );
    // printf("Is the pkcs7 padding valid  report = %d  |  key = %d\n", valid, valid2);


    assert(data_len % AES_BLOCKLEN == 0);
    assert(keyE_len % AES_BLOCKLEN == 0);
    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, keyDataE, iv);
    PRINTF("Finished init aes ctx\n");



    // more about padding: https://erev0s.com/blog/tiny-aes-cbc-mode-pkcs7-padding-written-c/
    AES_CBC_encrypt_buffer(&aes_ctx, data, data_len);

    PLOC();
    PRINTF("Finished encrypting\n");
    // , got length: %d\nCipher text:\n", data_len);
    PRINTF("%.*H\n", data_len, data);

    os_memcpy(G_io_apdu_buffer, data, data_len);
    io_exchange_with_code(SW_OK, data_len);


    // ecies_encrypt(
    //     data_to_encrypt, 
    //     data_len, 
    //     data_out, 
    //     data_out_len,
    //     uncompressed_public_key, 
    //     PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT
    // );










    // } else {
    //     PRINTF("Should decrypt\n");
    // }
}