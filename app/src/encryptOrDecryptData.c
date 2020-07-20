#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"

static encryptDecryptDataContext_t *ctx = &global.encryptDecryptDataContext;

void handleEncryptOrDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
    //  PRINTF("Encrypt or decrypt! Cool!\n");
    // bool encrypt = p1 == 1;

    // if (encrypt) {
    //     PRINTF("Should encrypt\n");
    // size_t data_len = p1;
    // size_t iv_len = p2;
    // assert(iv_len == AES_BLOCKLEN);
    // size_t keyE_len = dataLength - data_len - iv_len;

    // // PRINTF("'data_len': %d\n'iv_len': %d\n'keyE_len': %d\n", data_len, iv_len, keyE_len);
    // // PRINTF("Whole 'databuffer' (length %d):\n", dataLength);
    // // PRINTF("%.*h", dataLength, dataBuffer);

    // size_t offset = 0;

    // uint8_t data[data_len];
    // os_memcpy(
    //     data, 
    //     dataBuffer + offset,
    //     data_len
    // );
    // offset += data_len;
    // PRINTF("Finished parsing 'data'\n");
    // PRINTF("%.*h\n", data_len, data);

    // uint8_t iv[iv_len];
    // os_memcpy(
    //     iv, 
    //     dataBuffer + offset,
    //     iv_len
    // );
    // offset += iv_len;
    // PRINTF("Finished parsing 'iv'\n");
    // PRINTF("%.*h\n", iv_len, iv);

    // uint8_t keyDataE[keyE_len];
    // os_memcpy(
    //     keyDataE, 
    //     dataBuffer + offset,
    //     keyE_len
    // );
    // offset += keyE_len;
    // PRINTF("Finished parsing 'keyDataE'\n");
    // PRINTF("%.*h\n", keyE_len, keyDataE);
  
    // assert(data_len % AES_BLOCKLEN == 0);
    // assert(keyE_len % AES_BLOCKLEN == 0);
    // struct AES_ctx aes_ctx;
    // AES_init_ctx_iv(&aes_ctx, keyDataE, iv);
    // // unsigned int data_out_len = data_len + (AES_BLOCKLEN - (data_len % AES_BLOCKLEN));
    // unsigned int data_out_len = 64;
    // PRINTF("Expected length of cipherText: %d\n", data_out_len);
    // uint8_t data_out[data_out_len];
    // unsigned int length_diff = data_out_len - data_len;
    // os_memset(data_out, 0x00, data_out_len);
    // os_memcpy(data_out + length_diff, data, data_len);

    // // more about padding: https://erev0s.com/blog/tiny-aes-cbc-mode-pkcs7-padding-written-c/
    // AES_CBC_encrypt_buffer(&aes_ctx, data_out, data_out_len);

    // PRINTF("Cipher text (length: %d)\n", data_out_len);
    // // , got length: %d\nCipher text:\n", data_len);
    // PRINTF("%.*h\n", data_out_len, data_out);



    PRINTF("Using AES256\n");
    uint8_t key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    uint8_t out[] = { 0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6,
                      0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d,
                      0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61,
                      0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b };


    uint8_t iv[]  = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    uint8_t in[]  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };
    struct AES_ctx ctx;

    PRINTF("AES_KEYLEN: %d\n", AES_KEYLEN);
    PRINTF("AES_keyExpSize: %d\n", AES_keyExpSize);
    assert(AES_KEYLEN == 32);
    assert(AES_keyExpSize == 240);

    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, in, 64);

    PRINTF("%.*h\n", 64, in);

    PRINTF("CBC encrypt: ");
    if (0 == memcmp((char*) out, (char*) in, 64)) {
        PRINTF("SUCCESS!\n");
    } else {
        PRINTF("FAILURE!\n");
    }

    os_memcpy(G_io_apdu_buffer, in, 64);
    io_exchange_with_code(SW_OK, 64);


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