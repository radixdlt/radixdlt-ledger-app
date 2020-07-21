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
     PRINTF("Encrypt or decrypt! Cool!\n");

    size_t message_len_in = p1;
    size_t iv_len = p2;
    assert(iv_len == AES_BLOCKLEN);
    size_t keyE_len = dataLength - message_len_in - iv_len;

    // PRINTF("'data_len': %d\n'iv_len': %d\n'keyE_len': %d\n", data_len, iv_len, keyE_len);
    // PRINTF("Whole 'databuffer' (length %d):\n", dataLength);
    // PRINTF("%.*h", dataLength, dataBuffer);

    size_t offset = 0;

    uint8_t messageCBC[message_len_in];
    os_memcpy(
        messageCBC, 
        dataBuffer + offset,
        message_len_in
    );
    offset += message_len_in;
    PRINTF("Finished parsing 'data'\n");
    PRINTF("%.*h\n", message_len_in, messageCBC);

    uint8_t iv[iv_len];
    os_memcpy(
        iv, 
        dataBuffer + offset,
        iv_len
    );
    offset += iv_len;
    PRINTF("Finished parsing 'iv'\n");
    PRINTF("%.*h\n", iv_len, iv);

    uint8_t keyDataE[keyE_len];
    os_memcpy(
        keyDataE, 
        dataBuffer + offset,
        keyE_len
    );
    offset += keyE_len;
    PRINTF("Finished parsing 'keyDataE'\n");
    PRINTF("%.*h\n", keyE_len, keyDataE);





//Run AES-CBC encrypt test

    int blocks = (message_len_in / AES_BLOCKLEN) + 1; 
    int blocksALTERNATIVE_SOLUTION = (message_len_in / AES_BLOCKLEN) + 1 + (message_len_in % AES_BLOCKLEN ? 1 : 0); 
    int blocksALTERNATIVE_SOLUTION2 = (message_len_in / AES_BLOCKLEN) + (message_len_in % AES_BLOCKLEN ? 1 : 0); 

    int cipherText_len = blocks * AES_BLOCKLEN;
    uint8_t cipherCBC[cipherText_len];

    os_memcpy(cipherCBC, messageCBC, sizeof(cipherCBC));
    os_memset(cipherCBC + message_len_in, 0x00, 1);

    PRINTF("AES-256-CBC encryption test\n");
    PRINTF("Adding PKCS7 padding:...");

    int padBytes = pkcs7_padding_pad_buffer(
        cipherCBC, 
        message_len_in,
        sizeof(cipherCBC),
        AES_BLOCKLEN
    );

    if (padBytes == 0) {
        PRINTF("FAIL\n");
    } else {
        PRINTF("SUCCESS %d\n", padBytes);
    }

    struct AES_ctx aes_ctx;
    AES_init_ctx_iv(&aes_ctx, keyDataE, iv);
    AES_CBC_encrypt_buffer(&aes_ctx, cipherCBC, sizeof(cipherCBC));

    PRINTF("Cipher text (length: %d)\n", sizeof(cipherCBC));
    PRINTF("%.*h\n", sizeof(cipherCBC), cipherCBC);
    PLOC();
    os_memcpy(G_io_apdu_buffer, cipherCBC, sizeof(cipherCBC));
    PLOC();
    io_exchange_with_code(SW_OK, sizeof(cipherCBC));
    PLOC();

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