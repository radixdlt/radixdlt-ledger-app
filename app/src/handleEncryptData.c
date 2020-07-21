#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"

static encryptDataContext_t *ctx = &global.encryptDataContext;

void handleEncryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
     PRINTF("Encrypt data! Cool!\n");

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

    size_t data_out_len = IO_APDU_BUFFER_SIZE;
    uint8_t data_out[data_out_len];

    PRINTF("Calling ECIES encrypt\n");
    
    size_t length_of_output = ecies_encrypt_iv(
        iv, iv_len, 
        messageCBC, message_len_in, 
        data_out, data_out_len, 
        keyDataE, keyE_len
    );

    assert(length_of_output <= data_out_len);
    PRINTF("ECIES result (length=%d):\n", length_of_output);
    PRINTF("%.*h", length_of_output, data_out);
    os_memcpy(G_io_apdu_buffer, data_out, length_of_output);
    io_exchange_with_code(SW_OK, length_of_output);

}