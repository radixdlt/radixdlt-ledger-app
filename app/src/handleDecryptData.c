#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"
#include "key_and_signatures.h"

static decryptDataContext_t *ctx = &global.decryptDataContext;

void handleDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
    PRINTF("handleDecryptData\n");

    *flags |= IO_ASYNCH_REPLY;

    size_t encrypted_len = p1;
    assert(encrypted_len <= MAX_ENCRYPTED_LEN);
    
    // dataBuffer: BIPPath(12) || Encrypted(P1)
    // Encrypted: // IV(16) || 0x33 || PubKeyComp(33) || cipher_text_len(4) || cipher_text(cipher_text_len) || MAC(32)


    // READ BIP32Path (12 bytes)
    uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    PRINTF("Reading BIP32 path\n");
    parse_bip32_path_from_apdu_command(
        dataBuffer, bip32Path, G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH
    );
   
    // FINISHED PARSING INPUT
    PRINTF("deriving key from seed and BIP\n");
    int KEY_SEED_BYTE_COUNT = 32;
    volatile uint8_t keySeed[KEY_SEED_BYTE_COUNT];
    volatile uint16_t error = 0;
    volatile cx_ecfp_private_key_t privateKey;
    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1, bip32Path, 5, keySeed, NULL);
            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &privateKey);
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY { explicit_bzero(keySeed, KEY_SEED_BYTE_COUNT); }
    }
    END_TRY;

    if (error) {
        FATAL_ERROR("Error? code: %d\n", error);
    }

    // Read CipherText Length
    uint32_t cipher_text_length = U4BE(dataBuffer, BIP32_PATH_LEN + IV_LEN + 1 + PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    // PRINTF("Length of cipher text: %d\n", cipher_text_length);
    size_t message_for_mac_len = IV_LEN + PUBLIC_KEY_COMPRESSEED_BYTE_COUNT + cipher_text_length;
    uint8_t message_for_mac[message_for_mac_len];

    size_t plain_text_len = do_decrypt(
        &privateKey,
        message_for_mac,
        message_for_mac_len,
        dataBuffer + BIP32_PATH_LEN,
        encrypted_len
    );

    PRINTF("Decryption finished.\n");
    PRINTF("Actual length of plain text: %d\n", plain_text_len);
    PRINTF("Plaintext: '%.*s'\n", plain_text_len, dataBuffer + BIP32_PATH_LEN);
    os_memcpy(G_io_apdu_buffer, dataBuffer + BIP32_PATH_LEN, plain_text_len);

    io_exchange_with_code(SW_OK, plain_text_len);
    PRINTF("\n\n***** DONE *****\n");
}