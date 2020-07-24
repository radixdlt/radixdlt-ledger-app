#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"

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

    PRINTF("Reading BIP32 path\n");

    // READ BIP 32 path
    parse_bip32_path_from_apdu_command(
        dataBuffer, ctx->bip32Path, G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH
    );

    PRINTF("BIP 32 path:\n");
    PRINTF(G_ui_state.lower_line_long);
    int KEY_SEED_BYTE_COUNT = 32;
    volatile uint8_t keySeed[KEY_SEED_BYTE_COUNT];
       volatile uint16_t error = 0;
    PRINTF("deriving key from seed and BIP\n");
    volatile cx_ecfp_private_key_t privateKey;

    BEGIN_TRY {
        TRY {
            os_perso_derive_node_bip32(CX_CURVE_256K1, ctx->bip32Path, 5, keySeed, NULL);
            PRINTF("Finished deriving seed from BIP32\n");
            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &privateKey);
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY { explicit_bzero(keySeed, KEY_SEED_BYTE_COUNT); }
    }
    END_TRY;

    if (error) {
        PRINTF("Error? code: %d\n", error);
    }

    PRINTF("PrivateKey:");
    PRINTF("%.*h\n", privateKey.d_len, privateKey.d);

    // DataBuffer: bipPath[12] || cipherText[p1] 
    size_t cipherText_length = p1;
    PRINTF("Length of CipherText to decrypt: %d\n", cipherText_length);
    uint8_t cipherText[cipherText_length];
    os_memcpy(cipherText, dataBuffer + 12, cipherText_length);

    PRINTF("CipherText to decrypt:\n");
    PRINTF("%.*h\n", cipherText_length, cipherText);
    // use `cipherText_length` as upperbound, since we know plaintext will be shorter than cipherText.
    size_t plainText_length_upperBound = cipherText_length;
    uint8_t plainText[plainText_length_upperBound]; 

    PLOC();
    PRINTF("Decrypting ciphertext\n");

    size_t actual_plainText_length = ecies_decrypt(
        cipherText, cipherText_length, 
        plainText, plainText_length_upperBound,
        &privateKey
    );

    if (actual_plainText_length == 0) {
        PRINTF("Failed to ECIES decrypt cipher text, got length 0.\n");
        return;
    }

    PRINTF("Successfully ECIES decrypted cipher->plainText (length=%d):\n", actual_plainText_length);
    PRINTF("%.*h\n", actual_plainText_length, plainText);

    os_memcpy(G_io_apdu_buffer, plainText, actual_plainText_length);
    io_exchange_with_code(SW_OK, actual_plainText_length);
}