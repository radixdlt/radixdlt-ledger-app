#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"

static decryptDataContext_t *ctx = &global.decryptDataContext;

static void zero_out_ctx() {
    explicit_bzero(ctx->iv, IV_LEN);
    explicit_bzero(ctx->mac_data, MAC_LEN);
    explicit_bzero(ctx->mac_calculated, MAC_LEN);
    explicit_bzero(ctx->message_for_mac, MESSAGE_FOR_CALC_MAC_MAX_LEN);
    explicit_bzero(ctx->pointM, UNCOM_PUB_KEY_LEN);
    explicit_bzero(ctx->hashH, HASH512_LEN);
    explicit_bzero(ctx->cipher_to_plain_text, MAX_CIPHER_LENGTH);
}

void handleDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
    PRINTF("handleDecryptData\n");
    zero_out_ctx();

    *flags |= IO_ASYNCH_REPLY;

    // Length of JUST the cipher text, i.e. not the long ECIES enccrypted byte string containing `IV || PubKey || Cipher || MAC`, but rather
    // length of just the cipher, length as in byte count.
    size_t cipher_text_len = p1;
    assert(cipher_text_len <= MAX_CIPHER_LENGTH);
    
    // dataBuffer: BIPPath(12) || IV(16) || EphemeralPubKeyUncomp(65) || CipherText(P1) || MAC(32)  


    // READ BIP32Path (12 bytes)
    size_t offset = 0;
    size_t copy_byte_count = BIP32_PATH_LEN;
    uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    PRINTF("Reading BIP32 path\n");
    parse_bip32_path_from_apdu_command(
        dataBuffer + offset, bip32Path, G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH
    );
    offset += copy_byte_count;

    // READ IV (16 bytes)
    copy_byte_count = IV_LEN;
    os_memmove(ctx->iv, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

    // READ EphemeralPubKeyUncomp (65 bytes)
    copy_byte_count = UNCOM_PUB_KEY_LEN;
    os_memmove(ctx->pubkey_uncompressed, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

    // READ CipherText (`P1` bytes)
    copy_byte_count = cipher_text_len;
    os_memmove(ctx->cipher_to_plain_text, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;
    
    // READ MAC (32 bytes)
    copy_byte_count = MAC_LEN;
    os_memmove(ctx->mac_data, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

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

    size_t plain_text_len = do_decrypt(
        &privateKey, 
        cipher_text_len
    );

    PRINTF("Decryption finished.\n");
    PRINTF("Actual length of plain text: %d\n", plain_text_len);
    PRINTF("Plaintext: %.*s", plain_text_len, ctx->cipher_to_plain_text);

    os_memcpy(G_io_apdu_buffer, ctx->cipher_to_plain_text, plain_text_len);
    io_exchange_with_code(SW_OK, plain_text_len);
    PRINTF("\n\n***** DONE *****\n");
    ui_idle();
}