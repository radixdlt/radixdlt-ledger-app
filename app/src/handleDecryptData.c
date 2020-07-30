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

static uint8_t const secp256k1_P[] = { 
  //p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
};

// Secp256k1: (p + 1) // 4
const unsigned char secp256k1_p_plus_1_div_4[] = {
    0x3f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbf, 0xff, 0xff, 0x0c
};

static uint8_t const secp256k1_b[] = { 
  //b:  0x07
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07
};


#define FIELD_SCALAR_SIZE 32
#define MOD (unsigned char *)secp256k1_P, 32

#define ReadBitAt(data,y) ( (data>>y) & 1)      /** Return Data.Y value   **/

/// Decompresses a compressed public key (33 bytes) into a decompressed one (65 bytes).
void decompressPublicKey(
    uint8_t *compressed_pubkey,
    const size_t compressed_pubkey_len,

    uint8_t *uncompressed_pubkey_res,
    const size_t uncompressed_pubkey_len
) {
    // inspiration: https://bitcoin.stackexchange.com/a/86239/91730

    assert(compressed_pubkey_len == COM_PUB_KEY_LEN);
    assert(uncompressed_pubkey_len >= UNCOM_PUB_KEY_LEN);

    uint8_t x[FIELD_SCALAR_SIZE];
	uint8_t y[FIELD_SCALAR_SIZE];

    os_memcpy(x, compressed_pubkey + 1, FIELD_SCALAR_SIZE);
    cx_math_multm(y, x, x, MOD); // y == x^2 % p
    cx_math_multm(y, y, x, MOD); // y == x^3 % p
    cx_math_addm(y, y, secp256k1_b, MOD); // y == x^3 + 7 % p
    cx_math_powm(y, y, (unsigned char *)secp256k1_p_plus_1_div_4, FIELD_SCALAR_SIZE, MOD); // y == pow(y, (p+1) // 4) % p

    bool y_LSB = ReadBitAt(y[FIELD_SCALAR_SIZE-1], 0);
    if (compressed_pubkey[0] == 0x02 && y_LSB || compressed_pubkey[0] == 0x03 && !y_LSB) {
        cx_math_sub(y, secp256k1_P, y, FIELD_SCALAR_SIZE);
    }

    os_memset(uncompressed_pubkey_res, 0x04, 1);
    os_memcpy(uncompressed_pubkey_res + 1, x, FIELD_SCALAR_SIZE);
    os_memcpy(uncompressed_pubkey_res + 1 + FIELD_SCALAR_SIZE, y, FIELD_SCALAR_SIZE);
}

static uint8_t const test_1[] = { 
  //test compressed pubkey:  0229b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898
  // expected uncompressed pubkey: 0429b3e0919adc41a316aad4f41444d9bf3a9b639550f2aa735676ffff25ba3898d6881e81d2e0163348ff07b3a9a3968401572aa79c79e7edb522f41addc8e6ce
0x02, 0x29, 0xb3, 0xe0, 0x91, 0x9a, 0xdc, 0x41, 0xa3, 0x16, 0xaa, 0xd4, 0xf4, 0x14, 0x44, 0xd9, 0xbf, 0x3a, 0x9b, 0x63, 0x95, 0x50, 0xf2, 0xaa, 0x73, 0x56, 0x76, 0xff, 0xff, 0x25, 0xba, 0x38, 0x98
};

static uint8_t const test_2[] = {
    // compressed: 02f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f27
    // expected uncompressed: 04f15446771c5c585dd25d8d62df5195b77799aa8eac2f2196c54b73ca05f72f274d335b71c85e064f80191e1f7e2437afa676a3e2a5a5fafcf0d27940cd33e4b4
    0x02, 0xf1, 0x54, 0x46, 0x77, 0x1c, 0x5c, 0x58, 0x5d, 0xd2, 0x5d, 0x8d, 0x62, 0xdf, 0x51, 0x95, 0xb7, 0x77, 0x99, 0xaa, 0x8e, 0xac, 0x2f, 0x21, 0x96, 0xc5, 0x4b, 0x73, 0xca, 0x05, 0xf7, 0x2f, 0x27
};


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

    os_memcpy(ctx->pubkey_compressed, test_1, COM_PUB_KEY_LEN);
    decompressPublicKey(ctx->pubkey_compressed, COM_PUB_KEY_LEN, ctx->pubkey_uncompressed, UNCOM_PUB_KEY_LEN);
    PRINTF("Uncompressed result: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
    zero_out_ctx();

    os_memcpy(ctx->pubkey_compressed, test_2, COM_PUB_KEY_LEN);
    decompressPublicKey(ctx->pubkey_compressed, COM_PUB_KEY_LEN, ctx->pubkey_uncompressed, UNCOM_PUB_KEY_LEN);
    PRINTF("Uncompressed result: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
    zero_out_ctx();

    FATAL_ERROR("killing program now\n");

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