#include "common_macros.h"
#include "ecies.h"
#include "stdint.h"
#include "global_state.h"
#include "aes.h"
#include "ui.h"

static decryptDataContext_t *ctx = &global.decryptDataContext;

static int do_decrypt(
    cx_ecfp_private_key_t *privateKey,
    const uint8_t *cipher_text,
    const size_t cipher_text_len,

    uint8_t *plain_text_out,
    const size_t plain_text_len // MAX length in
) {

    PRINTF("Decrypting with private key: %.*h\n", privateKey->d_len, privateKey->d);

  
        
        // // 5. The first 32 bytes of H are called key_e and the last 32 bytes are called key_m.
        // let keyDataE = hashH.prefix(byteCountHashH/2)
        // let keyDataM = hashH.suffix(byteCountHashH/2)

    PRINTF("IV: %.*h\n", IV_LEN, ctx->iv);
    PRINTF("MAC: %.*h\n", MAC_LEN, ctx->mac_data);
    PRINTF("Ephemeral PubKey Uncomp: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
    PRINTF("Cipher text to decrypt: %.*h\n", cipher_text_len, cipher_text);

    // 1. Do an EC point multiply with `privateKey` and ephemeral public key. Call it `pointM` 
    // "PointM" is now in `ctx->pubkey_uncompressed`
    cx_ecfp_scalar_mult(
        CX_CURVE_256K1, 
        ctx->pubkey_uncompressed, UNCOM_PUB_KEY_LEN, 
        privateKey->d, privateKey->d_len
    );

    PRINTF("PointM: %.*h", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
       
        // 2. Use the X component of `pointM` and calculate the SHA512 `hashH`.
        // let hashH = RadixHash(unhashedData: pointM.x.asData, hashedBy: sha512TwiceHasher).asData
        // assert(hashH.length == byteCountHashH)

    os_memset(plain_text_out + 0, 0xde, 1);
    os_memset(plain_text_out + 1, 0xad, 1);
    os_memset(plain_text_out + 2, 0xbe, 1);
    os_memset(plain_text_out + 3, 0xef, 1);
    return 4;
}

#define BIP32_PATH_LEN 12
#define MAX_CIPHER_LENGTH (MAX_CHUNK_SIZE - BIP32_PATH_LEN - IV_LEN - UNCOM_PUB_KEY_LEN - MAC_LEN)

void handleDecryptData(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer,
    
    uint16_t dataLength, 
    unsigned int *flags,
    unsigned int *tx
 ) {
    PRINTF("handleDecryptData\n");

    // Length of JUST the cipher text, i.e. not the long ECIES enccrypted byte string containing `IV || PubKey || Cipher || MAC`, but rather
    // length of just the cipher, length as in byte count.
    size_t cipher_text_len = p1;
    assert(cipher_text_len <= MAX_CIPHER_LENGTH);
    
    // dataBuffer: BIPPath(12) || IV(16) || EphemeralPubKeyUncomp(65) || CipherText(P1) || MAC(32)  


    // READ BIP32Path (12 bytes)
    size_t offset = 0;
    size_t copy_byte_count = BIP32_PATH_LEN;
    PRINTF("Reading BIP32 path\n");
    parse_bip32_path_from_apdu_command(
        dataBuffer + offset, ctx->bip32Path, G_ui_state.lower_line_long,
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
    uint8_t cipher_text[cipher_text_len];
    copy_byte_count = cipher_text_len;
    os_memmove(cipher_text, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;
    
    // READ MAC (32 bytes)
    copy_byte_count = MAC_LEN;
    os_memmove(ctx->mac_data, dataBuffer + offset, copy_byte_count);
    offset += copy_byte_count;

    // FINISHED PARSING INPUT

    // Plain text will in fact be shorter than cipher, but we ignore that
    size_t plain_text_len = cipher_text_len;
    uint8_t plain_text[plain_text_len];


    PRINTF("deriving key from seed and BIP\n");
    int KEY_SEED_BYTE_COUNT = 32;
    volatile uint8_t keySeed[KEY_SEED_BYTE_COUNT];
    volatile uint16_t error = 0;
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
        FATAL_ERROR("Error? code: %d\n", error);
    }


    plain_text_len = do_decrypt(&privateKey, cipher_text, cipher_text_len, plain_text, plain_text_len);
    os_memmove(G_io_apdu_buffer, plain_text, plain_text_len);
    
    io_exchange_with_code(SW_OK, plain_text_len);
    PRINTF("\nPlain text: %.*h\nDONE.\n", plain_text_len, plain_text);
}