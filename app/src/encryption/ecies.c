#include "ecies.h"
#include "os.h"
#include "common_macros.h"
#include "key_and_signatures.h"
#include "stdint.h"
#include "crypt.h"
#include <stdio.h>
#include <inttypes.h>
#include <strings.h>
#include "global_state.h"
#include "pkcs7_padding.h"
#include "aes.h"
#include "stddef.h"

static decryptDataContext_t *ctx = &global.decryptDataContext;


static void uncompress_and_init_pubkey(
    uint8_t *compressed_pubkey,
    const size_t compressed_pubkey_len,
    cx_ecfp_256_public_key_t *pubkey
) {
    uint8_t pubkey_uncompressed[UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT];
    uncompress_public_key(compressed_pubkey, compressed_pubkey_len, pubkey_uncompressed, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    cx_ecfp_init_public_key(
        CX_CURVE_256K1,
        pubkey_uncompressed, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT,
        pubkey
    );
}


static bool sha512Twice(
     const uint8_t *data_in, const size_t data_in_len,
     uint8_t *data_out, const size_t data_out_len
) {

    cx_sha512_init(&(ctx->hasher));
      cx_hash(
          ((cx_hash_t *) (&(ctx->hasher))),
              CX_LAST, 
              data_in, data_in_len,
              data_out,
              data_out_len
    );

    // Once again, since twice
    cx_sha512_init(&(ctx->hasher));
    cx_hash(
        ((cx_hash_t *) (&(ctx->hasher))),
        CX_LAST, 
        data_out, data_out_len,
        data_out,
        data_out_len
    );

}

int do_decrypt(
    cx_ecfp_private_key_t *privateKey,

    uint8_t *message_for_mac,
    size_t message_for_mac_len,

    uint8_t *encrypted, // IV(16) || 0x33 || PubKeyComp(33) || cipher_text_length(4) || cipher_text(cipher_text_length) || MAC(32)
    size_t encrypted_length
) {
    PRINTF("Decrypting\n");
    PRINTF("\nENCRYPTED: %.*h\n", encrypted_length, encrypted);

    size_t offset = 0;
    size_t copy_byte_count = 0;

     // READ IV (16 bytes)
    copy_byte_count = IV_LEN;
    os_memmove(ctx->iv, encrypted + offset, copy_byte_count);
    offset += copy_byte_count;

    // SKIP reading length of PubKeyComp, should be 33
    assert(encrypted[offset] == 33);
    offset += 1;

    // READ EphemeralPubKeyComp (33 bytes)
    copy_byte_count = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
    uncompress_and_init_pubkey(encrypted + offset, copy_byte_count, &(ctx->ephemeral_pubkey));
    offset += copy_byte_count;

    // Read CipherText Length
    uint32_t cipher_text_length = U4BE(encrypted, offset);
    PRINTF("Length of cipher text: %d\n", cipher_text_length);
    offset += 4; // length of cipher text is encoded as 4 bytes, hence `U4BE` above

    size_t offset_cipher_text = offset;
    offset += cipher_text_length;

    PRINTF("Cipher text to decrypt: %.*h\n", cipher_text_length, encrypted + offset_cipher_text);
    
    // READ MAC (32 bytes)
    copy_byte_count = MAC_LEN;
    os_memcpy(ctx->mac, encrypted + offset, copy_byte_count);
    offset += copy_byte_count;
    
    // 1. Do an EC point multiply with `privateKey` and ephemeral public key. Call it `pointM` 
    os_memcpy(ctx->pointM, ctx->ephemeral_pubkey.W, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    cx_ecfp_scalar_mult(
        CX_CURVE_256K1, 
        ctx->pointM, UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT, 
        privateKey->d, privateKey->d_len
    );

    // 2. Use the X component of `pointM` and calculate the SHA512 `hashH`.
    sha512Twice(ctx->pointM + 1, 32, ctx->hashH, HASH512_LEN);

    // Compare MACs
    offset = 0;
    copy_byte_count = IV_LEN;
    os_memcpy(message_for_mac + offset, ctx->iv, copy_byte_count);
    offset += copy_byte_count;
    copy_byte_count = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
    compress_public_key(&(ctx->ephemeral_pubkey));

    ctx->ephemeral_pubkey.W_len = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
    os_memcpy(message_for_mac + offset, ctx->ephemeral_pubkey.W, copy_byte_count);
    offset += copy_byte_count;

    copy_byte_count = cipher_text_length;
    os_memcpy(message_for_mac + offset, encrypted + offset_cipher_text, copy_byte_count);
    offset += copy_byte_count;
    assert(offset == message_for_mac_len);
    
    cx_hmac_sha256_init(&(ctx->hmac), ctx->hashH + 32, 32);
    cx_hmac(
        (cx_hmac_t *)&(ctx->hmac), 
        CX_LAST, 
        message_for_mac,
        message_for_mac_len, 
        ctx->calc_mac, 
        MAC_LEN
    );

    if (os_memcmp(ctx->calc_mac, ctx->mac, MAC_LEN) != 0) {
        PRINTF("FAILURE! MAC mismatch\n");
	    return 0;
    }

    AES_init_ctx_iv(&(ctx->aes_ctx), ctx->hashH, ctx->iv);
    AES_CBC_decrypt_buffer(&(ctx->aes_ctx), encrypted + offset_cipher_text, cipher_text_length);
    int actual_plain_text_length = pkcs7_padding_data_length(
        encrypted + offset_cipher_text, 
        cipher_text_length,
        AES_BLOCKLEN
    );
    if (actual_plain_text_length == 0) {
        PRINTF("FAIL\n");
        return 0;
    }


    os_memcpy(encrypted, encrypted + offset_cipher_text, actual_plain_text_length);
    os_memset(encrypted + actual_plain_text_length, 0x00, encrypted_length - actual_plain_text_length);
    PRINTF("Decrypted message: '%.*s'\n", actual_plain_text_length, encrypted);

    return actual_plain_text_length; 
}