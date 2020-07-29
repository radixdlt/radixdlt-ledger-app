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

static decryptDataContext_t *ctx = &global.decryptDataContext;

static bool sha512Twice(
     const uint8_t *data_in, const size_t data_in_len,
     uint8_t *data_out, const size_t data_out_len
) {
        cx_sha512_t hasher;
    cx_sha512_init(&hasher);

      cx_hash(
          ((cx_hash_t *) (&hasher)),
              CX_LAST, 
              data_in, data_in_len,
              data_out,
              data_out_len
    );

    // Once again, since twice
    cx_sha512_init(&hasher);
    cx_hash(
        ((cx_hash_t *) (&hasher)),
        CX_LAST, 
        data_out, data_out_len,
        data_out,
        data_out_len
    );

}

int do_decrypt(
    cx_ecfp_private_key_t *privateKey,
    const uint8_t *cipher_text,
    const size_t cipher_text_len,

    uint8_t *plain_text_out,
    const size_t plain_text_len // MAX length in
) {

    PRINTF("Decrypting with private key: %.*h\n", privateKey->d_len, privateKey->d);

    PRINTF("IV: %.*h\n", IV_LEN, ctx->iv);
    PRINTF("MAC: %.*h\n", MAC_LEN, ctx->mac_data);
    PRINTF("Ephemeral PubKey Uncomp: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
    PRINTF("Cipher text to decrypt: %.*h\n", cipher_text_len, cipher_text);

    // 1. Do an EC point multiply with `privateKey` and ephemeral public key. Call it `pointM` 
    os_memcpy(ctx->pointM, ctx->pubkey_uncompressed, UNCOM_PUB_KEY_LEN);
    cx_ecfp_scalar_mult(
        CX_CURVE_256K1, 
        ctx->pointM, UNCOM_PUB_KEY_LEN, 
        privateKey->d, privateKey->d_len
    );

    PRINTF("PointM: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pointM);
       
    // 2. Use the X component of `pointM` and calculate the SHA512 `hashH`.
    sha512Twice(ctx->pointM + 1, 32, ctx->hashH, HASH512_LEN);

    PRINTF("hashH: %.*h\n", HASH512_LEN, ctx->hashH);

    size_t actual_message_for_mac_len = IV_LEN + COM_PUB_KEY_LEN + cipher_text_len;
    assert(actual_message_for_mac_len <= MESSAGE_FOR_CALC_MAC_MAX_LEN);

    cx_hmac_sha256_init(&(ctx->hmac), ctx->hashH + 32, 32);

    size_t msg_for_mac_offset = 0;
    size_t byte_count_to_copy = 0;
    
    byte_count_to_copy = IV_LEN;
    os_memcpy(
        ctx->message_for_mac + msg_for_mac_offset, 
        ctx->iv, 
        byte_count_to_copy
    );
    msg_for_mac_offset += byte_count_to_copy;

    uint8_t byte = 0x03;
    if ((*(ctx->pubkey_uncompressed + 64)) % 2 == 0) {
        byte = 0x02;
    }
    byte_count_to_copy = 1;
    os_memcpy(
        ctx->message_for_mac + msg_for_mac_offset, 
        &byte, 
        byte_count_to_copy
    );
    msg_for_mac_offset += byte_count_to_copy;

    byte_count_to_copy = 32;
    os_memcpy(
        ctx->message_for_mac + msg_for_mac_offset,
        ctx->pubkey_uncompressed + 1,
        byte_count_to_copy
    );
    msg_for_mac_offset += byte_count_to_copy;

    byte_count_to_copy = cipher_text_len;
    os_memcpy(
        ctx->message_for_mac + msg_for_mac_offset,
        cipher_text,
        byte_count_to_copy
    );
    msg_for_mac_offset += byte_count_to_copy;
    assert(msg_for_mac_offset == actual_message_for_mac_len)

    cx_hmac(
        (cx_hmac_t *)&(ctx->hmac), 
        CX_LAST, 
        ctx->message_for_mac, 
        actual_message_for_mac_len, 
        ctx->mac_calculated, 
        MAC_LEN
    );

    PRINTF("CALC mac: %.*h\n", MAC_LEN, ctx->mac_calculated);

    if (0 == memcmp(ctx->mac_calculated, ctx->mac_data, MAC_LEN)) {
        PRINTF("SUCCESS! MAC matches\n");
    } else {
        PRINTF("FAILURE! MAC mismatch\n");
	    return 0;
    }

    os_memcpy(plain_text_out, ctx->hashH, plain_text_len);
    return plain_text_len;
}