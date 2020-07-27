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

static bool hmac256(
    const uint8_t* key,
    const size_t key_len,

    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* mac_out,
    const size_t mac_out_len
) {
    cx_hmac_sha256_t hmac256;
    cx_hmac_sha256_init(&hmac256, key, key_len);
    int res = cx_hmac(
        &hmac256, 
        CX_LAST | CX_NO_REINIT,
        data_in, data_in_len,
        mac_out, mac_out_len
    );

    if (res == 0) {
        return false; // failure
    }

    return true;
}

static bool calculateMAC(
    const uint8_t* iv,
    const size_t iv_len,

    const uint8_t* salt,
    const size_t salt_len,

    const uint8_t* ephemeralPublicKeyBytes,
    const size_t ephemeralPublicKeyBytes_len,

    const uint8_t* cipherText,
    const size_t cipherText_len,

    uint8_t* mac_out,
    const size_t mac_out_len
) {
    size_t message_len = iv_len + ephemeralPublicKeyBytes_len + cipherText_len;
    uint8_t message[message_len];
    size_t offset = 0;

    os_memcpy(message + offset, iv, iv_len);
    offset += iv_len;

    os_memcpy(message + offset, ephemeralPublicKeyBytes, ephemeralPublicKeyBytes_len);
    offset += ephemeralPublicKeyBytes_len;

    os_memcpy(message + offset, cipherText, cipherText_len);

    bool was_successful = hmac256(salt, salt_len, message, message_len, mac_out, mac_out_len);

    return was_successful;
}

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

    PRINTF("PointM: %.*h\n", UNCOM_PUB_KEY_LEN, ctx->pubkey_uncompressed);
       
    // 2. Use the X component of `pointM` and calculate the SHA512 `hashH`.
    // let hashH = RadixHash(unhashedData: pointM.x.asData, hashedBy: sha512TwiceHasher).asData
        // assert(hashH.length == byteCountHashH)
    PRINTF("EXPECTED sha512 twice hash: '8f4faa6c319cf556e94bf845a1a48089afce5a2ae42243d46cba29805f0ac4308d3e1667b63cb5db8ce6d5395df8b713cbe2f084a6973f4456413e4fcbe68b24'\n");
    uint8_t hashH[64];
    sha512Twice(ctx->pubkey_uncompressed + 1, 32, hashH, 64);
    PRINTF("hashH: %.*h\n", 64, hashH);
    os_memmove(plain_text_out, hashH, plain_text_len);
    return plain_text_len;
}