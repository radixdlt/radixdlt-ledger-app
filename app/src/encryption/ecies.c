#include "ecies.h"
#include "os.h"
#include "common_macros.h"
#include "key_and_signatures.h"
#include "stdint.h"
#include "crypt.h"
#include <stdio.h>
#include <inttypes.h>
#include <strings.h>

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

size_t ecies_decrypt_bipPath(
    const uint8_t* data_in,
    const size_t data_in_len,

    const uint8_t* ephemeralUncompressedPublicKeyBytes,
    const size_t ephemeral_public_key_uncompressed_len,

    uint8_t* data_out,
    size_t data_out_len,

    uint32_t *bip32Path
) {
    volatile cx_ecfp_public_key_t publicKey;
    volatile cx_ecfp_private_key_t privateKey;
    derive_radix_key_pair(bip32Path, &publicKey, &privateKey);

    return ecies_decrypt(
        data_in, data_in_len,
        ephemeralUncompressedPublicKeyBytes, ephemeral_public_key_uncompressed_len,
        data_out, data_out_len,
        &privateKey
    );
}

size_t ecies_decrypt(
    const uint8_t* data_in,
    const size_t data_in_len,

    const uint8_t* ephemeralUncompressedPublicKeyBytes,
    const size_t ephemeral_public_key_uncompressed_len,

    uint8_t* data_out,
    size_t data_out_len,

    cx_ecfp_private_key_t *privateKey
) {
    FATAL_ERROR("foobar");
    // assert(ephemeral_public_key_uncompressed_len == UNCOM_PUB_KEY_LEN);

    // // 1: Read the IV
    // size_t offset = 0;
    // os_memcpy(ctx->iv, data_in + offset, IV_LEN);
    // offset += IV_LEN;

    // // 2. Read `ephemeralPublicKey`

    // // VALIDATION ONLY  
    // cx_ecfp_public_key_t ephemeralPublicKey;
    // int actual_length_ephemeral_public_key_uncompressed_len = cx_ecfp_init_public_key(
    //     CX_CURVE_256K1, 
    //     ephemeralUncompressedPublicKeyBytes, 
    //     UNCOM_PUB_KEY_LEN, 
    //     &ephemeralPublicKey
    // );
    // assert(actual_length_ephemeral_public_key_uncompressed_len == ephemeral_public_key_uncompressed_len);

    // PLOC();
   
    // // 3. Do an EC point multiply with `privateKey` and `ephemeralPublicKeyPoint`. This gives you a point M.
    // // LAST CHECKPOINT ✅ ✅ ✅
    // os_memmove(ctx->pointM, ephemeralUncompressedPublicKeyBytes, ephemeral_public_key_uncompressed_len);

    // THROW(39203);

    // PLOC();
    // cx_ecfp_scalar_mult(
    //     CX_CURVE_256K1, 
    //     ctx->pointM, UNCOM_PUB_KEY_LEN, 
    //     privateKey->d, privateKey->d_len
    // );
    // PLOC();

    // int pointM_validation_res = cx_ecfp_is_valid_point(CX_CURVE_256K1, pointM, pointM_len);
    // PRINTF("pointM_validation_res: %d\n", pointM_validation_res);
    // // if ( != 1) {
    // //     PRINTF("Invalid ECPoint\n");
    // //     return 0;
    // // }
    // PLOC();

    // // 4. `hashH := sha512(sha512(pointM.x))`
    // size_t hashH_len = 64;
    // uint8_t hashH[hashH_len];
    // PLOC();
    // sha512Twice(pointM + 1, 32,  // copy over `pointM.x` (32 bytes)
    //             hashH, hashH_len);
    // PLOC();

    // // 5. `keyDataE := hashH[0..<32]`, `keyDataM := hashH[32..<64]`
    // size_t keyDataE_len = 32;
    // uint8_t keyDataE[keyDataE_len];
    // os_memcpy(keyDataE, hashH, keyDataE_len);
    // size_t keyDataM_len = 32;
    // uint8_t keyDataM[keyDataM_len];
    // os_memcpy(keyDataM, hashH + keyDataE_len, keyDataM_len);

    // PRINTF("iv: %.*h\n", IV_LEN, iv);
    // PRINTF("keyE: %.*h\n", keyDataE_len, keyDataE);
    // PRINTF("keyM: %.*h\n", keyDataM_len, keyDataM);

    // // 6. Read cipherText data
    // size_t encodedCipherText_length = sizeof(uint32_t); // four bytes
    // uint8_t cipherText_length_encoded[encodedCipherText_length];

    // os_memcpy(cipherText_length_encoded, data_in + offset, encodedCipherText_length);
    // offset += encodedCipherText_length;
    // uint32_t cipherText_length = U4BE(cipherText_length_encoded, 0);

    // uint8_t cipherText[cipherText_length];
    // os_memcpy(cipherText, data_in + offset, cipherText_length);
    // offset += cipherText_length;

    // PRINTF("encrypted (cipher): %.*h\n", cipherText_length, cipherText);


  

    // // 7. Read mac
    // uint8_t parsed_macData[MAC_LEN];
    // os_memcpy(parsed_macData, data_in + offset, MAC_LEN);
    // offset += MAC_LEN;

    // PRINTF("expected (parsed) mac: %.*h\n", MAC_LEN, parsed_macData);

    // // 8. calculate MAC and compare MAC

    // uint8_t compare_macData[MAC_LEN];
    // bool was_mac_successful = calculateMAC(
    //     iv, IV_LEN, 
    //     keyDataM, keyDataM_len,
    //     ephemeralPublicKey.W, ephemeralPublicKey.W_len,
    //     cipherText, cipherText_length,
    //     compare_macData, MAC_LEN
    // );

    // if (!was_mac_successful) {
    //     PRINTF("Mac failed");
    //     return 0;
    // }
   
    // PRINTF("calculated mac: %.*h\n", MAC_LEN, compare_macData);


   
    // if (os_memcmp(compare_macData, parsed_macData, 32)) {
    //     PRINTF("FAILURE! MAC mismatch...\n");
    // 	return 0;
    // }
    // PRINTF("SUCCESS! Parsed (Expectd) MAC and calculated MAC matches! :D :D\n");
     
    //   // 8. Decrypt the cipher text with AES-256-CBC, using IV as initialization vector, key_e as decryption key and the cipher text as payload. The output is the padded input text.
    // size_t length_plaintext = cipherText_length; // plaintext should be shorter than cipher text, so use chiper text as an upperbound... // TODO calc this..
    // uint8_t plainTextUTF8Encoded[length_plaintext];

    // size_t actual_length_plaintext = crypt_decrypt(
    //     iv, IV_LEN, 
    //     cipherText, cipherText_length, 
    //     keyDataE, keyDataE_len, 
    //     plainTextUTF8Encoded, length_plaintext
    // );

    // PRINTF("ECIES decrypted plaintext (utf8 encoded): %.*h\n", actual_length_plaintext, plainTextUTF8Encoded);

    // assert(data_out_len >= actual_length_plaintext);

    // os_memcpy(data_out, plainTextUTF8Encoded, actual_length_plaintext);

    // return actual_length_plaintext;
}