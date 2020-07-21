#include "ecies.h"
#include "os.h"
#include "common_macros.h"
#include "key_and_signatures.h"
#include "stdint.h"
#include "crypt.h"
#include <stdio.h>
#include <inttypes.h>

// int decode_public_point(
//     const uint8_t *public_key_bytes,
//     const size_t pk_byte_count
// ) {
//     cx_ecfp_public_key_t publicKey;
//     cx_ecfp_init_public_key(CX_CURVE_SECP256K1, public_key_bytes, public_key_bytes, &publicKey);
//     return false;
// }

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

#define IV_LEN 16
#define MAC_LEN 32

size_t ecies_encrypt(
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count
) {
    // 6. `iv := generateBytes(count: 16)`
    size_t iv_len = IV_LEN;
    uint8_t iv[iv_len];
    // uint8_t iv[] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
    //                 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};

    cx_rng(iv, iv_len);
    return ecies_encrypt_iv(iv, iv_len, data_in, data_in_len, data_out, data_out_len, uncompress_public_key_bytes, pk_byte_count);
}

size_t ecies_encrypt_iv(
    const uint8_t* iv,
    const size_t iv_len, // for testing purposes
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count
) {
    assert(iv_len == IV_LEN);
    assert(pk_byte_count == PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);
    size_t fp_element_size = 32;

    // 1. `pointFromPubKey := decode(pubKey)`
    // 2. `ephemeralKeyPair := generateNewKeyPair()`
    volatile cx_ecfp_public_key_t ephemeralPublicKey;
    volatile cx_ecfp_private_key_t ephemeralPrivateKey;
    PLOC();
    assert(generate_key_pair(&ephemeralPublicKey, &ephemeralPrivateKey));
    PLOC();

    // 3. `pointM := pointFromPubKey * ephemeralKeyPair.privateKey`
    size_t pointM_len = 65;
    uint8_t pointM[pointM_len];
    pointM[0] = 0x04;
    os_memcpy(pointM + 1, uncompress_public_key_bytes,
              PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);

    PLOC();
    cx_ecfp_scalar_mult(CX_CURVE_256K1, pointM,
                        pointM_len, ephemeralPrivateKey.d,
                        ephemeralPrivateKey.d_len);
    PLOC();

    if (cx_ecfp_is_valid_point(CX_CURVE_256K1, pointM, pointM_len) != 1) {
        PRINTF("Invalid ECPoint\n");
        return 0;
    }
    
    // 4. `hashH := sha512(sha512(pointM.x))`
    size_t hashH_len = 64;
    uint8_t hashH[hashH_len];
    PLOC();
    sha512Twice(pointM + 1, fp_element_size,  // copy over `pointM.x` (32 bytes)
                hashH, hashH_len);
    PLOC();

    // 5. `keyDataE := hashH[0..<32]`, `keyDataM := hashH[32..<64]`
    size_t keyDataE_len = fp_element_size;
    uint8_t keyDataE[keyDataE_len];
    os_memcpy(keyDataE, hashH, keyDataE_len);
    size_t keyDataM_len = fp_element_size;
    uint8_t keyDataM[keyDataM_len];
    os_memcpy(keyDataM, hashH + keyDataE_len, keyDataM_len);

    PRINTF("iv: %.*h\n", iv_len, iv);
    PRINTF("keyE: %.*h\n", keyDataE_len, keyDataE);
    PRINTF("keyM: %.*h\n", keyDataM_len, keyDataM);

    // 6. Encrypt the data with AES-256-CBC, using IV as initialization vector,
    // `keyDataE` as encryption key and the padded input text as payload.
    size_t cipherText_length = 64;
    uint8_t cipherText[cipherText_length];

    size_t actual_cipherText_length = crypt_encrypt(
            iv, iv_len,
            data_in, data_in_len,
            keyDataE, keyDataE_len,
            cipherText, cipherText_length
    );

    if (actual_cipherText_length != cipherText_length) {
        PRINTF("Incorrect length of cipher text, expected: %d, but got: %d\n", cipherText_length, actual_cipherText_length);
        return 0;
    }

     PRINTF("encrypted (cipher): %.*h\n", actual_cipherText_length, cipherText);

    // 7. Calculate 32 byte MAC using keyDataM as salt and `IV + ephemeral.pub + cipherText` as data

    uint8_t macData[MAC_LEN];
    bool was_mac_successful = calculateMAC(
        iv, iv_len, 
        keyDataM, keyDataM_len,
        ephemeralPublicKey.W, ephemeralPublicKey.W_len,
        cipherText, actual_cipherText_length,
        macData, MAC_LEN
    );

    if (!was_mac_successful) {
        PRINTF("Mac failed");
        return 0;
    }

    PRINTF("mac: %.*h\n", MAC_LEN, macData);

    // 8. Concatenate: IV | ephemeral.pub.length | ephemeral.pub | cipherText.length | cipherText | MAC
    size_t offset = 0;
    size_t size_to_copy = 0;

    size_to_copy = iv_len;
    assert(data_out_len >= (offset + size_to_copy));
    os_memcpy(data_out + offset, iv, size_to_copy);
    offset += size_to_copy;

    size_to_copy = 1;
    assert(data_out_len >= (offset + size_to_copy));
    os_memset(data_out + offset, (uint8_t) ephemeralPublicKey.W_len, size_to_copy);
    offset += size_to_copy;

    size_to_copy = ephemeralPublicKey.W_len;
    assert(data_out_len >= (offset + size_to_copy));
    os_memcpy(data_out + offset, ephemeralPublicKey.W, size_to_copy);
    offset += size_to_copy;

    size_t encodedCipherText_length = 4; // four bytes
    size_to_copy = encodedCipherText_length;
    assert(data_out_len >= (offset + size_to_copy));
    uint32_t encodedCipherTextLengthValue = __builtin_bswap32((uint32_t) actual_cipherText_length);
    os_memcpy(data_out + offset, encodedCipherTextLengthValue, size_to_copy);
    offset += size_to_copy;

    size_to_copy = actual_cipherText_length;
    assert(data_out_len >= (offset + size_to_copy));
    os_memset(data_out + offset, cipherText, size_to_copy);
    offset += size_to_copy;


    size_to_copy = MAC_LEN;
    assert(data_out_len >= (offset + size_to_copy));
    os_memset(data_out + offset, macData, size_to_copy);
    offset += size_to_copy;

    PRINTF("ECIES encrypted bytes: %.*h\n", offset, data_out);


    return offset;
}



// bool encrypt(const uint8_t *data_in, const size_t data_in_len,
//              uint8_t *data_out,
//              size_t data_out_len,  // will be overwritten with actual length
//              cx_ecfp_public_key_t *public_key) {
//     return false;
// }

// bool encrypt(const uint8_t *data_in, const size_t data_in_len,
//             uint8_t *data_out,
//             size_t data_out_len,  // will be overwritten with actual length
//             uint32_t *bip32path
// ) {
    
//     volatile cx_ecfp_public_key_t publicKey;
//     derive_radix_key_pair(bip32path, &publicKey, NULL);
//     return 
// }


size_t ecies_decrypt_bipPath(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    uint32_t *bip32Path
) {
    // cx_ecfp_private_key_t privateKey

   
    volatile cx_ecfp_public_key_t publicKey;
    volatile cx_ecfp_private_key_t privateKey;
    derive_radix_key_pair(bip32Path, &publicKey, &privateKey);

    return ecies_decrypt(
        data_in, data_in_len,
        data_out, data_out_len,
        &privateKey
    );
}

size_t ecies_decrypt(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    cx_ecfp_private_key_t *privateKey
) {

    size_t fp_element_size = 32;

    // 1: Read the IV
    uint8_t iv[IV_LEN];
    size_t offset = 0;
    os_memcpy(iv, data_in + offset, IV_LEN);
    offset += IV_LEN;

    PLOC();

    // 2. Read `ephemeralPublicKey`
    cx_ecfp_public_key_t ephemeralPublicKey;
    // volatile cx_ecfp_private_key_t ephemeralPrivateKey;
    // assert(generate_key_pair(&ephemeralPublicKey, &ephemeralPrivateKey));
    uint8_t publicKeyLengthDataEncoded = 0;
    os_memset(publicKeyLengthDataEncoded, data_in + offset, 1);
    offset += 1;

    uint8_t ephemeralPublicKeyBytes[publicKeyLengthDataEncoded];
    os_memcpy(ephemeralPublicKeyBytes, data_in + offset, publicKeyLengthDataEncoded);
    offset += publicKeyLengthDataEncoded;

     PLOC();

    if (cx_ecfp_is_valid_point(CX_CURVE_256K1, ephemeralPublicKeyBytes, publicKeyLengthDataEncoded) != 1) {
        PRINTF("Invalid ECPoint\n");
        return 0;
    }

    PLOC();

    int public_key_init_result = cx_ecfp_init_public_key(
        CX_CURVE_256K1, ephemeralPublicKeyBytes, publicKeyLengthDataEncoded, &ephemeralPublicKey
    );

    PRINTF("public_key_init_result: %d\n", public_key_init_result);

    // size_t ephemeralPublicKeyPoint_len = 65;
    // uint8_t ephemeralPublicKeyPoint[ephemeralPublicKeyPoint_len];
    // os_memcpy(ephemeralPublicKeyPoint + 1, ephemeralPublicKey.W,
    //           ephemeralPublicKey.W_len);

    PLOC();
   
    // 3. Do an EC point multiply with `privateKey` and `ephemeralPublicKeyPoint`. This gives you a point M.
    // size_t pointM_len = 65;
    uint8_t pointM[ephemeralPublicKey.W_len];
    os_memcpy(pointM, ephemeralPublicKey.W, ephemeralPublicKey.W_len);
    // pointM[0] = 0x04;
    // os_memcpy(pointM + 1, uncompress_public_key_bytes,
            //   PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);

    PLOC();
    cx_ecfp_scalar_mult(
        CX_CURVE_256K1, 
        pointM, ephemeralPublicKey.W_len, 
        privateKey->d, privateKey->d_len
    );
    PLOC();

    if (cx_ecfp_is_valid_point(CX_CURVE_256K1, pointM, ephemeralPublicKey.W_len) != 1) {
        PRINTF("Invalid ECPoint\n");
        return 0;
    }
    PLOC();


    // 4. `hashH := sha512(sha512(pointM.x))`
    size_t hashH_len = 64;
    uint8_t hashH[hashH_len];
    PLOC();
    sha512Twice(pointM + 1, fp_element_size,  // copy over `pointM.x` (32 bytes)
                hashH, hashH_len);
    PLOC();

    // 5. `keyDataE := hashH[0..<32]`, `keyDataM := hashH[32..<64]`
    size_t keyDataE_len = fp_element_size;
    uint8_t keyDataE[keyDataE_len];
    os_memcpy(keyDataE, hashH, keyDataE_len);
    size_t keyDataM_len = fp_element_size;
    uint8_t keyDataM[keyDataM_len];
    os_memcpy(keyDataM, hashH + keyDataE_len, keyDataM_len);

    PRINTF("iv: %.*h\n", IV_LEN, iv);
    PRINTF("keyE: %.*h\n", keyDataE_len, keyDataE);
    PRINTF("keyM: %.*h\n", keyDataM_len, keyDataM);

    // 6. Read cipherText data
    size_t encodedCipherText_length = sizeof(uint32_t); // four bytes
    uint8_t cipherText_length_encoded[encodedCipherText_length];

    os_memcpy(cipherText_length_encoded, data_in + offset, encodedCipherText_length);
    offset += encodedCipherText_length;
    uint32_t cipherText_length = U4BE(cipherText_length_encoded, 0);

    uint8_t cipherText[cipherText_length];
    os_memcpy(cipherText, data_in + offset, cipherText_length);
    offset += cipherText_length;

    PRINTF("encrypted (cipher): %.*h\n", cipherText_length, cipherText);

    // 7. Read mac
    uint8_t parsed_macData[MAC_LEN];
    os_memcpy(parsed_macData, data_in + offset, MAC_LEN);
    offset += MAC_LEN;

    PRINTF("expected (parsed) mac: %.*h\n", MAC_LEN, parsed_macData);

    // 8. calculate MAC and compare MAC

    uint8_t compare_macData[MAC_LEN];
    bool was_mac_successful = calculateMAC(
        iv, IV_LEN, 
        keyDataM, keyDataM_len,
        ephemeralPublicKey.W, ephemeralPublicKey.W_len,
        cipherText, cipherText_length,
        compare_macData, MAC_LEN
    );

    if (!was_mac_successful) {
        PRINTF("Mac failed");
        return 0;
    }
   
    PRINTF("calculated mac: %.*h\n", MAC_LEN, compare_macData);

    if (0 == memcmp(compare_macData, parsed_macData, MAC_LEN)) {
        PRINTF("SUCCESS! Parsed (Expectd) MAC and calculated MAC matches! :D :D\n");
    } else {
        printf("FAILURE! MAC mismatch...\n");
    	return 0;
    }

      // 8. Decrypt the cipher text with AES-256-CBC, using IV as initialization vector, key_e as decryption key and the cipher text as payload. The output is the padded input text.
    size_t length_plaintext = cipherText_length; // plaintext should be shorter than cipher text, so use chiper text as an upperbound... // TODO calc this..
    uint8_t plainTextUTF8Encoded[length_plaintext];

    size_t actual_length_plaintext = crypt_decrypt(
        iv, IV_LEN, 
        cipherText, cipherText_length, 
        keyDataE, keyDataE_len, 
        plainTextUTF8Encoded, length_plaintext
    );

    PRINTF("ECIES decrypted plaintext (utf8 encoded): %.*h\n", actual_length_plaintext, plainTextUTF8Encoded);

    assert(data_out_len >= actual_length_plaintext);

    os_memcpy(data_out, plainTextUTF8Encoded, actual_length_plaintext);

    return actual_length_plaintext;
}