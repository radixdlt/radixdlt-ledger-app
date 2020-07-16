#include "ecies.h"
#include "os.h"
#include "common_macros.h"
#include "key_and_signatures.h"
#include "stdint.h"

// int decode_public_point(
//     const uint8_t *public_key_bytes,
//     const size_t pk_byte_count
// ) {
//     cx_ecfp_public_key_t publicKey;
//     cx_ecfp_init_public_key(CX_CURVE_SECP256K1, public_key_bytes, public_key_bytes, &publicKey);
//     return false;
// }

bool sha512Twice(
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

bool ecies_encrypt(
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count
) {

    assert(pk_byte_count == PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);
    size_t fp_element_size = 32;

    // 1. `pointFromPubKey := decode(pubKey)`
    // 2. `ephemeralKeyPair := generateNewKeyPair()`
    volatile cx_ecfp_public_key_t ephemeralPublicKey;
    volatile cx_ecfp_private_key_t ephemeralPrivateKey;
    assert(generate_key_pair(&ephemeralPublicKey, &ephemeralPrivateKey));

    // 3. `pointM := pointFromPubKey * ephemeralKeyPair.privateKey`
    size_t pointM_len = 65;
    uint8_t pointM[pointM_len];
    pointM[0] = 0x04;
    os_memcpy(pointM + 1, uncompress_public_key_bytes,
              PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);

    cx_ecfp_scalar_mult(CX_CURVE_256K1, pointM,
                        pointM_len, ephemeralPrivateKey.d,
                        ephemeralPrivateKey.d_len);
    
    // 4. `hashH := sha512(sha512(pointM.x))`
    size_t hashH_len = 64;
    uint8_t hashH[hashH_len];
    sha512Twice(pointM + 1, fp_element_size,  // copy over `pointM.x` (32 bytes)
                hashH, hashH_len);

    // 5. `keyDataE := hashH[0..<32]`, `keyDataM := hashH[32..<64]`
    uint8_t keyDataE[fp_element_size];
    os_memcpy(keyDataE, hashH, fp_element_size);
    uint8_t keyDataM[fp_element_size];
    os_memcpy(keyDataM, hashH + fp_element_size, fp_element_size);

    // 6. `iv := generateBytes(count: 16)`
    size_t iv_len = 16;
    // uint8_t iv[iv_len];
    uint8_t iv[] = {0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef,
                    0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef};
    // cx_rng(iv, iv_len);

    // 7. Pad the input text to a multiple of 16 bytes, in accordance to PKCS7.
    // Encrypt the data with AES-256-CBC, using IV as initialization vector,
    // `keyDataE` as encryption key and the padded input text as payload.
    cx_aes_key_t keyE;
    cx_aes_init_key(keyDataE, fp_element_size, &keyE);

    // `crypt.encrypt(iv, data, keyE)`
    size_t cipherText_len = 32;
    uint8_t cipherText[cipherText_len];
    size_t length_from_crypt = cx_aes_iv(
        &keyE, 
        CX_ENCRYPT | 
        CX_PAD_ISO9797M1 // not sure if this or `CX_PAD_ISO9797M2` or `CX_PAD_NONE` or none.
        | CX_CHAIN_CBC, 
        iv, iv_len, data_in, data_in_len, cipherText,
              cipherText_len);

    assert(length_from_crypt == cipherText_len);


    // DELETE THIS
    assert(data_out_len >= cipherText_len);
    os_memcpy(data_out, cipherText, cipherText_len);


    return true;
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

