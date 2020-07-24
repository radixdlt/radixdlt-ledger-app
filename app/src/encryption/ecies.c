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

#define IV_LEN 16
#define MAC_LEN 32

size_t ecies_decrypt_bipPath(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    uint32_t *bip32Path
) {
    volatile cx_ecfp_public_key_t publicKey;
    volatile cx_ecfp_private_key_t privateKey;
    derive_radix_key_pair(bip32Path, &publicKey, &privateKey);

    return ecies_decrypt(
        data_in, data_in_len,
        data_out, data_out_len,
        &privateKey
    );
}


/* ------------------------------------------------------------------------ */
/* ---                            secp256k1                             --- */
/* ------------------------------------------------------------------------ */

static unsigned char const C_cx_secp256k1_a[]  = { 
  // a:  0x00
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static unsigned char const C_cx_secp256k1_b[]  = { 
  //b:  0x07
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07};
static  unsigned char const C_cx_secp256k1_p []  = { 
  //p:  0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f};
static unsigned char const C_cx_secp256k1_Hp[]  = {
  //Hp: 0x000000000000000000000000000000000000000000000001000007a2000e90a1
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x07, 0xa2, 0x00, 0x0e, 0x90, 0xa1};
static unsigned char const C_cx_secp256k1_Gx[] = { 
  //Gx: 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
  0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07, 
  0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98};
static unsigned char const C_cx_secp256k1_Gy[] = { 
  //Gy:  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
  0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65, 0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8, 
  0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19, 0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8};
static unsigned char const C_cx_secp256k1_n[]  = { 
  //n: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 
  0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41};
static unsigned char const C_cx_secp256k1_Hn[]  = {
  //Hn:0x9d671cd581c69bc5e697f5e45bcd07c6741496c20e7cf878896cf21467d7d140
  0x9d, 0x67, 0x1c, 0xd5, 0x81, 0xc6, 0x9b, 0xc5, 0xe6, 0x97, 0xf5, 0xe4, 0x5b, 0xcd, 0x07, 0xc6,
  0x74, 0x14, 0x96, 0xc2, 0x0e, 0x7c, 0xf8, 0x78, 0x89, 0x6c, 0xf2, 0x14, 0x67, 0xd7, 0xd1, 0x40};
  
#define C_cx_secp256k1_h  1

cx_curve_weierstrass_t const C_cx_secp256k1 = { 
  CX_CURVE_SECP256K1,
  256, 32,
  (unsigned char*)C_cx_secp256k1_p,
  (unsigned char*)C_cx_secp256k1_Hp,
  (unsigned char*)C_cx_secp256k1_Gx, 
  (unsigned char*)C_cx_secp256k1_Gy, 
  (unsigned char*)C_cx_secp256k1_n, 
  (unsigned char*)C_cx_secp256k1_Hn, 
  C_cx_secp256k1_h,
  (unsigned char*)C_cx_secp256k1_a, 
  (unsigned char*)C_cx_secp256k1_b, 
};

// def decompress_pubkey(pk):
//     x = int.from_bytes(pk[1:33], byteorder='big')
//     y_sq = (pow(x, 3, p) + 7) % p
//     y = pow(y_sq, (p + 1) // 4, p)
//     if y % 2 != pk[0] % 2:
//         y = p - y
//     y = y.to_bytes(32, byteorder='big')
//     return b'\x04' + pk[1:33] + y
static size_t decompress_pubkey(
    const uint8_t *compressedPublicKey, const size_t compressedPublicKey_len,

    uint8_t *uncompressedPublicKey_out, const size_t uncompressedPublicKey_len
) {
   
    assert(compressedPublicKey_len == 33);
    assert(uncompressedPublicKey_len == 65);

    assert(*compressedPublicKey == 2 || *compressedPublicKey == 3);
    uint8_t sign_y = *(compressedPublicKey) - 2;


    cx_curve_weierstrass_t WIDE const *domain = &C_cx_secp256k1;


    
    size_t fp_scalar_size = domain->length;

    uint8_t x[fp_scalar_size];
    explicit_bzero(x, fp_scalar_size);
    os_memcpy(x, compressedPublicKey + 1, fp_scalar_size);

    uint8_t y_sq[fp_scalar_size];
    explicit_bzero(y_sq, fp_scalar_size);

  
    uint8_t tmpByte = 3;
    cx_math_powm(
        y_sq, // r = result
        x,  // a = first operand
        &tmpByte, // e = second operand
        1,  // length of `e`
        domain->p, // m = modulu
        fp_scalar_size // length of: `r`, `a`, `m`
    );
   
    uint8_t tmp_bytes[fp_scalar_size];
    // LAST CHECKPOINT ✅ ✅ ✅
    PRINTF("Zeroing out tmp_bytes\n");
    explicit_bzero(tmp_bytes, fp_scalar_size);
    THROW(39004);


    // tmp_bytes = (y_sq + 7) % p
    cx_math_addm( // r = a+b mod m
        tmp_bytes, // r = result
        y_sq, // a = first operand
        domain->b, // b = second operand
        domain->p, // m = modulo
        fp_scalar_size // len = length of `r`, `a`,`b`, `m`
    );
        // LAST KNOWN FAIL ❌ ❌ ❌
    os_memcpy(y_sq, tmp_bytes, fp_scalar_size); // y_sq = tmp_bytes
    explicit_bzero(tmp_bytes, fp_scalar_size);



    // os_memcpy(y_e, domain->p, fp_scalar_size); // NOW: y_e = p

    explicit_bzero(tmp_bytes, fp_scalar_size);
    os_memset(tmp_bytes, 0x01, 1);

    if (cx_math_cmp(tmp_bytes, domain->b, fp_scalar_size) >= 0) {
        PRINTF("tmp_bytes: %.*h\n", fp_scalar_size, tmp_bytes);
        PRINTF("domain->b: %.*h\n", fp_scalar_size, domain->b);
        FATAL_ERROR("Incorrectly set `tmp_bytes`, meant to be `1`, but was inverse.");
    }

    // tmpByte = 1;

    uint8_t y_e[fp_scalar_size]; // GOAL: y_e == (p + 1)//4
    explicit_bzero(y_e, fp_scalar_size);
    
    cx_math_add( //  r = a+b
        y_e,  // r = result
        domain->p, // a = first operand
        tmp_bytes, // b = second operand
        fp_scalar_size // length of `r`, `a`, `b`
    ); // NOW: y_e = p + 1
    
    uint8_t four_inv[fp_scalar_size]; // 1 // 4
    unsigned long int tmpLongInt = 4;
    cx_math_invintm(four_inv, &tmpLongInt, domain->p, fp_scalar_size);
    cx_math_multm(y_e, y_e, four_inv, domain->p, fp_scalar_size); // GOAL ACHIVED: y_e == (p + 1)//4

    uint8_t y[fp_scalar_size];
    cx_math_powm(y, y, y_e, sizeof(y_e), domain->p, fp_scalar_size); // y = pow(y_sq, y_e, p) = pow(y_sq, (p + 1) // 4, p)

    uint8_t y_mod_2[fp_scalar_size];
    os_memcpy(y_mod_2, y, fp_scalar_size);
    cx_math_modm(y_mod_2, fp_scalar_size, domain->p, sizeof(domain->p));

    if (*y_mod_2 != sign_y) {
        cx_math_sub(y, domain->p, y, fp_scalar_size);
    }

    size_t offset = 0;
    size_t length_of_value = 0;

    length_of_value = 1;
    os_memset(uncompressedPublicKey_out + offset, 0x04, length_of_value);
    offset += length_of_value;

    length_of_value = fp_scalar_size;
    os_memcpy(uncompressedPublicKey_out + offset, x, length_of_value);
    offset += length_of_value;

    length_of_value = fp_scalar_size;
    os_memcpy(uncompressedPublicKey_out + offset, y, length_of_value);
    offset += length_of_value;

    return offset; // 65 bytes
}

size_t ecies_decrypt(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    cx_ecfp_private_key_t *privateKey
) {

    // 1: Read the IV
    uint8_t iv[IV_LEN];
    size_t offset = 0;
    os_memcpy(iv, data_in + offset, IV_LEN);
    offset += IV_LEN;

    // 2. Read `ephemeralPublicKey`
    cx_ecfp_public_key_t ephemeralPublicKey;
    // volatile cx_ecfp_private_key_t ephemeralPrivateKey;
    // assert(generate_key_pair(&ephemeralPublicKey, &ephemeralPrivateKey));
    uint8_t encoded_length_of_compressed_public_key = *(data_in + offset); // ought to be 33?
    PRINTF("encoded_length_of_compressed_public_key: %d\n", encoded_length_of_compressed_public_key);
    offset += 1;

    uint8_t ephemeralCompressedPublicKeyBytes[encoded_length_of_compressed_public_key];
    os_memcpy(ephemeralCompressedPublicKeyBytes, data_in + offset, encoded_length_of_compressed_public_key);
    offset += encoded_length_of_compressed_public_key;
    PRINTF("ephemeralCompressedPublicKeyBytes:");
    PRINTF("%.*h\n", encoded_length_of_compressed_public_key, ephemeralCompressedPublicKeyBytes);
  
    size_t uncompressed_public_key_length = 65;
    uint8_t ephemeralUncompressedPublicKeyBytes[uncompressed_public_key_length];
    size_t actual_size_uncompKey = decompress_pubkey(
        ephemeralCompressedPublicKeyBytes, encoded_length_of_compressed_public_key,
        ephemeralUncompressedPublicKeyBytes, uncompressed_public_key_length
    );
    if (actual_size_uncompKey != uncompressed_public_key_length) {
        PRINTF("WARNING expected 'actual_size_uncompKey' to be 65, but was: %d\n", actual_size_uncompKey);
    }

    PRINTF("Uncompressed public key");
    PRINTF("%.*h\n", uncompressed_public_key_length, ephemeralUncompressedPublicKeyBytes);

    if (cx_ecfp_is_valid_point(CX_CURVE_256K1, ephemeralUncompressedPublicKeyBytes, uncompressed_public_key_length) != 1) {
        PRINTF("Invalid ECPoint\n");
        return 0;
    }


    int public_key_init_result = cx_ecfp_init_public_key(
        CX_CURVE_256K1, ephemeralCompressedPublicKeyBytes, encoded_length_of_compressed_public_key, &ephemeralPublicKey
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
    sha512Twice(pointM + 1, 32,  // copy over `pointM.x` (32 bytes)
                hashH, hashH_len);
    PLOC();

    // 5. `keyDataE := hashH[0..<32]`, `keyDataM := hashH[32..<64]`
    size_t keyDataE_len = 32;
    uint8_t keyDataE[keyDataE_len];
    os_memcpy(keyDataE, hashH, keyDataE_len);
    size_t keyDataM_len = 32;
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


   
    if (os_memcmp(compare_macData, parsed_macData, 32)) {
        PRINTF("FAILURE! MAC mismatch...\n");
    	return 0;
    }
    PRINTF("SUCCESS! Parsed (Expectd) MAC and calculated MAC matches! :D :D\n");
     
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