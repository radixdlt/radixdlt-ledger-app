#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "key_and_signatures.h"
#include "os_io_seproxyhal.h"
#include "stringify_bip32_path.h"
#include "common_macros.h"

#define KEY_SEED_BYTE_COUNT 32

static void get_key_seed(
    uint8_t* key_seed, 
    uint32_t *bip32path
) {

    BEGIN_TRY {
        TRY {
            io_seproxyhal_io_heartbeat();
            os_perso_derive_node_bip32(CX_CURVE_256K1, bip32path, 5, key_seed, NULL);
            io_seproxyhal_io_heartbeat();
        }
        CATCH_OTHER(e) {
            os_memset(key_seed, 0, KEY_SEED_BYTE_COUNT);
            switch (e) {
                case EXCEPTION_SECURITY: {
                    PRINTF("FAILED call 'os_perso_derive_node_bip32', error: 'EXCEPTION_SECURITY' (==%d)\n", e);
                    break;
                }
                default: {
                    PRINTF("FAILED call 'os_perso_derive_node_bip32', unknown error: %d\n", e);
                    break;
                }
            }
            // Rethrow so that program terminates
            THROW(e);
        }
        FINALLY {
        }
    }
    END_TRY;
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

/// Uncompresses/Decompresses/Decodes a compressed public key (33 bytes) into a uncompressed one (65 bytes).
void uncompress_public_key(
    uint8_t *compressed_pubkey,
    const size_t compressed_pubkey_len,
    uint8_t *uncompressed_pubkey_res,
    const size_t uncompressed_pubkey_len
) {
    // inspiration: https://bitcoin.stackexchange.com/a/86239/91730

    assert(compressed_pubkey_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    assert(uncompressed_pubkey_len >= PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);

    uint8_t x[FIELD_SCALAR_SIZE];
	uint8_t y[FIELD_SCALAR_SIZE];

    os_memcpy(x, compressed_pubkey + 1, FIELD_SCALAR_SIZE);
    cx_math_multm(y, x, x, MOD); // y == x^2 % p
    cx_math_multm(y, y, x, MOD); // y == x^3 % p
    cx_math_addm(y, y, secp256k1_b, MOD); // y == x^3 + 7 % p
    cx_math_powm(y, y, (unsigned char *)secp256k1_p_plus_1_div_4, FIELD_SCALAR_SIZE, MOD); // y == pow(y, (p+1) // 4) % p

    bool y_LSB = ReadBitAt(y[FIELD_SCALAR_SIZE-1], 0);
    if ((compressed_pubkey[0] == 0x02 && y_LSB) || (compressed_pubkey[0] == 0x03 && !y_LSB)) {
        cx_math_sub(y, secp256k1_P, y, FIELD_SCALAR_SIZE);
    }

    os_memset(uncompressed_pubkey_res, 0x04, 1);
    os_memcpy(uncompressed_pubkey_res + 1, x, FIELD_SCALAR_SIZE);
    os_memcpy(uncompressed_pubkey_res + 1 + FIELD_SCALAR_SIZE, y, FIELD_SCALAR_SIZE);
}

void compress_public_key(cx_ecfp_public_key_t *public_key) {
    // Uncompressed key has 0x04 + X (32 bytes) + Y (32 bytes).
    if (public_key->W_len != 65 || public_key->W[0] != 0x04) {
        PRINTF("compressPubKey: Input public key is incorrect\n");
        THROW(SW_INVALID_PARAM);
    }

    // check if Y is even or odd. Assuming big-endian, just check the last byte.
    if (public_key->W[64] % 2 == 0) {
        // Even
        public_key->W[0] = 0x02;
    } else {
        // Odd
        public_key->W[0] = 0x03;
    }

    public_key->W_len = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
}

static void format_signature_out(const uint8_t *signature)
{
    os_memset(G_io_apdu_buffer + 1, 0x00, 64);
    uint8_t xoffset = 4; //point to r value
    //copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33)
    {
        xlength = 32;
        xoffset++;
    }
    uint8_t offset = 0;
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
    offset += 32;
    xoffset += xlength + 2; //move over rvalue and TagLEn
    //copy s value
    xlength = signature[xoffset - 1];
    if (xlength == 33)
    {
        xlength = 32;
        xoffset++;
    }
    memmove(G_io_apdu_buffer + offset + 32 - xlength, signature + xoffset, xlength);
}

static int ecdsa_sign_hash(
    cx_ecfp_private_key_t *privateKey,  // might be NULL if you do 'verify'
    cx_ecfp_public_key_t *public_key,  // might be NULL if you do 'sign' instead of 'verify'
    const unsigned char *in, unsigned short inlen, 
    volatile unsigned char *out, unsigned short outlen,
    bool use_rfc6979_deterministic_signing
) {

    // ⚠️ IMPORTANT GUIDELINE
    // https://ledger.readthedocs.io/en/latest/additional/security_guidelines.html
    // https://ledger.readthedocs.io/en/latest/userspace/troubleshooting.html#error-handling


    volatile int result = 0;
    volatile unsigned int result_info = 0;
    
    volatile uint16_t error = 0;

    BEGIN_TRY {
        TRY {
                io_seproxyhal_io_heartbeat();
                result = cx_ecdsa_sign(
                    privateKey,
                    CX_LAST |
                        (use_rfc6979_deterministic_signing ? CX_RND_RFC6979
                                                           : CX_RND_TRNG),
                    CX_SHA256, in, inlen, (unsigned char *)out, outlen, (unsigned int *)&result_info);
                if (result_info & CX_ECCINFO_PARITY_ODD) {
                    out[0] |= 0x01;
                }
      
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY {
            /* Nothing to do, but make sure to zero out private key from calling function */
        }

    }
    END_TRY;
    if (error) {
        PRINTF("Error? code: %d\n", error);
    }

    return result;
}

// ======= HEADER FUNCTIONS ======================

int parse_bip32_path_from_apdu_command(
    uint8_t *data_buffer,
    uint32_t *output_bip32path,
    char *output_bip32String, // might be null
    unsigned short output_bip32_pathString_length
) {
    uint16_t byte_count_bip_component = 4;
    
    uint32_t bip32_path[5];

    // BIP32 Purpose
    uint32_t purpose = 44 | 0x80000000; // BIP44 - hardened
    bip32_path[0] = purpose;

    // BIP32 coin_type
    uint32_t coin_type = 536 | 0x80000000; // Radix - hardened
    bip32_path[1] = coin_type;

    uint32_t account = U4BE(data_buffer, 0 * byte_count_bip_component) | 0x80000000; // hardened 
    bip32_path[2] = account;

    uint32_t change = U4BE(data_buffer, 1 * byte_count_bip_component);
    if ((change != 0) && (change != 1)) {
        PRINTF("BIP32 'change' must be 0 or 1, but was: %u\n", change);
        THROW(SW_INVALID_PARAM);
    }
 
    bip32_path[3] = change;

    uint32_t address_index = U4BE(data_buffer, 2 * byte_count_bip_component);
    bip32_path[4] = address_index;

    os_memcpy(output_bip32path, bip32_path, 20);

    if (output_bip32String) {
        if (output_bip32_pathString_length != BIP32_PATH_STRING_MAX_LENGTH) {
            PRINTF("Wrong length of output_bip32_pathString_length, is: %d, but expected: %d\n", output_bip32_pathString_length, BIP32_PATH_STRING_MAX_LENGTH);
            THROW(SW_INVALID_PARAM);
        }
        char bip32_pathString_null_terminated[BIP32_PATH_STRING_MAX_LENGTH];
    	int length_of_bip32_string_path = stringify_bip32_path(
            output_bip32path,
            5,
            bip32_pathString_null_terminated
        );

        os_memset(output_bip32String, 0, BIP32_PATH_STRING_MAX_LENGTH);
    	os_memmove(output_bip32String, bip32_pathString_null_terminated, length_of_bip32_string_path);

        return length_of_bip32_string_path;
    } else {
        return 0;
    }
}

void derive_radix_key_pair(
    uint32_t *bip32path, 
    volatile cx_ecfp_public_key_t *public_key_nullable,
    volatile cx_ecfp_private_key_t *private_key_nullable
) {

    volatile cx_ecfp_public_key_t *public_key_local;
    volatile cx_ecfp_private_key_t private_key_local;
    volatile uint8_t key_seed[KEY_SEED_BYTE_COUNT];
    volatile uint16_t error = 0;

    BEGIN_TRY {
        TRY {
            get_key_seed((uint8_t *)key_seed, bip32path);
            cx_ecfp_init_private_key(CX_CURVE_SECP256K1, (uint8_t *)key_seed, 32, (cx_ecfp_private_key_t *)&private_key_local);
            cx_ecfp_init_public_key(CX_CURVE_SECP256K1, NULL, 0, (cx_ecfp_public_key_t *)public_key_local);
            cx_ecfp_generate_pair(CX_CURVE_SECP256K1,  (cx_ecfp_public_key_t *)public_key_local, (cx_ecfp_private_key_t *)&private_key_local, 1);

            if (public_key_nullable) {
                os_memcpy((cx_ecfp_public_key_t *)public_key_nullable, (cx_ecfp_public_key_t *)&public_key_local, sizeof(public_key_local));
            }
            
            if (private_key_nullable) {
                os_memcpy((cx_ecfp_private_key_t *)private_key_nullable, (cx_ecfp_private_key_t *)&private_key_local, sizeof(private_key_local));
            }
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY { 
            explicit_bzero((uint8_t *)key_seed, sizeof(KEY_SEED_BYTE_COUNT));
            explicit_bzero((cx_ecfp_private_key_t *)&private_key_local, sizeof(private_key_local));
        }
    }
    END_TRY;
    
    if (error) {
        PRINTF("Error? code: %d\n", error);
    }

    if (public_key_nullable) {
        compress_public_key((cx_ecfp_public_key_t *)public_key_nullable);
    }
 
}

size_t derive_sign_move_to_global_buffer(uint32_t *bip32path,
                                         const uint8_t *hash) {
    volatile cx_ecfp_public_key_t public_key;
    volatile cx_ecfp_private_key_t privateKey;
    derive_radix_key_pair(bip32path, &public_key, &privateKey);

    int over_estimated_DER_sig_length = 80;  // min length is 70.
    volatile uint8_t der_sig[over_estimated_DER_sig_length + 1];

    int actual_DER_sig_length = ecdsa_sign_hash(
        (cx_ecfp_private_key_t *)&privateKey,
        NULL,  // pubkey not needed for sign
        hash, 32, // in 
        der_sig, over_estimated_DER_sig_length, // out
        true  // use deterministic signing
    );

    // Ultra important step, MUST zero out the private, else sensitive information is leaked.
    explicit_bzero((cx_ecfp_private_key_t *)&privateKey, sizeof(cx_ecfp_private_key_t));

    int der_signature_length = der_sig[1] + 2;
    if (der_signature_length != actual_DER_sig_length) {
        FATAL_ERROR("LENGTH MISMATCH");
    }

    format_signature_out((uint8_t *)der_sig);
    
    return ECSDA_SIGNATURE_BYTE_COUNT;
}
