#include <stdbool.h>
#include <stdint.h>
#include <os.h>
#include <cx.h>
#include "radix.h"
#include "os_io_seproxyhal.h"
#include "stringify_bip32_path.h"

#define KEY_SEED_BYTE_COUNT 32

void parse_bip32_path_from_apdu_command(
    uint8_t *dataBuffer,
    uint32_t *output_bip32path,
    uint8_t *output_bip32String, // might be null
    unsigned short output_bip32PathString_length
) {
    // uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    // uint16_t expected_data_length = expected_number_of_bip32_compents * byte_count_bip_component;
    
    uint32_t bip32Path[5];

    // BIP32 Purpose
    uint32_t purpose = 44 | 0x80000000; // BIP44 - hardened
    bip32Path[0] = purpose;

    // BIP32 coin_type
    uint32_t coin_type = 536 | 0x80000000; // Radix - hardened
    bip32Path[1] = coin_type;

    uint32_t account = U4BE(dataBuffer, 0 * byte_count_bip_component) | 0x80000000; // hardened 
    bip32Path[2] = account;

    uint32_t change = U4BE(dataBuffer, 1 * byte_count_bip_component);
    if ((change != 0) && (change != 1)) {
        PRINTF("BIP32 'change' must be 0 or 1, but was: %u\n", change);
        THROW(SW_INVALID_PARAM);
    }
 
    bip32Path[3] = change;

    uint32_t address_index = U4BE(dataBuffer, 2 * byte_count_bip_component);
    bip32Path[4] = address_index;

    PRINTF("BIP32 path (uint32 array): %u,%u,%u,%u,%u\n", bip32Path[0], bip32Path[1], bip32Path[2], bip32Path[3], bip32Path[4]);

    os_memcpy(output_bip32path, bip32Path, 20);

    if (output_bip32String) {
        if (output_bip32PathString_length != BIP32_PATH_STRING_MAX_LENGTH) {
            PRINTF("Wrong length of output_bip32PathString_length, is: %d, but expected: %d\n", output_bip32PathString_length, BIP32_PATH_STRING_MAX_LENGTH);
            THROW(0x9320);
        }
        char bip32PathString_null_terminated[BIP32_PATH_STRING_MAX_LENGTH];
    	int length_of_bip32_string_path = stringify_bip32_path(
            output_bip32path,
            5,
            bip32PathString_null_terminated
        );

        os_memset(output_bip32String, 0, BIP32_PATH_STRING_MAX_LENGTH);
    	os_memmove(output_bip32String, bip32PathString_null_terminated, length_of_bip32_string_path);
    }
}

void get_key_seed(
    uint8_t* keySeed, 
    uint32_t *bip32path
) {

    BEGIN_TRY {
        TRY {
            io_seproxyhal_io_heartbeat();
            os_perso_derive_node_bip32(CX_CURVE_256K1, bip32path, 5, keySeed, NULL);
            io_seproxyhal_io_heartbeat();
        }
        CATCH_OTHER(e) {
            os_memset(keySeed, 0, KEY_SEED_BYTE_COUNT);
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

void compress_public_key(cx_ecfp_public_key_t *publicKey) {
    // Uncompressed key has 0x04 + X (32 bytes) + Y (32 bytes).
    if (publicKey->W_len != 65 || publicKey->W[0] != 0x04) {
        PRINTF("compressPubKey: Input public key is incorrect\n");
        THROW(SW_INVALID_PARAM);
    }

    // check if Y is even or odd. Assuming big-endian, just check the last byte.
    if (publicKey->W[64] % 2 == 0) {
        // Even
        publicKey->W[0] = 0x02;
    } else {
        // Odd
        publicKey->W[0] = 0x03;
    }

    publicKey->W_len = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
}

void derive_radix_key_pair(
    uint32_t *bip32path, 
    cx_ecfp_public_key_t *publicKey,
    cx_ecfp_private_key_t *privateKey_nullable
) {
    cx_ecfp_private_key_t privateKeyLocal;

    uint8_t keySeed[KEY_SEED_BYTE_COUNT];
    get_key_seed(keySeed, bip32path);
    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &privateKeyLocal);

    assert (publicKey);
    cx_ecfp_init_public_key(CX_CURVE_SECP256K1, NULL, 0, publicKey);
    cx_ecfp_generate_pair(CX_CURVE_SECP256K1, publicKey, &privateKeyLocal, 1);
    // PRINTF("Uncompressed public key:\n %.*H \n\n", publicKey->W_len, publicKey->W);

    compress_public_key(publicKey);

    os_memset(keySeed, 0, sizeof(keySeed));
    if (privateKey_nullable) { 
        // copy over local private key to passed in pointer, if not null
        os_memcpy(privateKey_nullable, &privateKeyLocal, sizeof(privateKeyLocal));
    }
    os_memset(&privateKeyLocal, 0, sizeof(privateKeyLocal));
}

void format_signature_out(const uint8_t *signature)
{
    os_memset(G_io_apdu_buffer + 1, 0x00, 64);
    uint8_t offset = 1;
    uint8_t xoffset = 4; //point to r value
    //copy r
    uint8_t xlength = signature[xoffset - 1];
    if (xlength == 33)
    {
        xlength = 32;
        xoffset++;
    }
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

static int ecdsa_sign_or_verify_hash(
        cx_ecfp_private_key_t *privateKey, // might be NULL if you do 'verify'
        cx_ecfp_public_key_t *publicKey, // might be NULL if you do 'sign' instead of 'verify'
        unsigned char sign_one_verify_zero,
        const unsigned char *in, unsigned short inlen,
        unsigned char *out, unsigned short outlen,
        unsigned char use_rfc6979_deterministic_signing
    ) {
    io_seproxyhal_io_heartbeat();
    int result = 0;
    if (sign_one_verify_zero)
    {
        unsigned int result_info = 0;
        result = cx_ecdsa_sign(
            privateKey,
            CX_LAST | (use_rfc6979_deterministic_signing ? CX_RND_RFC6979 : CX_RND_TRNG),
            CX_SHA256, 
            in, inlen, 
            out, outlen, 
            &result_info
        );
       if (result_info & CX_ECCINFO_PARITY_ODD)
       {
           out[0] |= 0x01;
       }
    }
    else
    {
        cx_ecdsa_verify(
            publicKey, 
            CX_LAST,
            CX_SHA256, 
            in, inlen, 
            out, outlen
        );
    }
    io_seproxyhal_io_heartbeat();
    return result;
}

size_t derive_sign_move_to_global_buffer(
    uint32_t *bip32path, 
    const uint8_t *hash
) {

	cx_ecfp_public_key_t publicKey;
	cx_ecfp_private_key_t privateKey;
	derive_radix_key_pair(bip32path, &publicKey, &privateKey);

    int over_estimated_DER_sig_length = 80; // min length is 70. 
    uint8_t der_sig[over_estimated_DER_sig_length];
    int actual_DER_sig_length = 0;

    BEGIN_TRY {
        TRY {
            actual_DER_sig_length = ecdsa_sign_or_verify_hash(
                &privateKey, 
                NULL, // pubkey not needed for sign
                1, // sign, not verify
                hash,
                32,
                der_sig,
                over_estimated_DER_sig_length,
                1 // use deterministic signing
            );
        }
        CATCH_OTHER(e) {
            PRINTF("Failed to sign, got some error: %d\n, e");
        }
        FINALLY {
        	os_memset(&privateKey, 0, sizeof(privateKey));
        }
    }
    END_TRY;

    int derSignatureLength = der_sig[1] + 2;
    if (derSignatureLength != actual_DER_sig_length) {
        FATAL_ERROR("LENGTH MISMATCH");
    }

    format_signature_out(der_sig);

    return ECSDA_SIGNATURE_BYTE_COUNT + 1;
}