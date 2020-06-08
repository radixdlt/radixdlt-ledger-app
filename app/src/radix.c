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

void getKeySeed(
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

void compressPubKey(cx_ecfp_public_key_t *publicKey) {
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

void deriveRadixKeyPair(
    uint32_t *bip32path, 
    cx_ecfp_public_key_t *publicKey,
    cx_ecfp_private_key_t *privateKey_nullable
) {
    cx_ecfp_private_key_t privateKeyLocal;

    uint8_t keySeed[KEY_SEED_BYTE_COUNT];
    getKeySeed(keySeed, bip32path);
    cx_ecfp_init_private_key(CX_CURVE_SECP256K1, keySeed, 32, &privateKeyLocal);

    assert (publicKey);
    cx_ecfp_init_public_key(CX_CURVE_SECP256K1, NULL, 0, publicKey);
    cx_ecfp_generate_pair(CX_CURVE_SECP256K1, publicKey, &privateKeyLocal, 1);
    // PRINTF("Uncompressed public key:\n %.*H \n\n", publicKey->W_len, publicKey->W);

    compressPubKey(publicKey);

    os_memset(keySeed, 0, sizeof(keySeed));
    if (privateKey_nullable) { 
        // copy over local private key to passed in pointer, if not null
        os_memcpy(privateKey_nullable, &privateKeyLocal, sizeof(privateKeyLocal));
    }
    os_memset(&privateKeyLocal, 0, sizeof(privateKeyLocal));
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
    //    if (result_info & CX_ECCINFO_PARITY_ODD)
    //    {
    //        out[0] |= 0x01;
    //    }
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

size_t deriveSignRespond(
    uint32_t *bip32path, 
    const uint8_t *hash
) {

	cx_ecfp_public_key_t publicKey;
	cx_ecfp_private_key_t privateKey;
	deriveRadixKeyPair(bip32path, &publicKey, &privateKey);

    int over_estimated_DER_sig_length = 80; // min length is 70. 
    uint8_t der_sig[over_estimated_DER_sig_length];
    int actual_DER_sig_length = 0;

    BEGIN_TRY {
        TRY {
            // PRINTF("About to sign hash\n");
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
            // PRINTF("DER encoded signature has length: %d\n", actual_DER_sig_length);
            // PRINTF("DER encoded signature is: %.*H\n", actual_DER_sig_length, der_sig);
        }
        CATCH_OTHER(e) {
            // PRINTF("Failed to sign, got some error: %d\n, e");
            THROW(0x9988);
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

    os_memcpy(G_io_apdu_buffer, der_sig, actual_DER_sig_length);

    return actual_DER_sig_length;
}

void bin2hex(uint8_t *dst, uint64_t dstlen, uint8_t *data, uint64_t inlen) {
    if(dstlen < 2*inlen + 1)
        THROW(SW_INVALID_PARAM);
    static uint8_t const hex[] = "0123456789abcdef";
    for (uint64_t i = 0; i < inlen; i++) {
        dst[2 * i + 0] = hex[(data[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex[(data[i] >> 0) & 0x0F];
    }
    dst[2 * inlen] = '\0';
}

static uint8_t hexchar2bin (unsigned char c) {
    switch (c)
    {
        case '0': return 0x0;
        case '1': return 0x1;
        case '2': return 0x2;
        case '3': return 0x3;
        case '4': return 0x4;
        case '5': return 0x5;
        case '6': return 0x6;
        case '7': return 0x7;
        case '8': return 0x8;
        case '9': return 0x9;
        case 'a': case 'A': return 0xa;
        case 'b': case 'B': return 0xb;
        case 'c': case 'C': return 0xc;
        case 'd': case 'D': return 0xd;
        case 'e': case 'E': return 0xe;
        case 'f': case 'F': return 0xf;
    default:
        THROW(SW_INVALID_PARAM);
    }
}

// Given a hex string with numhexchar characters, convert it
// to byte sequence and place in "bin" (which must be allocated
// with at least numhexchar/2 bytes already).
void hex2bin(uint8_t *hexstr, unsigned numhexchars, uint8_t *bin) {
    if (numhexchars % 2 != 0 || numhexchars == 0)
        THROW(SW_INVALID_PARAM);

    unsigned hexstr_start = 0;
    if (hexstr[0] == '0' && (hexstr[1] == 'x' || hexstr[1] == 'X')) {
        hexstr_start += 2;
    }

    for (unsigned binidx = 0, idx = 0; idx < numhexchars; idx += 2, binidx++) {
        uint8_t msn = hexchar2bin(hexstr[idx+hexstr_start]);
        msn <<= 4;
        uint8_t lsn = hexchar2bin(hexstr[idx+hexstr_start+1]);
        bin[binidx] = msn | lsn;
    }
}

int bin64b2dec(uint8_t *dst, uint32_t dst_len, uint64_t n) {
    if (n == 0) {
        if (dst_len < 2)
            FAIL("Insufficient destination buffer length to represent 0");
        dst[0] = '0';
        dst[1] = '\0';
        return 1;
    }
    // determine final length
    uint32_t len = 0;
    for (uint64_t nn = n; nn != 0; nn /= 10) {
        len++;
    }

    if (dst_len < len+1)
        FAIL("Insufficient destination buffer length for decimal representation.");

    // write digits in big-endian order
    for (int i = len - 1; i >= 0; i--) {
        dst[i] = (n % 10) + '0';
        n /= 10;
    }
    dst[len] = '\0';
    return len;
}

// https://stackoverflow.com/a/32567419/2128804
int strncmp( const char * s1, const char * s2, size_t n )
{
    while ( n && *s1 && ( *s1 == *s2 ) ) {
        ++s1;
        ++s2;
        --n;
    }
    if ( n == 0 ) {
        return 0;
    } else {
        return ( *(unsigned char *)s1 - *(unsigned char *)s2 );
    }
}

// https://stackoverflow.com/a/1733294/2128804
size_t strlen(const char *str)
{
    const char *s;

    for (s = str; *s; ++s)
      ;
    return (s - str);
}

// copy a c-string (including the terminating '\0'.
char *strcpy(char *dst, const char *src)
{
    unsigned i = 0;
    if (src == NULL) {
        dst[i] = '\0';
        return dst;
    }

    while (src[i] != '\0') {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}