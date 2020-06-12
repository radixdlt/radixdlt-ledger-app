#include "stdint.h"
#include <seproxyhal_protocol.h>
#include <os_io_seproxyhal.h>

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xAA // Alex and Alex
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

#define BIP32_PATH_STRING_MAX_LENGTH 20 // assumed 
// assuming a font size of 11 (`BAGL_FONT_OPEN_SANS_REGULAR_11px`)
#define DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE 12

#define ECSDA_SIGNATURE_BYTE_COUNT 64

// MACROS
#define PLOC() PRINTF("\n%s - %s:%d \n", __FILE__, __func__, __LINE__);
#define assert(x) \
    if (x) {} else { PLOC(); PRINTF("Assertion failed\n"); THROW (EXCEPTION); }
#define FAIL(x) \
    { \
        PLOC();\
        PRINTF("Radix ledger app failed: %s\n", x);\
        THROW(EXCEPTION); \
    }

#define FATAL_ERROR(...)     \
    {                        \
        PLOC();              \
        PRINTF(__VA_ARGS__); \
        THROW(0x9876);       \
    }

// Constants
#define SHA256_HASH_DIGEST_BYTE_COUNT 32
#define PUBLIC_KEY_COMPRESSEED_BYTE_COUNT 33

// exception codes
#define SW_DEVELOPER_ERR 0x6B00
#define SW_INVALID_PARAM 0x6B01
#define SW_IMPROPER_INIT 0x6B02
#define SW_USER_REJECTED 0x6985
#define SW_OK            0x9000

// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// FUNCTIONS

void parse_bip32_path_from_apdu_command(
    uint8_t *dataBuffer,
    uint32_t *output_bip32path,
    uint8_t *output_bip32String, // might be null
    unsigned short output_bip32PathString_length
);

// Convert un-compressed zilliqa public key to a compressed form.
void compress_public_key(cx_ecfp_public_key_t *publicKey);

// derive_radix_key_pair derives a key pair from a BIP32 path and the Ledger
// seed. Returns the public key and private key if not NULL.
void derive_radix_key_pair(
    uint32_t *bip32path, 
    cx_ecfp_public_key_t *publicKey,
    cx_ecfp_private_key_t *privateKey_nullable
);

size_t derive_sign_move_to_global_buffer(
    uint32_t *bip32path, 
    const uint8_t *hash
);
