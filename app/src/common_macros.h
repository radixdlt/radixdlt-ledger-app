#ifndef COMMONMACROS_H
#define COMMONMACROS_H


#include "stdint.h"
#include <seproxyhal_protocol.h>
#include <os_io_seproxyhal.h>

// These are the offsets of various parts of a request APDU packet. INS
// identifies the requested command (see above), and P1 and P2 are parameters
// to the command.
#define CLA          0xAA // Alexander Cyon (this Ledger app) and Alexander Wormbs (JS desktop wallet)
#define OFFSET_CLA   0x00
#define OFFSET_INS   0x01
#define OFFSET_P1    0x02
#define OFFSET_P2    0x03
#define OFFSET_LC    0x04
#define OFFSET_CDATA 0x05

// MACROS
#define PLOC() PRINTF("\n%s - %s:%d \n", __FILE__, __func__, __LINE__);
#define assert(x)      \
    if (x) {           \
    } else {           \
        FATAL_ERROR("Assertion failed\n"); \
    }

#define FATAL_ERROR(...)     \
    {                        \
        PLOC();              \
        PRINTF(__VA_ARGS__); \
        THROW(SW_FATAL_ERROR_INCORRECT_IMPLEMENTATION);       \
    }


// exception codes
#define SW_USER_REJECTED                        0x6985
#define SW_INVALID_MAC_CODE                     0x6986
#define SW_FATAL_ERROR_INCORRECT_IMPLEMENTATION 0x6B00
#define SW_INVALID_PARAM                        0x6B01
#define SW_INVALID_INSTRUCTION                  0x6D00
#define SW_INCORRECT_CLA                        0x6E00
#define SW_OK                                   0x9000

// FUNCTIONS
// macros for converting raw bytes to uint64_t
#define U8BE(buf, off) (((uint64_t)(U4BE(buf, off))     << 32) | ((uint64_t)(U4BE(buf, off + 4)) & 0xFFFFFFFF))
#define U8LE(buf, off) (((uint64_t)(U4LE(buf, off + 4)) << 32) | ((uint64_t)(U4LE(buf, off))     & 0xFFFFFFFF))

// Constants
#define PUBLIC_KEY_COMPRESSEED_BYTE_COUNT 33
#define PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT 64


#define BIP32_PATH_STRING_MAX_LENGTH 20 // assumed 

#define ECSDA_SIGNATURE_BYTE_COUNT 64

#define NUMBER_OF_BIP32_COMPONENTS_IN_PATH 5
#define MAX_CHUNK_SIZE 255 

// The biggest of a value split across chunks might be the `rri`
#define MAX_ATOM_SLICE_SIZE MAX_CHUNK_SIZE

#define HASH256_BYTE_COUNT 32

#define IV_LEN 16
#define MAC_LEN 32
#define HASH512_LEN 64
#define UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT 65
#define BIP32_PATH_LEN 12

#endif