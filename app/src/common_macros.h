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

#define ECSDA_SIGNATURE_BYTE_COUNT 64

#define NUMBER_OF_BIP32_COMPONENTS_IN_PATH 5
#define MAX_CHUNK_SIZE 255 

#define MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP 6
#define MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP 15 // 240/16, where 16 is size of `ParticleMetaData` and 240 is MAX_CHUNK_SIZE-2-12, where 2 is number of bytes to encode AtomSize and 12 is number of bytes for BIP32 path

// The biggest of a value split across chunks might be the `rri`
#define MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS (RADIX_RRI_MAX_BYTE_COUNT - 1)

#define HASH256_BYTE_COUNT 32

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