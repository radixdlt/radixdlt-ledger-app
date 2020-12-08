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

// Use Radix's DER decode function for signing?
// (this shouldn't have any functional impact).
#define DER_DECODE_RADIX 0

#define BIP32_PATH_STRING_MAX_LENGTH 20 // assumed 

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

#define FATAL_ERROR(...) { PRINTF(__VA_ARGS__); THROW(0x9876); }

// Constants
#define SHA256_HASH_DIGEST_BYTE_COUNT 32
#define PUBLIC_KEY_COMPRESSEED_BYTE_COUNT 33
#define ECDSA_SIGNATURE_BYTE_COUNT 64

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
void compressPubKey(cx_ecfp_public_key_t *publicKey);

// pubkeyToRadixAddress converts a Ledger pubkey to a Radix wallet address.
void pubkeyToRadixAddress(uint8_t *dst, cx_ecfp_public_key_t *publicKey);

// deriveRadixKeyPair derives a key pair from a BIP32 path and the Ledger
// seed. Returns the public key and private key if not NULL.
void deriveRadixKeyPair(
    uint32_t *bip32path, 
    cx_ecfp_public_key_t *publicKey,
    cx_ecfp_private_key_t *privateKey_nullable
);

// deriveAndSign derives a secp256k1 private key from a BIP32 path and the
// Ledger seed, and uses it to produce a 64-byte ECDSA signature (DER decoded)
// of the provided 32-byte hash. The key is cleared from memory after signing.
void deriveAndSign(
    uint32_t *bip32path, 
    const uint8_t *hash,
    uint8_t *output_signature_R_S
);

// bin2hex converts binary to hex and appends a final NUL byte.
void bin2hex(uint8_t *dst, uint64_t dstlen, uint8_t *data, uint64_t inlen);

// bin64b2dec converts an unsigned integer to a decimal string and appends a
// final NUL byte. It returns the length of the string.
int bin64b2dec(uint8_t *dst, uint32_t dst_len, uint64_t n);

// Given a hex string with numhexchar characters, convert it
// to byte sequence and place in "bin" (which must be allocated
// with at least numhexchar/2 bytes already).
void hex2bin(uint8_t *hexstr, unsigned numhexchars, uint8_t *bin);

// Equivalent to what is there in stdlib.
int strncmp( const char * s1, const char * s2, size_t n );
// Equivalent to what is there in stdlib.
size_t strlen(const char *str);
// Equivalent to what is there in stdlib.
char* strcpy(char *dst, const char *src);