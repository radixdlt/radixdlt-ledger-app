#include "radix.h"

#define NUMBER_OF_BIP32_COMPONENTS_IN_PATH 5

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	
	// If set to `true` the Ledger will not generate a public key until user has confirmed on her Ledger
	// after confirmation the Ledger emits the pubkey in an APDU *response*. UX flow is now done iff
	// `requireConfirmationOfDisplayedPubKey` is set to `false`, otherwise a second confirmation is needed,
	bool requireConfirmationBeforeGeneration;

	// Disregarding of this value, a Public Key should already have been generated and sent back
	// via an APDU response, but if this bool is set to `true`, then said public key is displayed
	// on the Ledger and user needs to confirm on the Ledger that she acknowledges that she sees
	// the same public key in her wallet.
	bool requireConfirmationOfDisplayedPubKey;

	uint8_t displayIndex;
	// NUL-terminated strings for display
	uint8_t typeStr[40]; // variable-length
	uint8_t bip32PathString[BIP32_PATH_STRING_MAX_LENGTH]; // variable-length
	uint8_t fullStr[77]; // variable length
	// partialStr contains 12 characters of a longer string. This allows text
	// to be scrolled.
	uint8_t partialStr[13];
} getPublicKeyContext_t;

#define HASH256_BYTE_COUNT 32

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t bip32PathString[BIP32_PATH_STRING_MAX_LENGTH]; // variable-length
	uint8_t hash[HASH256_BYTE_COUNT];

	uint8_t hexHash[65]; // 2*sizeof(hash) + 1 for '\0'

	uint8_t displayIndex;
	// NUL-terminated strings for display
	uint8_t partialHashStr[13];
} signHashContext_t;

typedef struct {
	uint16_t startsAt;
	uint16_t byteCount;
} OffsetInAtom;

#define MAX_CHUNK_SIZE 255 // or should it be 256? then it wont fit in UInt8 which is inconvenient

#define MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP 60

// The biggest of a value split across chunks might be the `rri` which might be 68 bytes for the value
// and for key ("rri") is 3 bytes, lets take some security margin up to 80 bytes.
#define MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS 80

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t bip32PathString[BIP32_PATH_STRING_MAX_LENGTH]; // variable-length
	
    uint16_t atomByteCount;
    uint16_t atomByteCountParsed;

	cx_sha256_t hasher;

	// Only written to when the digest is finalized, after having received the
	// last byte of the atom
	uint8_t hash[HASH256_BYTE_COUNT];

	// Array of memory offsets from start of Atom to particles with spin up,
	// and the byte count per particle, total 4 bytes, with max length of 60
	// particles => 240 bytes.
	OffsetInAtom offsetsOfParticlesWithSpinUp[MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP]; // variable-length
    uint8_t numberOfParticlesParsed;
    // The de-facto length of the array `offsetsOfParticlesWithSpinUp`, read from APDU instr
    uint8_t numberOfParticlesWithSpinUp;

	// Sometimes a particle might span across multiple chunks and thus some relevant
	// info, such as `serializer` (type of Particle), `amount`, `recepientAddress`,
	// `rri` (RadixResourceIdentifier - which toke type) etc might get split.
	uint8_t cachedSmallBuffer[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];
	
	// Contains the number of cached bytes in the `cachedSmallBuffer`
	uint8_t numberOfCachedBytes;

	uint8_t chunkBuffer[MAX_CHUNK_SIZE];

} signAtomContext_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	signAtomContext_t signAtomContext;
} commandContext;
extern commandContext global;