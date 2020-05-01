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

#define MAX_CHUNK_SIZE 256

typedef struct {
	uint8_t buf[MAX_CHUNK_SIZE]; // the buffer, the chunk of bytes
	uint32_t nextIdx, len; // next read into buf and len of buf.
	int hostBytesLeft;     // How many more bytes to be streamed from host.
} StreamData;


#define MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP 60

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t bip32PathString[BIP32_PATH_STRING_MAX_LENGTH]; // variable-length
	
    uint16_t atomByteCount;
    uint16_t atomByteCountParsed;

	// Array of memory offsets from start of Atom to particles with spin up,
	// and the byte count per particle, total 4 bytes, with max length of 60
	// particles => 240 bytes.
	OffsetInAtom offsetsOfParticlesWithSpinUp[MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP]; // variable-length
    uint8_t numberOfParticlesParsed;
    // The de-facto length of the array `offsetsOfParticlesWithSpinUp`, read from APDU instr
    uint8_t numberOfParticlesWithSpinUp;

	StreamData streamData;
	uint8_t hash[HASH256_BYTE_COUNT];

} signAtomContext_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	signAtomContext_t signAtomContext;
} commandContext;
extern commandContext global;