#include "key_and_signatures.h"
#include "Transfer.h"
#include "common_macros.h"
#include "ParticleMetaData.h"
#include "RadixParticleTypes.h"

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    bool requireConfirmationOfDisplayedPubKey;
} getPublicKeyContext_t;

typedef struct {
    uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    bool requireConfirmationOfAddress;
    uint8_t radixUniverseMagicByte;
} generateRadixAddressContext_t;

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t hash[HASH256_BYTE_COUNT];
} signHashContext_t;

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	
    uint16_t atomByteCount;
    uint16_t atomByteCountParsed;

	cx_sha256_t hasher;

	// Only written to when the digest is finalized, after having received the
	// last byte of the atom
	uint8_t hash[HASH256_BYTE_COUNT];

	// Array of memory offsets from start of Atom to particles with spin up,
	// and the byte count per particle, total 16 bytes, with max length of 15
	// particles => 240 bytes.
	ParticleMetaData metaDataAboutParticles[MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP]; // variable-length

    // The de-facto length of the array `offsetsOfParticlesWithSpinUp`, read from APDU instr
    uint8_t numberOfParticlesWithSpinUp;

	uint8_t numberOfNonTransferrableTokensParticlesIdentified;
    uint8_t numberOfTransferrableTokensParticlesParsed;

    uint8_t numberOfTransfersToNotMyAddress;
	uint8_t indiciesTransfersToNotMyAddress[MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP];

	uint8_t numberOfTransfersToNotMyAddressApproved;

	// This might only contains `MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP` many Non-TTP particles, if the number
	// of TTP particles is 0....
	RadixParticleTypes nonTransferrableTokensParticlesIdentified[MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP];

	// The number of cached bytes from last chunk, bound by `MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS`
	uint8_t numberOfCachedBytes;

	// Sometimes a particle might span across multiple chunks and thus some relevant
	// info, such as `serializer` (type of Particle), `amount`, `recepientAddress`,
	// `rri` (RadixResourceIdentifier - which toke type) etc might get split. This will
	// be "cached"/"carried over" to the next chunk, and should be copied over to
	// the beginning of this atomSlice buffer in between chunk parsing. We must also set
	// `numberOfCachedBytes`
   	uint8_t atomSlice[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE];

	// A temporary value helping construction of a Transfer
	RadixAddress parsedAddressInTransfer;

	// A temporary value helping construction of a Transfer
	TokenAmount parsedAmountInTransfer;

	// A temporary value helping construction of a Transfer
	bool hasConfirmedSerializerOfTransferrableTokensParticle;

	// At max all particles with spin up are transferrableTokensParticles that we
	// need to parse into transfers.
	Transfer transfers[MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP];
} signAtomContext_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    generateRadixAddressContext_t generateRadixAddressContext;
    getPublicKeyContext_t getPublicKeyContext;
    signHashContext_t signHashContext;
    signAtomContext_t signAtomContext;
} commandContext;
extern commandContext global;