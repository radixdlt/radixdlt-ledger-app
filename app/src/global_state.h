#include "key_and_signatures.h"
#include "Transfer.h"
#include "common_macros.h"
#include "ParticleMetaData.h"
#include "RadixParticleTypes.h"

#define IV_LEN 16
#define MAC_LEN 32
#define ECIES_KEY_DATA_PART_LEN 32
#define HASH512_LEN 64
#define UNCOM_PUB_KEY_LEN 65
#define COM_PUB_KEY_LEN 33
#define BIP32_PATH_LEN 12
#define MAX_CIPHER_LENGTH (MAX_CHUNK_SIZE - BIP32_PATH_LEN - IV_LEN - UNCOM_PUB_KEY_LEN - MAC_LEN)
#define MESSAGE_FOR_CALC_MAC_MAX_LEN (IV_LEN + COM_PUB_KEY_LEN + MAX_CIPHER_LENGTH)

typedef struct {
	// uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	cx_hmac_sha256_t hmac;
	uint8_t pubkey_uncompressed[UNCOM_PUB_KEY_LEN];
	uint8_t iv[IV_LEN];
	uint8_t mac_data[MAC_LEN];
	uint8_t mac_calculated[MAC_LEN];
	uint8_t message_for_mac[MESSAGE_FOR_CALC_MAC_MAX_LEN]; // depends on cipher text
	uint8_t pointM[UNCOM_PUB_KEY_LEN];
	uint8_t hashH[HASH512_LEN];
} decryptDataContext_t;

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
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
	decryptDataContext_t decryptDataContext;
} commandContext;
extern commandContext global;