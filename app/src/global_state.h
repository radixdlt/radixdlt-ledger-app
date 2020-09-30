#include "key_and_signatures.h"
#include "Transfer.h"
#include "common_macros.h"
#include "ParticleMetaData.h"
#include "aes.h"

typedef struct {
	size_t cipher_text_byte_count;
	size_t cipher_number_of_parsed_bytes;
	cx_ecfp_private_key_t privateKey;
	cx_hmac_sha256_t hmac;
	struct AES_ctx aes_ctx;
	cx_sha512_t hasher;
	uint8_t calc_mac[MAC_LEN];
	uint8_t iv[IV_LEN];
	cx_ecfp_256_public_key_t ephemeral_pubkey;
	uint8_t mac[MAC_LEN];
	uint8_t pointM[UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT];
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

#define MAX_SERIALIZER_LENGTH 100

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	
    uint16_t atomByteCount;
    uint16_t atomByteCountParsed;

	cx_sha256_t hasher;

	// Only written to when the digest is finalized, after having received the
	// last byte of the atom
	uint8_t hash[HASH256_BYTE_COUNT];

	// a 20 byte object containing metadata about the next particle to parse
	ParticleMetaData metaDataAboutParticle;

    // The de-facto length of the array `offsetsOfParticlesWithSpinUp`, read from APDU instr
    uint8_t numberOfParticlesWithSpinUp;

	uint8_t numberOfNonTransferrableTokensParticlesIdentified;
    uint8_t numberOfTransferrableTokensParticlesParsed;

	// char serializerOfLastParticle[MAX_SERIALIZER_LENGTH];

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
	bool hasConfirmedSerializerOfTransferrableTokensParticle;

	uint8_t numberOfTransfersToNotMyAddressApproved;

	// If the recently parsed UP particle was of type TransferrableTokensParticle we will have parsed it into this `Transfer` object
	// this might be a transfer back to the user's own address, so we might wanna skip presenting user with confirmation
	// flow if it
	Transfer transfer;

	bool hasApprovedNonTransferData;
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