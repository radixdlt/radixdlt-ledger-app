#include "key_and_signatures.h"
#include "Transfer.h"

#define NUMBER_OF_BIP32_COMPONENTS_IN_PATH 5

// Size of some string used for displaying long text on disaply
#define MAX_LENGTH_FULL_STR_DISPLAY 103 // "ABCD0123456789E, Full Identifier: /9hTaTtgqxhAGRryeMs5htePmJA53tpjDgJK1FY3H1tLrmiZjv6j/ABCD0123456789E\0"

typedef struct {
	uint8_t displayIndex;
	uint8_t fullString[MAX_LENGTH_FULL_STR_DISPLAY]; // the RRI is the longest data we wanna display
	uint8_t lengthOfFullString;
	uint8_t partialString12Char[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE + 1]; //+1 for NULL
} ui_state_t;

extern ui_state_t G_ui_state;

#define APPROVAL_SCREEN(textLine1) APPROVAL_SCREEN_TWO_LINES(textLine1, G_ui_state.partialString12Char)

#define SEEK_SCREEN(textLine1) SEEK_SCREEN_TWO_LINES(textLine1, G_ui_state.partialString12Char)

void reset_ui();

void ui_fullStr_to_partial();

const bagl_element_t *preprocessor_for_seeking(const bagl_element_t *element);

unsigned int reject_or_approve(
	unsigned int button_mask,
	unsigned int button_mask_counter,
	void (*didApproveCallback)(void));

unsigned int seek_left_right_or_approve(
	unsigned int button_mask,
	unsigned int button_mask_counter,
	void (*didApproveCallback)(void));


typedef enum {
    AddressField = 0,
    AmountField,
    SerializerField,
    TokenDefinitionReferenceField
} ParticleField;

typedef enum {
    NoParticleTypeParsedYet = 0,
    MessageParticleType = 1,
    RRIParticleType,
    FixedSupplyTokenDefinitionParticleType,
    MutableSupplyTokenDefinitionParticleType,
    UnallocatedTokensParticleType,
    TransferrableTokensParticleType,
    UniqueParticleType,

    ParticleType_is_unknown
} RadixParticleTypes;

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
	uint8_t partialStr[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE + 1]; //+1 for NULL
} getPublicKeyContext_t;

#define HASH256_BYTE_COUNT 32

typedef struct {
	uint32_t bip32Path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t bip32PathString[BIP32_PATH_STRING_MAX_LENGTH]; // variable-length
	uint8_t hash[HASH256_BYTE_COUNT];

	uint8_t hexHash[(2 * HASH256_BYTE_COUNT) + 1]; // 1 for null

	uint8_t displayIndex;
	// NUL-terminated strings for display
	uint8_t partialHashStr[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE + 1]; //+1 for NULL
} signHashContext_t;

typedef struct {
	uint16_t startsAt;
	uint16_t byteCount;
} ByteInterval;

// A 16 byte struct, containing byte intervals (offset + count) to 
// fields (values) of interest inside of a Particle. The byte offsets are
// measured from the start of the Atom (that the particle is part of).
// In case of a Non-TransferrableTokensParticle the byte interval tuple
// will have value (0, 0), thus we can distinquish between this ParticleMetaData
// being meta data for a `TransferrableTokensParticle` of other particle type
// by looking at `[addressOfRecipientByteInterval, amountByteInterval,
// tokenDefinitionReferenceByteInterval]` and check if all zero or not.
typedef struct {

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval addressOfRecipientByteInterval;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval amountByteInterval;

	// Always present, disregarding of particle type
	ByteInterval serializerValueByteInterval;

	// In case of Non-TransferrableTokensParticle this will have value (0, 0)
	ByteInterval tokenDefinitionReferenceByteInterval;
} ParticleMetaData;

#define MAX_CHUNK_SIZE 255 

#define MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP 6
#define MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP 15 // 240/16, where 16 is size of `ParticleMetaData` and 240 is MAX_CHUNK_SIZE-2-12, where 2 is number of bytes to encode AtomSize and 12 is number of bytes for BIP32 path

// The biggest of a value split across chunks might be the `rri`
#define MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS (RADIX_RRI_MAX_BYTE_COUNT - 1)

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
	getPublicKeyContext_t getPublicKeyContext;
	signHashContext_t signHashContext;
	signAtomContext_t signAtomContext;
} commandContext;
extern commandContext global;