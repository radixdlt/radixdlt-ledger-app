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
    uint8_t number_of_up_particles;
	bool non_transfer_data_found;
	cx_sha256_t hasher;
	uint8_t hash[HASH256_BYTE_COUNT];
    uint16_t number_of_atom_bytes_received;
    uint16_t number_of_atom_bytes_parsed;

	ByteInterval interval_of_atom_slice;
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    uint16_t atom_byte_count;
	uint8_t number_of_cached_bytes;

	ParticleMetaData particle_meta_data; 
	Transfer transfer;
   	uint8_t atom_slice[MAX_ATOM_SLICE_SIZE];
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