#ifndef GLOBALSTATE_H
#define GLOBALSTATE_H

#include "key_and_signatures.h"
#include "transfer.h"
#include "aes.h"
#include "particles_counter.h"
#include "particle_field.h"
#include "common_macros.h"

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
	uint8_t point_m[UNPUBLIC_KEY_COMPRESSEED_BYTE_COUNT];
	uint8_t hash_h[HASH512_LEN];
} decrypt_data_context_t;

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
} get_public_key_context_t;

typedef struct {
    uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    bool require_confirmation_of_address;
    uint8_t radix_universe_magic_byte;
} generate_radix_address_context_t;

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t hash[HASH256_BYTE_COUNT];
} sign_hash_context_t;

#define MAX_SERIALIZER_LENGTH 100

typedef struct {

	bool __DEBUG_MODE_skip_short_transfer_reviews;

	bool is_users_public_key_calculated;
	cx_ecfp_public_key_t my_public_key_compressed;

	particles_counter_t up_particles_counter;

	bool user_has_accepted_non_transfer_data;

	particle_field_t next_particle_field_to_parse; 
	transfer_t transfer;
} parse_atom_t;

typedef struct {
    uint16_t atom_byte_count;
    uint16_t number_of_atom_bytes_received;
	cx_sha256_t hasher;
	uint8_t hash[HASH256_BYTE_COUNT];
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];

	parse_atom_t parse_state;
} sign_atom_context_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    generate_radix_address_context_t generate_radix_address_context;
    get_public_key_context_t get_public_key_context;
    sign_hash_context_t sign_hash_context;
    sign_atom_context_t sign_atom_context;
    decrypt_data_context_t decrypt_data_context;
} command_context_u;
extern command_context_u global;

#endif