#ifndef GLOBALSTATE_H
#define GLOBALSTATE_H

#include "key_and_signatures.h"
#include "transfer.h"
#include "common_macros.h"


#include "actions_counter.h"
#include "action_field.h"



typedef struct {

    bool is_users_public_key_calculated;
    cx_ecfp_public_key_t my_public_key_compressed;

    actions_counter_t actions_counter;

    bool user_has_accepted_non_transfer_data;

    action_field_t next_action_field_to_parse;
    transfer_t transfer;
    transfer_t debug_print_transfer; // Only for debug printing, TODO change impl of `print_transfer` to NOT mutate struct, which would remove need for this. This eats up ~300 bytes (which is about ~25% of all available space on Ledger Nano S (?)), so terribly costly variable.

} parse_tx_t;

typedef struct {
    uint16_t tx_byte_count;
    uint16_t number_of_tx_bytes_received;
    cx_sha256_t hasher;
    uint8_t hash[HASH256_BYTE_COUNT];
    uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];

    parse_tx_t parse_state;
} sign_tx_context_t;

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    bool display_address;
    radix_address_t address;
} get_public_key_context_t;

typedef struct {
    uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    uint8_t public_key_of_other_party[PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT];
} do_key_exchange_context_t;

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t hash[HASH256_BYTE_COUNT];
} sign_hash_context_t;

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    get_public_key_context_t get_public_key_context;
    do_key_exchange_context_t do_key_exchange_context;
    sign_hash_context_t sign_hash_context;
    sign_tx_context_t sign_tx_context;
} command_context_u;
extern command_context_u global;

#endif
