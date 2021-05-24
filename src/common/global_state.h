#ifndef GLOBALSTATE_H
#define GLOBALSTATE_H

#include "key_and_signatures.h"
#include "transfer.h"
#include "common_macros.h"

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
} get_public_key_context_t;

typedef struct {
    uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
    uint8_t public_key_of_other_party[PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT];
} do_key_exchange_context_t;

typedef struct {
	uint32_t bip32_path[NUMBER_OF_BIP32_COMPONENTS_IN_PATH];
	uint8_t hash[HASH256_BYTE_COUNT];
} sign_hash_context_t;

#define MAX_SERIALIZER_LENGTH 100

// To save memory, we store all the context types in a single global union,
// taking advantage of the fact that only one command is executed at a time.
typedef union {
    get_public_key_context_t get_public_key_context;
    do_key_exchange_context_t do_key_exchange_context;
    sign_hash_context_t sign_hash_context;
} command_context_u;
extern command_context_u global;

#endif
