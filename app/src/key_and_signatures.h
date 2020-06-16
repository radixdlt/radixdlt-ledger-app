#include "stdint.h"

void parse_bip32_path_from_apdu_command(
    uint8_t *dataBuffer,
    uint32_t *output_bip32path,
    uint8_t *output_bip32String, // might be null
    unsigned short output_bip32PathString_length
);

// Convert un-compressed zilliqa public key to a compressed form.
void compress_public_key(cx_ecfp_public_key_t *publicKey);

// derive_radix_key_pair derives a key pair from a BIP32 path and the Ledger
// seed. Returns the public key and private key if not NULL.
void derive_radix_key_pair(
    uint32_t *bip32path, 
    cx_ecfp_public_key_t *publicKey,
    cx_ecfp_private_key_t *privateKey_nullable
);

size_t derive_sign_move_to_global_buffer(
    uint32_t *bip32path, 
    const uint8_t *hash
);
