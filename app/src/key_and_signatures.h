#include "stdint.h"

int parse_bip32_path_from_apdu_command(
    uint8_t *dataBuffer,
    uint32_t *output_bip32path,
    uint8_t *output_bip32String, // might be null
    unsigned short output_bip32PathString_length
);

// derive_radix_key_pair derives a key pair from a BIP32 path and the Ledger
// seed. Returns the public key and private key if not NULL.
void derive_radix_key_pair(uint32_t *bip32path,
                           volatile cx_ecfp_public_key_t *publicKey,
                           volatile cx_ecfp_private_key_t *privateKey_nullable);

size_t derive_sign_move_to_global_buffer(
    uint32_t *bip32path, 
    const uint8_t *hash
);

bool generate_key_pair(volatile cx_ecfp_public_key_t *publicKey,
                       volatile cx_ecfp_private_key_t *privateKey);