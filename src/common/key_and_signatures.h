#include "stdint.h"

int parse_bip32_path_from_apdu_command(
    uint8_t *data_buffer,
    uint32_t *output_bip32path,
    uint8_t *output_bip32String, // might be null
    unsigned short output_bip32_pathString_length
);

// derive_radix_key_pair derives a key pair from a BIP32 path and the Ledger
// seed. Returns the public key and private key if not NULL.
void derive_radix_key_pair(uint32_t *bip32path,
                           volatile cx_ecfp_public_key_t *public_key,
                           volatile cx_ecfp_private_key_t *private_key_nullable);

size_t derive_sign_move_to_global_buffer(
    uint32_t *bip32path, 
    const uint8_t *hash
);

void compress_public_key(cx_ecfp_public_key_t *public_key);

void uncompress_public_key(
    uint8_t *compressed_pubkey,
    const size_t compressed_pubkey_len,

    uint8_t *uncompressed_pubkey_res,
    const size_t uncompressed_pubkey_len
);