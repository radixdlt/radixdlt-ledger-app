#include "stdbool.h"
#include "stdint.h"
#include "os.h"

size_t ecies_encrypt(
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count);

size_t ecies_encrypt_iv(
    const uint8_t* iv,
    const size_t iv_len,
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count);

size_t ecies_decrypt_bipPath(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    uint32_t *bip32Path
);

size_t ecies_decrypt(
    const uint8_t* data_in,
    const size_t data_in_len,

    uint8_t* data_out,
    size_t data_out_len,

    cx_ecfp_private_key_t *privateKey
);