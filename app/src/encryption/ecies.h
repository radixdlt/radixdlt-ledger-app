#include "stdbool.h"
#include "stdint.h"
#include "os.h"

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