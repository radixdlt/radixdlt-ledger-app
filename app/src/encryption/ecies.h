#include "stdbool.h"
#include "stdint.h"
#include "os.h"

bool ecies_encrypt(
    const uint8_t* data_in,
    const size_t data_in_len,
    uint8_t* data_out,
    size_t data_out_len,
    const uint8_t* uncompress_public_key_bytes,
    const size_t pk_byte_count);