#include "stdbool.h"
#include "stdint.h"
#include "os.h"

int do_decrypt(
    cx_ecfp_private_key_t *privateKey,
    const uint8_t *cipher_text,
    const size_t cipher_text_len,

    uint8_t *plain_text_out,
    const size_t plain_text_len // MAX length in
);