#include "stdbool.h"
#include "stdint.h"
#include "os.h"

int do_decrypt(
    cx_ecfp_private_key_t *privateKey,
    const size_t cipher_text_len
);