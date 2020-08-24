#include "stdbool.h"
#include "stdint.h"
#include "os.h"

int do_decrypt(
    cx_ecfp_private_key_t *privateKey,

    uint8_t *message_for_mac,
    size_t message_for_mac_len,

    uint8_t *encrypted, // IV(16) || 0x33 || PubKeyComp(33) || cipher_text_length(4) || cipher_text(cipher_text_length) || MAC(32)
    size_t encrypted_length
);