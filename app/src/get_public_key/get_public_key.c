#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>

#include "base_conversion.h"
#include "common_macros.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "stringify_bip32_path.h"
#include "ui.h"

static get_public_key_context_t *ctx = &global.getPublicKeyContext;

static void generate_and_respond_with_compressed_public_key() {
    cx_ecfp_public_key_t publicKey;

    derive_radix_key_pair(ctx->bip32_path, &publicKey,
                          NULL  // dont write private key
    );
    assert(publicKey.W_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    os_memmove(G_io_apdu_buffer, publicKey.W,
               PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    io_exchange_with_code(SW_OK, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    ui_idle();
}

static void generate_publickey_require_confirmation_if_needed(
    bool requireConfirmationBeforeGeneration) {
    if (requireConfirmationBeforeGeneration) {
        display_value("Gen PubKey",
                      generate_and_respond_with_compressed_public_key);
    } else {
        generate_and_respond_with_compressed_public_key();
    }
}

// These are APDU parameters that control the behavior of the getPublicKey
// command. See `ux.h` or `APDUSPEC.md` for more details
#define P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION 0x01

// handle_get_public_key is the entry point for the getPublicKey command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handle_get_public_key(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *data_buffer,
    uint16_t data_length, 
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length =
        expected_number_of_bip32_compents * byte_count_bip_component;

    if (data_length != expected_data_length) {
        PRINTF("'data_length' must be: %u, but was: %d\n", expected_data_length,
               data_length);
        THROW(SW_INVALID_PARAM);
    }

    // READ BIP 32 path
    G_ui_state.length_lower_line_long = parse_bip32_path_from_apdu_command(
        data_buffer, ctx->bip32_path, G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH);

    *flags |= IO_ASYNCH_REPLY;

    generate_publickey_require_confirmation_if_needed(
        (p1 == P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION));
}
