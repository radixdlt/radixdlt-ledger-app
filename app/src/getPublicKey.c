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

static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

static void user_did_confirm_pub_key() {
    io_exchange_with_code(SW_OK, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    ui_idle();
}

static void genPubKey() {
    cx_ecfp_public_key_t publicKey;

    derive_radix_key_pair(ctx->bip32Path, &publicKey,
                          NULL  // dont write private key
    );

    assert(publicKey.W_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    os_memmove(G_io_apdu_buffer, publicKey.W,
               PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    if (!ctx->requireConfirmationOfDisplayedPubKey) {
        user_did_confirm_pub_key();
    } else {
        G_ui_state.lengthOfFullString = hexadecimal_string_from(
            G_io_apdu_buffer, publicKey.W_len, G_ui_state.fullString);
        display_value("Compare:", user_did_confirm_pub_key);
    }
}

static void generate_publickey_flow(bool requireConfirmationBeforeGeneration) {
    if (requireConfirmationBeforeGeneration) {
        display_value("Gen PubKey", genPubKey);
    } else {
        genPubKey();
    }
}

// These are APDU parameters that control the behavior of the getPublicKey
// command. See `ux.h` or `APDUSPEC.md` for more details
#define P1_NO_CONFIRMATION_BEFORE_GENERATION 0x00
#define P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION 0x01

#define P2_NO_CONFIRMATION_OF_DISPLAYED_PUBKEY 0x00
#define P2_REQUIRE_CONFIRMATION_OF_DISPLAYED_PUBKEY 0x01

// handleGetPublicKey is the entry point for the getPublicKey command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handleGetPublicKey(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx) {
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length =
        expected_number_of_bip32_compents * byte_count_bip_component;

    if (dataLength != expected_data_length) {
        PRINTF("'dataLength' must be: %u, but was: %d\n", expected_data_length,
               dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->requireConfirmationOfDisplayedPubKey =
        (p2 == P2_REQUIRE_CONFIRMATION_OF_DISPLAYED_PUBKEY);
    G_ui_state.lengthOfFullString = parse_bip32_path_from_apdu_command(
        dataBuffer, ctx->bip32Path, G_ui_state.fullString,
        MAX_LENGTH_FULL_STR_DISPLAY);

    *flags |= IO_ASYNCH_REPLY;

    generate_publickey_flow((p1 == P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION));
}
