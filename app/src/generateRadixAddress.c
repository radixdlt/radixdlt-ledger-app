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

static generateRadixAddressContext_t *ctx = &global.generateRadixAddressContext;

static void user_did_confirm_address() {
    ui_idle();
}

static void generate_and_respond_with_radix_address() {
    cx_ecfp_public_key_t publicKey;

    derive_radix_key_pair(ctx->bip32Path, &publicKey,
                          NULL  // dont write private key
    );
    assert(publicKey.W_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    int length_of_radix_address_string_b58 = generate_public_address_from_pub_key_and_universe_magic(
        ctx->radixUniverseMagicByte, publicKey.W, G_io_apdu_buffer,
        RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1);

        io_exchange_with_code(SW_OK, length_of_radix_address_string_b58);

    if (!ctx->requireConfirmationOfAddress) {
        ui_idle();
    } else {
        G_ui_state.lengthOfFullString = length_of_radix_address_string_b58;
        os_memcpy(G_ui_state.fullString, G_io_apdu_buffer,
                  length_of_radix_address_string_b58);
        display_value("Compare:", user_did_confirm_address);
    }
}

static void generate_address_require_confirmation_if_needed(
    bool requireConfirmationOfBIP32Path
) {
    if (requireConfirmationOfBIP32Path) {
        display_value("Gen addr for", generate_and_respond_with_radix_address);
    } else {
        generate_and_respond_with_radix_address();
    }
}

// These are APDU parameters that control the behavior of the getPublicKey
// command. See `ux.h` or `APDUSPEC.md` for more details
#define P1_MODE_NO_CONFIRMATION 0x00
#define P1_MODE_CONFIRM_JUST_ADDR 0x01
#define P1_MODE_CONFIRM_JUST_BIP32_PATH 0x02
#define P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH 0x03

// handleGenerateRadixAddress is the entry point for the generateRadixAddress command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handleGenerateRadixAddress(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                        uint16_t dataLength, volatile unsigned int *flags,
                        volatile unsigned int *tx) {

    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length =
        expected_number_of_bip32_compents * byte_count_bip_component;

    if (p1 != P1_MODE_NO_CONFIRMATION && p1 != P1_MODE_CONFIRM_JUST_ADDR && p1 != P1_MODE_CONFIRM_JUST_BIP32_PATH && p1 != P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH) {
        PRINTF("bad 'p1' value, should be 0-3");
        THROW(SW_INVALID_PARAM);
    }

    ctx->radixUniverseMagicByte = p2;
    ctx->requireConfirmationOfAddress =
        (p1 == P1_MODE_CONFIRM_JUST_ADDR ||
         p1 == P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH);
    bool requireConfirmationOfBIP32Path = (p1 == P1_MODE_CONFIRM_JUST_BIP32_PATH || p1 == P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH);

    if (dataLength != expected_data_length) {
        PRINTF("'dataLength' must be: %u, but was: %d\n", expected_data_length,
               dataLength);
        THROW(SW_INVALID_PARAM);
    }

    // READ BIP 32 path
    G_ui_state.lengthOfFullString = parse_bip32_path_from_apdu_command(
        dataBuffer, ctx->bip32Path, G_ui_state.fullString,
        BIP32_PATH_STRING_MAX_LENGTH);

    *flags |= IO_ASYNCH_REPLY;

    generate_address_require_confirmation_if_needed(
        requireConfirmationOfBIP32Path
    );
}
