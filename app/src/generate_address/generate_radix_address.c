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

static generate_radix_address_context_t *ctx = &global.generate_radix_address_context;

static void user_did_confirm_address() {
    ui_idle();
}

static void generate_and_respond_with_radix_address() {
    cx_ecfp_public_key_t public_key;

    derive_radix_key_pair(
        ctx->bip32_path, 
        &public_key,
        NULL  // dont write private key
    );
    
    assert(public_key.W_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    int length_of_radix_address_string_b58 = generate_public_address_from_pub_key_and_universe_magic(
        ctx->radix_universe_magic_byte, 
        public_key.W, 
        G_io_apdu_buffer,
        RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1
    );

    io_exchange_with_code(SW_OK, length_of_radix_address_string_b58);

    if (!ctx->require_confirmation_of_address) {
        ui_idle();
    } else {
        G_ui_state.length_lower_line_long = length_of_radix_address_string_b58;
        
        os_memcpy(
            G_ui_state.lower_line_long, 
            G_io_apdu_buffer,
            length_of_radix_address_string_b58
        );
        
        display_value("Compare:", user_did_confirm_address);
    }
}

static void generate_address_require_confirmation_if_needed(
    bool require_confirmation_of_bip32_path
) {
    if (require_confirmation_of_bip32_path) {
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

// handle_generate_radix_address is the entry point for the generateRadixAddress command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handle_generate_radix_address(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *data_buffer,
    
    uint16_t data_length, 
    unsigned int *flags,
    unsigned int *tx
) {

    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length =
        expected_number_of_bip32_compents * byte_count_bip_component;

    if (p1 != P1_MODE_NO_CONFIRMATION && p1 != P1_MODE_CONFIRM_JUST_ADDR && p1 != P1_MODE_CONFIRM_JUST_BIP32_PATH && p1 != P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH) {
        PRINTF("bad 'p1' value, should be 0-3");
        THROW(SW_INVALID_PARAM);
    }

    ctx->radix_universe_magic_byte = p2;
    ctx->require_confirmation_of_address =
        (p1 == P1_MODE_CONFIRM_JUST_ADDR ||
         p1 == P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH);
    bool require_confirmation_of_bip32_path = (p1 == P1_MODE_CONFIRM_JUST_BIP32_PATH || p1 == P1_MODE_CONFIRM_BOTH_ADDR_AND_BIP32_PATH);

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

    generate_address_require_confirmation_if_needed(
        require_confirmation_of_bip32_path
    );
}
