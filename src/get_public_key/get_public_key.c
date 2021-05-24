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
#include "radix_address.h"

static get_public_key_context_t *ctx = &global.get_public_key_context;

#define RADIX_ACCOUNT_ADDRESS_VERSION_BYTE 0x04
#define RADIX_ACCOUNT_ADDRESS_VERSION_DATA_LENGTH 1 // one byte

static void did_verify_address() {
    os_memmove(
        G_io_apdu_buffer,
        G_ui_state.lower_line_long,
        RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX
    );
    io_exchange_with_code(SW_OK, RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX);
    ui_idle();
    return;
}

static void generate_and_respond_with_compressed_public_key() {
    cx_ecfp_public_key_t public_key;

    if (!derive_radix_key_pair(
        ctx->bip32_path,
        &public_key,
        NULL  // dont write private key
    )) {
        PRINTF("Failed to derive public key");
        io_exchange_with_code(SW_INTERNAL_ERROR_ECC, 0);
        ui_idle();
        return;
    }
    assert(public_key.W_len == PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
  

        
    if (ctx->display_address) {
        
        clear_lower_line_long();
        
        os_memset(ctx->address.bytes, RADIX_ACCOUNT_ADDRESS_VERSION_BYTE, RADIX_ACCOUNT_ADDRESS_VERSION_DATA_LENGTH);
        os_memcpy(ctx->address.bytes + RADIX_ACCOUNT_ADDRESS_VERSION_DATA_LENGTH, public_key.W, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
        
        
        size_t actual_radix_address_length = to_string_radix_address(&ctx->address, G_ui_state.lower_line_long, RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX);
       
        if (actual_radix_address_length != RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX) {
            PRINTF("actual_radix_address_length != radix_address_string_len");
            io_exchange_with_code(SW_INTERNAL_ERROR_ECC, 0);
            ui_idle();
            return;
        }
        G_ui_state.length_lower_line_long = actual_radix_address_length;

                
        display_value("Address", did_verify_address);
    } else {
        
        os_memmove(
            G_io_apdu_buffer,
            public_key.W,
            PUBLIC_KEY_COMPRESSEED_BYTE_COUNT
        );
        io_exchange_with_code(SW_OK, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
        ui_idle();
        return;
    }

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
#define P2_DISPLAY_ADDRESS_MAINNET 0x01
#define P2_DISPLAY_ADDRESS_BETANET 0x02

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
    PRINTF("Handle instruction 'GET_PUBLIC_KEY' from host machine.\n");
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

    ctx->display_address = (p2 == P2_DISPLAY_ADDRESS_MAINNET) || (p2 == P2_DISPLAY_ADDRESS_BETANET);
    if (ctx->display_address) {
        ctx->address.is_mainnet = p2 == P2_DISPLAY_ADDRESS_MAINNET;
    }
    generate_publickey_require_confirmation_if_needed(
        (p1 == P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION));
}
