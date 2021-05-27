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
#include "account_address.h"

static get_public_key_context_t *ctx = &global.get_public_key_context;


static void finished_ui_flow_respond_with_pubkey() {
    io_exchange_with_code(SW_OK, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    ui_idle();
    return;
}

static void did_verify_address() {
    finished_ui_flow_respond_with_pubkey();
}

 static void proceed_to_final_address_confirmation() {
     display_lines("Send pubkey", "Confirm?", did_verify_address);
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
  
    os_memmove(
        G_io_apdu_buffer,
        public_key.W,
        PUBLIC_KEY_COMPRESSEED_BYTE_COUNT
    );
        
    if (ctx->display_address) {
        
        clear_lower_line_long();
        explicit_bzero(ctx->address.bytes, ACCOUNT_ADDRESS_BYTE_COUNT);
        
        os_memset(ctx->address.bytes, ACCOUNT_ADDRESS_VERSION_BYTE, ACCOUNT_ADDRESS_VERSION_DATA_LENGTH);
        os_memcpy(ctx->address.bytes + ACCOUNT_ADDRESS_VERSION_DATA_LENGTH, public_key.W, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
        
        size_t actual_radix_address_length = to_string_account_address(&ctx->address, G_ui_state.lower_line_long, MAX_LENGTH_FULL_STR_DISPLAY);

        G_ui_state.length_lower_line_long = actual_radix_address_length;
                
        display_value("Your address", proceed_to_final_address_confirmation);
    } else {
        finished_ui_flow_respond_with_pubkey();
    }

}

static void proceed_to_pubkey_generation_confirmation() {
    display_lines("Generate key", "Confirm?", generate_and_respond_with_compressed_public_key);
}

static void generate_publickey_require_confirmation_if_needed(
    bool requireConfirmationBeforeGeneration) {
    if (requireConfirmationBeforeGeneration) {
        callback_t cb = proceed_to_pubkey_generation_confirmation;
        if (ctx->display_address) {
            PRINTF("setting cb = generate_and_respond_with_compressed_public_key\n");
            cb = generate_and_respond_with_compressed_public_key;
        }
        display_value("Key at index", cb);
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
