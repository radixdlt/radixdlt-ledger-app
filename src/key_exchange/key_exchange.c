#include <os.h>
#include <os_io_seproxyhal.h>
#include <cx.h>
#include <stdbool.h>
#include <stdint.h>

#include "base_conversion.h"
#include "common_macros.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "stringify_bip32_path.h"
#include "ui.h"

static do_key_exchange_context_t *ctx = &global.do_key_exchange_context;


static void do_key_change_and_respond_with_point_on_curve() {
    if (cx_ecfp_is_valid_point(
                           CX_CURVE_SECP256K1,
                           ctx->public_key_of_other_party,
                               PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT) != 1) {
        PRINTF("Invalid public key, 'point' not on the curve");
        THROW(SW_INVALID_PARAM);
    }
    
    cx_ecfp_private_key_t private_key;

    if (!derive_radix_key_pair_should_compress(
        ctx->bip32_path,
        NULL,  // dont write public key
        &private_key,
        false
    )) {
        PRINTF("Key exchange failed, failed to derive private key.\n");
        io_exchange_with_code(SW_INTERNAL_ERROR_ECC, 0);
        ui_idle();
        return;
    }
    
    int actual_size_of_secret = 0;
    int error = 0;
    BEGIN_TRY {
        TRY {
                io_seproxyhal_io_heartbeat();
            actual_size_of_secret = cx_ecdh(
                    &private_key,
                    CX_ECDH_POINT, // or `CX_ECDH_X`
                    ctx->public_key_of_other_party,
                    PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT,
                    G_io_apdu_buffer,
                    PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);
                    
      
        }
        CATCH_OTHER(e) { error = e; }
        FINALLY {
            /* Nothing to do, but make sure to zero out private key from calling function */
        }

    }
    END_TRY;
    
    // Ultra important step, MUST zero out the private, else sensitive information is leaked.
    explicit_bzero((cx_ecfp_private_key_t *)&private_key, sizeof(cx_ecfp_private_key_t));
    
    
    if (error) {
        print_error_by_code(error);
        PRINTF("Key exchange failed, failed to perform ECDH\n");
        io_exchange_with_code(SW_INTERNAL_ERROR_ECC, 0);
    } else {
        io_exchange_with_code(SW_OK, actual_size_of_secret);
    }
    
    ui_idle();
    return;
}



static void proceed_to_exchange_confirmation() {
    display_lines("Key exchange", "Confirm?", do_key_change_and_respond_with_point_on_curve);
}

static void proceed_to_display_other_pubkey() {
    clear_lower_line_long();
    
    
    G_ui_state.length_lower_line_long =
        hexadecimal_string_from(
                                ctx->public_key_of_other_party,
                                PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT,
                                G_ui_state.lower_line_long
                                );
    
    display_value("Other pubkey",
                  proceed_to_exchange_confirmation);
}

static void generate_sharedkey_require_confirmation_if_needed(
    bool requireConfirmationDoingDiffieHellman) {
    if (requireConfirmationDoingDiffieHellman) {
        display_value("Your key at:",
                      proceed_to_display_other_pubkey);
    } else {
        do_key_change_and_respond_with_point_on_curve();
    }
}

#define P1_REQUIRE_CONFIRMATION_BEFORE_KEY_EXCHANGE 0x01

void handle_key_exchange(
        uint8_t p1,
        uint8_t p2,
        uint8_t *data_buffer,
        uint16_t data_length,
        volatile unsigned int *flags,
        volatile unsigned int *tx
) {
    PRINTF("Handle instruction 'DO_KEY_EXCHANGE' from host machine\n");
    
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length_path =
        expected_number_of_bip32_compents * byte_count_bip_component;
    
    uint16_t expected_lenght_public_key_of_other_party = PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT;
    
    
    uint16_t expected_data_length = expected_data_length_path + expected_lenght_public_key_of_other_party;

    if (data_length != expected_data_length) {
        PRINTF("'data_length' must be: %u, but was: %d\n", expected_data_length,
               data_length);
        THROW(SW_INVALID_PARAM);
    }

    // READ BIP 32 path
    G_ui_state.length_lower_line_long =
    parse_bip32_path_from_apdu_command(
        data_buffer,
        ctx->bip32_path,
        G_ui_state.lower_line_long,
        BIP32_PATH_STRING_MAX_LENGTH);
    
    // Copy public key bytes
    os_memmove(ctx->public_key_of_other_party, data_buffer + expected_data_length_path, expected_lenght_public_key_of_other_party);
    

    *flags |= IO_ASYNCH_REPLY;

    generate_sharedkey_require_confirmation_if_needed(
        (p1 == P1_REQUIRE_CONFIRMATION_BEFORE_KEY_EXCHANGE));
}
