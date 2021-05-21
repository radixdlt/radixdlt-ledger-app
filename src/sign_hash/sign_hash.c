#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>

#include "common_macros.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "ui.h"
#include "base_conversion.h"

static sign_hash_context_t *ctx = &global.sign_hash_context;

static void did_finish_sign_hash_flow() {
    size_t tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
    io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static void proceed_to_final_signature_confirmation() {
    display_lines("Sign content", "Confirm?", did_finish_sign_hash_flow);
}

static void ask_user_to_confirm_hash() {
    G_ui_state.length_lower_line_long =
        hexadecimal_string_from(
                                ctx->hash,
                                HASH256_BYTE_COUNT,
                                G_ui_state.lower_line_long
                                );
    
    display_value("Verify Hash", proceed_to_final_signature_confirmation);
}

void handle_sign_hash(
    uint8_t p1,
    uint8_t p2,
    uint8_t *data_buffer,
    uint16_t data_length,
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {

    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count =
        expected_number_of_bip32_compents * byte_count_bip_component;

    uint16_t expected_data_length = expected_bip32_byte_count + HASH256_BYTE_COUNT;
    if (data_length != expected_data_length) {
        PRINTF("'data_length' must be: %u, but was: %d\n", expected_data_length,
               data_length);
        THROW(SW_INVALID_PARAM);
    }

    // Parse BIP 32
    size_t offset_of_data = 0;
    
    parse_bip32_path_from_apdu_command(
        data_buffer + offset_of_data,
        ctx->bip32_path,
        NULL, 
        0
    );

    offset_of_data += expected_bip32_byte_count;

    // Read the hash.
    os_memmove(ctx->hash, data_buffer + offset_of_data, sizeof(ctx->hash));

    ask_user_to_confirm_hash();

    *flags |= IO_ASYNCH_REPLY;
}
