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
    cx_ecfp_private_key_t private_key;

    derive_radix_key_pair(
        ctx->bip32_path,
        NULL,  // dont write public key
        &private_key
    );

    
    uint8_t uncompressed_pubkey[PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT];
    

    uncompress_public_key(ctx->public_key_of_other_party, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT, uncompressed_pubkey, PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);
    

    
    int actual_size_of_secret = cx_ecdh(
            &private_key,
            CX_ECDH_POINT, // or `CX_ECDH_X`
            uncompressed_pubkey,
            PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT,
            ctx->shared_secret_point,
            PUBLIC_KEY_UNCOMPRESSEED_BYTE_COUNT);
            
    os_memmove(G_io_apdu_buffer, ctx->shared_secret_point, actual_size_of_secret);
    
    io_exchange_with_code(SW_OK, actual_size_of_secret);
    ui_idle();
}


static void generate_sharedkey_require_confirmation_if_needed(
    bool requireConfirmationDoingDiffieHellman) {
    if (requireConfirmationDoingDiffieHellman) {
        display_value("Exchange key",
                      do_key_change_and_respond_with_point_on_curve);
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
    PRINTF("Got DO_KEY_EXCHANGE from host machine\n");
    
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length_path =
        expected_number_of_bip32_compents * byte_count_bip_component;
    
    uint16_t expected_lenght_public_key_of_other_party = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT;
    
    
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
    os_memcpy(data_buffer + expected_data_length_path, ctx->public_key_of_other_party, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);

    *flags |= IO_ASYNCH_REPLY;

    generate_sharedkey_require_confirmation_if_needed(
        (p1 == P1_REQUIRE_CONFIRMATION_BEFORE_KEY_EXCHANGE));
}
