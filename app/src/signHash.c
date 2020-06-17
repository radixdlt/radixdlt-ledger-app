#include <os.h>
#include <os_io_seproxyhal.h>
#include <stdbool.h>
#include <stdint.h>

#include "common_macros.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "ui.h"

static signHashContext_t *ctx = &global.signHashContext;

static void didFinishSignAtomFlow() {
    int tx = derive_sign_move_to_global_buffer(ctx->bip32Path, ctx->hash);
    io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static void proceedToFinalSignatureConfirmation() {
    display_lines("Sign content", "Confirm?", didFinishSignAtomFlow);
}

static void askUserToConfirmHash() {
    G_ui_state.lengthOfFullString = hexadecimal_string_from(
        ctx->hash, HASH256_BYTE_COUNT, G_ui_state.fullString);
    display_value("Verify Hash", proceedToFinalSignatureConfirmation);
}

void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer,
                    uint16_t dataLength, volatile unsigned int *flags,
                    volatile unsigned int *tx) {

    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count =
        expected_number_of_bip32_compents * byte_count_bip_component;

    uint16_t expected_data_length = expected_bip32_byte_count + HASH256_BYTE_COUNT;
    if (dataLength != expected_data_length) {
        PRINTF("'dataLength' must be: %u, but was: %d\n", expected_data_length,
               dataLength);
        THROW(SW_INVALID_PARAM);
    }

    // Parse BIP 32
    size_t offset_of_data = 0;
    parse_bip32_path_from_apdu_command(dataBuffer + offset_of_data,
                                       ctx->bip32Path, NULL, 0);
    offset_of_data += expected_bip32_byte_count;

    // // Read the hash.
    os_memmove(ctx->hash, dataBuffer + offset_of_data, sizeof(ctx->hash));

    askUserToConfirmHash();

    *flags |= IO_ASYNCH_REPLY;
}
