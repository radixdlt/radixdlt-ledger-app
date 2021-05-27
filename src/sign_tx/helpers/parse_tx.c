#include "parse_tx.h"

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "ux.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "base_conversion.h"
#include "sign_tx_ui.h"
#include "common_macros.h"
#include "account_address.h"
#include "action.h"

static sign_tx_context_t *ctx = &global.sign_tx_context;
static parse_tx_t *parse_state = &global.sign_tx_context.parse_state;

static void empty_action() {
    explicit_bzero(&parse_state->action, sizeof(action_t));
}


void reset_parse_state(void);

static void user_accepted_action(void) {
    empty_action();
}

static void ux_block() {
    io_exchange(IO_ASYNCH_REPLY, 0); // BLOCK ux
}

void empty_buffer(void) {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

static bool do_parse_token_transfer_from_bytes(
                                               uint8_t *bytes,
                                               size_t byte_count) {

    bool is_mainnet = false; // TODO MAINNET change to true, or rather, only allow mainnet?
    parse_state->action.from.is_mainnet = is_mainnet;
    int offset = 2; // first byte is LENGTH_OF_ACTION, second byte is ACTION_TYPE
    os_memcpy(parse_state->action.from.bytes, bytes + offset, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    os_memcpy(parse_state->action.from, bytes + offset, PUBLIC_KEY_COMPRESSEED_BYTE_COUNT);
    return false;
}


static bool do_parse_stake_token_from_bytes(
                                               uint8_t *bytes,
                                               size_t byte_count) {
    
    FATAL_ERROR("WARNING Stake tokens action parsing is not implemented");
    return false;
}

static bool do_parse_unstake_token_from_bytes(
                                               uint8_t *bytes,
                                               size_t byte_count) {
    FATAL_ERROR("WARNING Unstake tokens action parsing is not implemented");
    return false;
}


static void do_parse_action_from_tx_bytes(
    uint8_t *bytes,
    size_t byte_count
) {
    size_t action_length = (size_t) bytes[0];
    assert(action_length == byte_count);
    ActionType action_type = (ActionType) bytes[1];
    
    parse_state->action.action_type = action_type;
    
    bool successfully_parse_action = false;
    switch (action_type) {
        case ActionTypeTransferTokens:
            successfully_parse_action = do_parse_token_transfer_from_bytes(bytes, byte_count);
        case ActionTypeStakeTokens:
            successfully_parse_action = do_parse_stake_token_from_bytes(bytes, byte_count);
        case ActionTypeUnstakeTokens:
            successfully_parse_action = do_parse_unstake_token_from_bytes(bytes, byte_count);
        case ActionTypeNotSet:
        default:
            FATAL_ERROR("Invalid or unsupported action type, got: %d", action_type);
    }
    
    if (!successfully_parse_action) {
        io_exchange_with_code(SW_INTERNAL_ERROR_PARSE_ACTION, 0);
        ui_idle();
        return;
    }
    
    PRINTF("\n-=#$ Finished parsing action $#=-\n\n");
    parse_state->actions_parsed += 1;
    
    // TODO when printing of action does not modify its content, remove the `debug_print_action`
    action_t debug_print_action;
    os_memcpy(&debug_print_action, &parse_state->action, sizeof(action_t));
    print_action(&debug_print_action);
    
    ask_user_for_confirmation_of_action();
    PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to review & accept the action.\n");
    ux_block();
    user_accepted_action();

}

void received_action_from_host_machine(
    int action_index,
    uint8_t *action_bytes,
    uint16_t number_of_bytes_received
) {
    ui_update_progress_display();

    if (finished_parsing_all_actions()) {
        empty_buffer();
        return;
    }
     
    do_parse_action_from_tx_bytes(action_bytes, number_of_bytes_received);
    empty_buffer();
}


void reset_parse_state(void) {
    parse_state->is_users_public_key_calculated = false;
    
    empty_action();

    ui_init_progress_display();
}
