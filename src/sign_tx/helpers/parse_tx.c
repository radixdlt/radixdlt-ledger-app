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
#include "radix_address.h"
#include "parse_field.h"

static sign_tx_context_t *ctx = &global.sign_tx_context;
static parse_tx_t *parse_state = &global.sign_tx_context.parse_state;

static void empty_transfer() {
    explicit_bzero(&parse_state->transfer, sizeof(transfer_t));
    parse_state->transfer.has_confirmed_action_type = false;
    parse_state->transfer.is_address_set = false;
    parse_state->transfer.is_amount_set = false;
    parse_state->transfer.is_token_definition_reference_set = false;
}

static void empty_action_field() {
    explicit_bzero(&parse_state->next_action_field_to_parse, sizeof(action_field_t));
    parse_state->next_action_field_to_parse.is_destroyed = true;
}

static void did_identify_a_transferrable_tokens_action() {
    identified_a_transferrable_tokens_action(&parse_state->actions_counter);
}

static void did_identify_a_non_transferrable_tokens_action() {
    identified_a_non_transferrable_tokens_action(&parse_state->actions_counter);
}

static bool has_action_field() {
    return !parse_state->next_action_field_to_parse.is_destroyed;
}

static bool user_has_accepted_non_transfer_data(void) {
    return parse_state->user_has_accepted_non_transfer_data;
}

void reset_parse_state(void);

static bool is_transfer_change_back_to_me() {
    if (!parse_state->is_users_public_key_calculated) {
        derive_radix_key_pair(
            ctx->bip32_path, 
            &ctx->parse_state.my_public_key_compressed, 
            NULL // dont write private key
        );
        parse_state->is_users_public_key_calculated = true;
    }

    bool matching_pub_keys = does_address_contain_public_key(&parse_state->transfer.address, &parse_state->my_public_key_compressed);
    return matching_pub_keys;
}

static void user_accepted_non_transfer_data() {
    empty_action_field();
    parse_state->user_has_accepted_non_transfer_data = true;
}

static void user_accepted_transfer_data() {
    empty_transfer();
    empty_action_field();
}

static void ux_block() {
    io_exchange(IO_ASYNCH_REPLY, 0); // BLOCK ux
}
static void do_parse_field_from_tx_bytes(
    action_field_t *action_field,
    uint8_t *bytes,
    transfer_t *debug_print_transfer
) {

//    explicit_bzero(&parse_state->cbor_parser, sizeof(CborParser));
//    explicit_bzero(&parse_state->cbor_value, sizeof(CborValue));
    
    /*
     ParseFieldResult parse_field_from_bytes_and_populate_transfer(
         action_field_t *action_field,
         uint8_t *bytes,
         transfer_t *transfer,
         uint8_t *out_bytes,
         const size_t out_len
     );
     */
    
    int buf_len = 150; // arbitrarily chosen
    uint8_t buf[buf_len];

    ParseFieldResult parse_result = parse_field_from_bytes_and_populate_transfer(
        action_field,
        bytes,
        &parse_state->transfer,
        buf,
        buf_len
    );

    empty_buffer();
   
    switch (parse_result) {
        case ParseFieldResultFinishedParsingTransfer:
            
            PRINTF("\n-=#$ Finished parsing whole transfer $#=-\n\n");

            did_identify_a_transferrable_tokens_action();

            bool ask_user_to_confirm_transfer = !is_transfer_change_back_to_me();
            if (ask_user_to_confirm_transfer) {
            
                ask_user_for_confirmation_of_transfer_if_to_other_address();
                PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to review & accept the transfer.\n");

                os_memcpy(debug_print_transfer, &parse_state->transfer, sizeof(transfer_t));
                print_transfer(debug_print_transfer);

                ux_block();
            }
            user_accepted_transfer_data();
            break;
        case ParseFieldResultNonTransferDataFound:
            // PRINTF("@@@ Finished parsing non Transferrable Tokens Action @@@\n");

            did_identify_a_non_transferrable_tokens_action();

            if (parse_state->user_has_accepted_non_transfer_data) {
                user_accepted_non_transfer_data();
            } else {
                ask_user_for_confirmation_of_non_transfer_data();
                PRINTF("\n\n  ---> Waiting for input from user on Ledger device, needs to accept non-transfer data.\n");
                ux_block();
                user_accepted_non_transfer_data();
            }
            break;
        case ParseFieldResultParsedPartOfTransfer:
            break;
    }
}

void empty_buffer(void) {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

void received_tx_bytes_from_host_machine(
    uint8_t *bytes,
    uint16_t number_of_newly_received_tx_bytes
) {
    ui_update_progress_display();

    if (finished_parsing_all_actions() || !has_action_field()) {
        // PRINTF("Skipping parsing field, finished parsing actions: %s, has action field: %s\n", finished_parsing_all_actions() ? "TRUE" : "FALSE", has_action_field() ? "TRUE" : "FALSE");
        return;
    }
     
    do_parse_field_from_tx_bytes(
        &parse_state->next_action_field_to_parse,
        bytes,
        &parse_state->debug_print_transfer
    );
    parse_state->next_action_field_to_parse.is_destroyed = true;
  
}

void print_next_action_field_to_parse(void) {
    print_action_field(&parse_state->next_action_field_to_parse);
}

void received_action_field_metadata_bytes_from_host_machine(
    ActionFieldType action_field_type,
    uint8_t *bytes,
    uint16_t number_of_bytes_received
) {
    empty_action_field();

    initialize_action_field_with_bytes(
        &parse_state->next_action_field_to_parse,
        action_field_type,
        bytes,
        number_of_bytes_received
    );

    assert(parse_state->next_action_field_to_parse.byte_interval.start_index_in_tx == ctx->number_of_tx_bytes_received);
}

void reset_parse_state(void) {
    parse_state->user_has_accepted_non_transfer_data = false;
    parse_state->is_users_public_key_calculated = false;
    
    empty_action_field();
    empty_transfer();

    ui_init_progress_display();
}
