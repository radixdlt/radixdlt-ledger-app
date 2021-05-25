#include "sign_tx_ui.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "base_conversion.h"
#include "common_macros.h"



static sign_tx_context_t *ctx = &global.sign_tx_context;

typedef enum {
    ReviewAddress = 0,
    ReviewAmount,
    ReviewRRI
} ReviewTXStep;


// // ===== START ===== HELPERS =========

static void prepare_display_with_transfer_data_step(ReviewTXStep step)
{
    clear_lower_line_long();
    transfer_t transfer = ctx->parse_state.transfer;

    switch (step)
    {
    case ReviewAddress:
    {
        size_t number_of_chars_to_copy = RADIX_ADDRESS_BECH32_CHAR_COUNT_MAX + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
        G_ui_state.length_lower_line_long = to_string_radix_address(&transfer.address, G_ui_state.lower_line_long, number_of_chars_to_copy);
        break;
    }
    case ReviewAmount:
    {
        size_t number_of_chars_to_copy = UINT256_DEC_STRING_MAX_LENGTH + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
       G_ui_state.length_lower_line_long = to_string_uint256(&transfer.amount, G_ui_state.lower_line_long, number_of_chars_to_copy);
        break;
    }
    case ReviewRRI: {

        size_t offset = to_string_rri_null_term_or_not(
            &transfer.token_definition_reference, 
            G_ui_state.lower_line_long, 
            RADIX_RRI_MAX_LENGTH_SYMBOL, 
            true,
            false
        );

        size_t length_of_string___comma_space_Full_Identifier_color_space = 19;
        os_memcpy(
            G_ui_state.lower_line_long + offset,
            ", Full Identifier: ",
            length_of_string___comma_space_Full_Identifier_color_space
        );
        offset += length_of_string___comma_space_Full_Identifier_color_space;

        offset += to_string_rri_null_term_or_not(
            &transfer.token_definition_reference, 
            G_ui_state.lower_line_long + offset, 
            MAX_LENGTH_FULL_STR_DISPLAY - offset,
            false,
            true
        );

       G_ui_state.length_lower_line_long = offset;
        break;
    }
    default:
        FATAL_ERROR("Unknown step: %d", step);
    }
}
// ===== END ===== HELPERS =========


static void do_ask_user_for_confirmation_of_signing_hash();

static void prepare_for_displaying_of_hash() {
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL
    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.lower_line_long);
    G_ui_state.length_lower_line_long = lengthOfHashString;
}

bool finished_parsing_all_actions();

static bool finished_parsing_whole_tx() {
    return ctx->number_of_tx_bytes_received == ctx->tx_byte_count && finished_parsing_all_actions();
}


void ui_update_progress_display();
static void redisplay_progress() {
    ui_init_progress_display();
}

static void unblock_ux(int tx) {
    io_exchange_with_code(SW_OK, tx);

    if (finished_parsing_whole_tx()) {
        ui_idle();
    } else {
        redisplay_progress();
    }
}

static void continue_sign_tx_flow() {
    unblock_ux(0);
}

static void did_approve_signing_of_hash() {

    int tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
    assert(tx == ECSDA_SIGNATURE_BYTE_COUNT);

    PRINTF("Signed tx, resulting signature: %.*h\n", ECSDA_SIGNATURE_BYTE_COUNT, G_io_apdu_buffer);
    PRINTF("\n\n._-=~$#@   END OF SIGN TX   @#$=~-_.\n\n");
    
	unblock_ux(tx);
}

static void finished_approving_transfer() {
    continue_sign_tx_flow();
}

static void did_approve_rri() {
    finished_approving_transfer();
}

static void did_approve_non_transfer_data() {
    continue_sign_tx_flow();
}

static void prepare_for_approval_of_rri()
{
    prepare_display_with_transfer_data_step(ReviewRRI);
    display_value("Token:", did_approve_rri);
}

static void prepare_for_approval_of_amount() {
    prepare_display_with_transfer_data_step(ReviewAmount);
    display_value("Amount:", prepare_for_approval_of_rri);
}

static void prepare_for_approval_of_address() {
    prepare_display_with_transfer_data_step(ReviewAddress);
    display_value("To address:", prepare_for_approval_of_amount);
}

static void do_ask_user_for_confirmation_of_signing_hash() {
    display_lines("Sign content", "Confirm?", did_approve_signing_of_hash);
}

static unsigned short ux_visible_element_index = 0;

static const ux_menu_entry_t ui_hack_as_menu_progress_update[] = {
	{NULL, NULL, 0, NULL, "Parsing tx", G_ui_state.lower_line_short, 0, 0},
	UX_MENU_END,
};


bool finished_parsing_all_actions(void) {
    bool parsed_all_actions = has_identified_all_actions(&ctx->parse_state.actions_counter);
    return parsed_all_actions;
}

void ask_user_to_verify_hash_before_signing(void) {
    prepare_for_displaying_of_hash();
    display_value("Verify Hash", do_ask_user_for_confirmation_of_signing_hash);
}

void ask_user_for_confirmation_of_non_transfer_data(void) {
    display_lines("WARNING", "DATA Found", did_approve_non_transfer_data);
}

void ask_user_for_confirmation_of_transfer_if_to_other_address(void) {
    display_lines("Review", "transfer", prepare_for_approval_of_address);
}

void ui_init_progress_display(void) {
    UX_MENU_DISPLAY(0, ui_hack_as_menu_progress_update, NULL);
    ux_visible_element_index = G_ux.stack[0].element_index;
    ui_update_progress_display();
}


void ui_update_progress_display(void) {
    reset_ui();

    size_t percentage = (100 * ctx->number_of_tx_bytes_received / ctx->tx_byte_count);

    snprintf(
        G_ui_state.lower_line_short, 
        DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
        "%02d%% done.", percentage
    );

    UX_REDISPLAY_IDX(ux_visible_element_index);
}
