#include "signAtomUI.h"
#include "global_state.h"
#include "key_and_signatures.h"
#include "base_conversion.h"
#include "common_macros.h"



static signAtomContext_t *ctx = &global.signAtomContext;

typedef enum {
    ReviewAddress = 0,
    ReviewAmount,
    ReviewRRI
} ReviewAtomStep;


// // ===== START ===== HELPERS =========

static void prepare_display_with_transfer_data_step(ReviewAtomStep step)
{
    clear_lower_line_long();
    Transfer transfer = ctx->ux_state.transfer;

    switch (step)
    {
    case ReviewAddress:
    {
        size_t number_of_chars_to_copy = RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1;
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

static void unblock_ux(int tx) {
    io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static void continue_sign_atom_flow() {
    unblock_ux(0);
}

static void did_approve_signing_of_hash() {

    int tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
    assert(tx == ECSDA_SIGNATURE_BYTE_COUNT);

    PRINTF("Signed atom, resulting signature: %.*h\n", ECSDA_SIGNATURE_BYTE_COUNT, G_io_apdu_buffer);
    PRINTF("\n\n._-=~$#@   END OF SIGN ATOM   @#$=~-_.\n\n");
    
	unblock_ux(tx);
}

static void finished_approving_transfer() {
    continue_sign_atom_flow();
}

static void did_approve_rri() {
    finished_approving_transfer();
}

static void did_approve_non_transfer_data() {
    continue_sign_atom_flow();
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

bool finished_parsing_all_particles() {
    bool parsed_all_particles = has_identified_all_particles(&ctx->ux_state.up_particles_counter);
    return parsed_all_particles;
}


bool finished_parsing_whole_atom() {
    return ctx->number_of_atom_bytes_received == ctx->atom_byte_count && finished_parsing_all_particles();
}


void ask_user_to_verify_hash_before_signing() {
    prepare_for_displaying_of_hash();
    display_value("Verify Hash", do_ask_user_for_confirmation_of_signing_hash);
}

void ask_user_for_confirmation_of_non_transfer_data() {
    display_lines("WARNING", "DATA Found", did_approve_non_transfer_data);
}

void ask_user_for_confirmation_of_transfer_if_to_other_address() {
    bool flow_is_short = ctx->ux_state.__DEBUG_MODE_skip_short_transfer_reviews;
    callback_t review_tx_callback = flow_is_short ? finished_approving_transfer : prepare_for_approval_of_address;
    display_lines("Review", "transfer", review_tx_callback);
    
}