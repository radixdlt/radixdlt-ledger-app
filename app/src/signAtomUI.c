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

static void prepareForDisplayingHash() {
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL
    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.lower_line_long);
    G_ui_state.length_lower_line_long = lengthOfHashString;
}

static void continue_sign_atom_flow() {
    PRINTF("APABANAN 'continue_sign_atom_flow' start'\n");
    io_exchange_with_code(SW_OK, 0);
    ui_idle();
    PRINTF("APABANAN 'continue_sign_atom_flow' END\n");
}

static void didFinishSignAtomFlow()
{
    PRINTF("APABANAN 'didFinishSignAtomFlow' start: calling 'io_exchange(IO_RETURN_AFTER_TX)'\n");
    int tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
	io_exchange_with_code(SW_OK, tx);
    ui_idle();
    PRINTF("APABANAN 'didFinishSignAtomFlow' END\n");
}

static void didApproveTransfer() {
    PRINTF("APABANAN signAtomUI 'didApproveTransfer'\n");
    continue_sign_atom_flow();
}

static void didApproveNonTransferData() {
    PRINTF("APABANAN signAtomUI 'didApproveNonTransferData'\n");
    continue_sign_atom_flow();
}

static void prepareForApprovalOfRRI()
{
    prepare_display_with_transfer_data_step(ReviewRRI);
    display_value("Token:", didApproveTransfer);
}

static void prepareForApprovalOfAmount() {
    prepare_display_with_transfer_data_step(ReviewAmount);
    display_value("Amount:", prepareForApprovalOfRRI);
}

static void prepareForApprovalOfAddress() {
    prepare_display_with_transfer_data_step(ReviewAddress);
    display_value("To address:", prepareForApprovalOfAmount);
}

static void do_ask_user_for_confirmation_of_signing_hash() {
    display_lines("Sign content", "Confirm?", didFinishSignAtomFlow);
}

void ask_user_to_verify_hash_before_signing() {
    prepareForDisplayingHash();
    display_value("Verify Hash", do_ask_user_for_confirmation_of_signing_hash);
}

void ask_user_for_confirmation_of_non_transfer_data() {
    display_lines("WARNING", "DATA Found", didApproveNonTransferData);
}

void ask_user_for_confirmation_of_transfer_if_to_other_address() {
    bool flow_is_short = ctx->ux_state.__DEBUG_MODE_skip_short_transfer_reviews;
    callback_t review_tx_callback = flow_is_short ? didApproveTransfer : prepareForApprovalOfAddress;
    display_lines("Review", "transfer", review_tx_callback);
    
}