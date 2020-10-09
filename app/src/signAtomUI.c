#include "ui.h"
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

static void didFinishSignAtomFlow()
{
    int tx = derive_sign_move_to_global_buffer(ctx->bip32_path, ctx->hash);
	io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

void ask_user_for_confirmation_of_signing_hash();

static void prepareForDisplayingHash()
{
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL

    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.lower_line_long);

    G_ui_state.length_lower_line_long = lengthOfHashString;

    display_value("Verify Hash", ask_user_for_confirmation_of_signing_hash);
}


static bool done_with_ux_for_atom_parsing() {
    return ctx->ux_state.number_of_identified_up_particles == ctx->ux_state.number_of_up_particles;
}

static void ask_user_to_verify_hash() {
    prepareForDisplayingHash();
}

static void continue_sign_atom_flow() {
    if (done_with_ux_for_atom_parsing()) {
        PRINTF("Done with parsing atom => confirm hash\n");
        ask_user_to_verify_hash();
    } else {
        io_exchange_with_code(SW_OK, 0);
        // Display back the original UX
        ui_idle();
    }
}


static void didApproveTransfer() {
    continue_sign_atom_flow();
}

static void didApproveNonTransferData() {
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

bool is_transfer_change_back_to_me() {
    if (!ctx->ux_state.is_users_public_key_calculated) {
        derive_radix_key_pair(
            ctx->bip32_path, 
            &ctx->ux_state.my_public_key_compressed, 
            NULL // dont write private key
        );
        ctx->ux_state.is_users_public_key_calculated = true;
    }

    return matchesPublicKey(&ctx->ux_state.transfer.address, &ctx->ux_state.my_public_key_compressed);
}

void ask_user_for_confirmation_of_signing_hash() {
    display_lines("Sign content", "Confirm?", didFinishSignAtomFlow);
    io_exchange(IO_ASYNCH_REPLY, 0);
}

void ask_user_for_confirmation_of_non_transfer_data() {
    display_lines("WARNING", "DATA Found", didApproveNonTransferData);
    io_exchange(IO_ASYNCH_REPLY, 0);
}

void ask_user_for_confirmation_of_transfer_if_to_other_address() {
    if (is_transfer_change_back_to_me()) {
        PRINTF("SKIPPED ASKING FOR USER INPUT ON LEDGER DEVICE FOR TRANSFER since it was 'change' back to user herself...\n");     
    } else {
        display_lines("Review", "transfer", prepareForApprovalOfAddress);
        io_exchange(IO_ASYNCH_REPLY, 0);
    }
}