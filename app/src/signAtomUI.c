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
    Transfer transfer = ctx->transfer;

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

void askUserForFinalConfirmation() {
    display_lines("Sign content", "Confirm?", didFinishSignAtomFlow);
}

static void prepareForDisplayingHash()
{
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL

    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.lower_line_long);

    G_ui_state.length_lower_line_long = lengthOfHashString;

    display_value("Verify Hash", askUserForFinalConfirmation);
}


void askUserForConfirmationOfHash() {
    prepareForDisplayingHash();
}

static void didApproveTransfer()
{

    unsigned int tx = 0;
    G_io_apdu_buffer[tx++] = 0x90;
    G_io_apdu_buffer[tx++] = 0x00;
    // Send back the response, do not restart the event loop
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
    // Display back the original UX
    ui_idle();
}

void prepareForApprovalOfRRI()
{
    prepare_display_with_transfer_data_step(ReviewRRI);
    display_value("Token:", didApproveTransfer);
}

void prepareForApprovalOfAmount() {
    prepare_display_with_transfer_data_step(ReviewAmount);
    display_value("Amount:", prepareForApprovalOfRRI);
}

void prepareForApprovalOfAddress() {
    prepare_display_with_transfer_data_step(ReviewAddress);
    display_value("To address:", prepareForApprovalOfAmount);
}

bool is_transfer_change_back_to_me() {
    cx_ecfp_public_key_t myPublicKeyCompressed;
    
    derive_radix_key_pair(
        ctx->bip32_path, 
        &myPublicKeyCompressed, 
        NULL // dont write private key
    );

    return matchesPublicKey(&ctx->transfer.address, &myPublicKeyCompressed);
}

void askUserForConfirmationOfTransferIfNeeded() {

    if (is_transfer_change_back_to_me()) 
    {
        PRINTF("Skipped reviewing transfer since it was change back to user...trying to return by calling `io_exchange(IO_RETURN_AFTER_TX, 0);`\n");

        io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, 0);
        return;
    }
    
    display_lines("Review", "transfer", prepareForApprovalOfAddress);

}

// // static void proceedToDisplayingTransfersIfAny() {
// //     if (ctx->numberOfTransferrableTokensParticlesParsed == 0)
// //     {
// //         prepareForDisplayingHash();
// //     }
// //     else
// //     {
// //         filterOutTransfersBackToMeFromAllTransfers();

// //         if (ctx->numberOfTransfersToNotMyAddress == 0) {
// //             // Either Burn Action or Mint Action
// //             // assert Data found
// //             assert(ctx->numberOfNonTransferrableTokensParticlesIdentified > 0); // Expect 
// //             prepareForDisplayingHash();
// //         } else if (ctx->numberOfTransfersToNotMyAddress == 1) {
// //             prepareForApprovalOfAddress();
// //         } else {
// //             char upper_line_with_value[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE + 1];
// //             snprintf(upper_line_with_value, 8, "Found %d", ctx->numberOfTransfersToNotMyAddress);
// //             G_ui_state.length_lower_line_long = 10;
// //             display_lines(upper_line_with_value, "transfers", proceedWithNextTransfer);
// //         }
// //     }
// // }

// static void didApproveNonTransferData() {
//     ctx->hasApprovedNonTransferData = true;
// }

// static void notifyNonTransferDataFound() {
//     display_lines("Non-Transfer", "data found!!", didApproveNonTransferData);
// }


// void notifyNonTransferDataFoundIfNeeded() {
//     if (ctx->hasApprovedNonTransferData) {
//         return;
//     }
//     notifyNonTransferDataFound();
// }

// // void presentAtomContentsOnDisplay() {
// //     if (ctx->numberOfNonTransferrableTokensParticlesIdentified > 0)
// //     {
// //         notifyNonTransferDataFound();
// //     }
// //     else
// //     {
// //         proceedToDisplayingTransfersIfAny();
// //     }
// // }