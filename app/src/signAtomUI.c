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


// ===== START ===== HELPERS =========

static Transfer* nextTransfer() {
    assert(ctx->numberOfTransfersToNotMyAddress > 0);

    uint8_t indexOfNextTransferToNotMyAddress = ctx->indiciesTransfersToNotMyAddress[ctx->numberOfTransfersToNotMyAddressApproved];
   
    assert(indexOfNextTransferToNotMyAddress < ctx->numberOfTransferrableTokensParticlesParsed);
    return &(ctx->transfers[indexOfNextTransferToNotMyAddress]);
}

static void prepare_display_with_transfer_data_step(ReviewAtomStep step)
{
    clear_fullString();
    Transfer *transfer = nextTransfer();
    switch (step)
    {
    case ReviewAddress:
    {
        size_t number_of_chars_to_copy = RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
       G_ui_state.lengthOfFullString = to_string_radix_address(&(transfer->address), G_ui_state.fullString, number_of_chars_to_copy);
        break;
    }
    case ReviewAmount:
    {
        size_t number_of_chars_to_copy = UINT256_DEC_STRING_MAX_LENGTH + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
       G_ui_state.lengthOfFullString = to_string_uint256(&(transfer->amount), G_ui_state.fullString, number_of_chars_to_copy);
        break;
    }
    case ReviewRRI: {

        size_t offset = to_string_rri_null_term_or_not(
            &(transfer->tokenDefinitionReference), 
            G_ui_state.fullString, 
            RADIX_RRI_MAX_LENGTH_SYMBOL, 
            true,
            false
        );

        size_t length_of_string___comma_space_Full_Identifier_color_space = 19;
        os_memcpy(
            G_ui_state.fullString + offset,
            ", Full Identifier: ",
            length_of_string___comma_space_Full_Identifier_color_space
        );
        offset += length_of_string___comma_space_Full_Identifier_color_space;

        offset += to_string_rri_null_term_or_not(
            &(transfer->tokenDefinitionReference), 
            G_ui_state.fullString + offset, 
            MAX_LENGTH_FULL_STR_DISPLAY - offset,
            false,
            true
        );

       G_ui_state.lengthOfFullString = offset;
        break;
    }
    default:
        FATAL_ERROR("Unknown step: %d", step);
    }
}
// ===== END ===== HELPERS =========

static void didFinishSignAtomFlow()
{
    int tx = derive_sign_move_to_global_buffer(ctx->bip32Path, ctx->hash);
	io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static void askUserForFinalConfirmation() {
    display_lines("Sign content", "Confirm?", didFinishSignAtomFlow);
}

static void prepareForDisplayingHash()
{
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL

    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.fullString);

    G_ui_state.lengthOfFullString = lengthOfHashString;

    display_value("Verify Hash", askUserForFinalConfirmation);
}



static void proceedWithNextTransfer();

static void proceedWithNextTransferIfAnyElseDisplayHash()
{
    // approved RRI -> finished with this transfer => proceed
    ctx->numberOfTransfersToNotMyAddressApproved++;
    if (ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress)
    {
        proceedWithNextTransfer();
    }
    else
    {
        // Finished accepting all transfers
        prepareForDisplayingHash();
    }
}

static void prepareForApprovalOfRRI()
{
    prepare_display_with_transfer_data_step(ReviewRRI);
    display_value("Token:", proceedWithNextTransferIfAnyElseDisplayHash);
}

static void prepareForApprovalOfAmount() {
    prepare_display_with_transfer_data_step(ReviewAmount);
    display_value("Amount:", prepareForApprovalOfRRI);
}

static void prepareForApprovalOfAddress() {
    prepare_display_with_transfer_data_step(ReviewAddress);
    display_value("To address:", prepareForApprovalOfAmount);
}

static void proceedWithNextTransfer()
{
    assert(ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress);

    size_t lengthOfTransferAtIndexString = DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE;
    snprintf(G_ui_state.fullString, lengthOfTransferAtIndexString, "tx@index: %d", ctx->numberOfTransfersToNotMyAddressApproved);
    G_ui_state.lengthOfFullString = lengthOfTransferAtIndexString;

    display_value("Approve TX:", prepareForApprovalOfAddress);
}

static void filterOutTransfersBackToMeFromAllTransfers() {
    cx_ecfp_public_key_t myPublicKeyCompressed;
    
    derive_radix_key_pair(
        ctx->bip32Path, 
        &myPublicKeyCompressed, 
        NULL // dont write private key
    );

    for (int transferIndex = 0; transferIndex < ctx->numberOfTransferrableTokensParticlesParsed; ++transferIndex)
    {
        Transfer *transfer = &(ctx->transfers[transferIndex]);
        if (!matchesPublicKey(&(transfer->address), &myPublicKeyCompressed))
        {
            ctx->indiciesTransfersToNotMyAddress[ctx->numberOfTransfersToNotMyAddress] = transferIndex;
            ctx->numberOfTransfersToNotMyAddress++;
        }
    }
}

static void proceedToDisplayingTransfersIfAny() {
    if (ctx->numberOfTransferrableTokensParticlesParsed == 0)
    {
        prepareForDisplayingHash();
    }
    else
    {
        filterOutTransfersBackToMeFromAllTransfers();

        if (ctx->numberOfTransfersToNotMyAddress == 0) {
            // Either Burn Action or Mint Action
            // assert Data found
            assert(ctx->numberOfNonTransferrableTokensParticlesIdentified > 0); // Expect 
            prepareForDisplayingHash();
        } else if (ctx->numberOfTransfersToNotMyAddress == 1) {
            prepareForApprovalOfAddress();
        } else {
            G_ui_state.lengthOfFullString = snprintf(
                G_ui_state.fullString,
                DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
                "no of tx:%2d", 
                ctx->numberOfTransfersToNotMyAddress
            );
            
            display_value("Found #TX:", proceedWithNextTransfer);
        }
    }
}

static void notifyNonTransferDataFound() {
    display_lines("Non-Transfer", "data found!!", proceedToDisplayingTransfersIfAny);
}

void presentAtomContentsOnDisplay() {
    if (ctx->numberOfNonTransferrableTokensParticlesIdentified > 0)
    {
        notifyNonTransferDataFound();
    }
    else
    {
        proceedToDisplayingTransfersIfAny();
    }
}