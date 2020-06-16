#include "ux.h"
#include "base_conversion.h"

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
    reset_ui();
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

    ui_fullStr_to_partial();
}
// ===== END ===== HELPERS =========

// ===== START ====== APPROVE HASH->SIGN =================
static void didFinishSignAtomFlow()
{
    int tx = derive_sign_move_to_global_buffer(ctx->bip32Path, ctx->hash);
	io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static const bagl_element_t ui_sign_confirm_signing[] = APPROVAL_SCREEN_TWO_LINES("Sign content", "Confirm?");
static unsigned int ui_sign_confirm_signing_button(
    unsigned int button_mask,
    unsigned int button_mask_counter)
{
    return reject_or_approve(button_mask, button_mask_counter, didFinishSignAtomFlow);
}

static void askUserForFinalConfirmation() {
    UX_DISPLAY(ui_sign_confirm_signing, NULL);
}


static void prepareForDisplayingHash()
{
    reset_ui();
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL

    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, G_ui_state.fullString);

    G_ui_state.lengthOfFullString = lengthOfHashString;
    ui_fullStr_to_partial();

    display_seek_if_needed("Verify Hash", askUserForFinalConfirmation);
}
// ===== END ====== APPROVE HASH->SIGN =================



// ===== START ====== APPROVE DETAILS OF EACH TRANSFER  =================
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
    display_seek_if_needed("Token:", proceedWithNextTransferIfAnyElseDisplayHash);
}

static void prepareForApprovalOfAmount() {
    prepare_display_with_transfer_data_step(ReviewAmount);
    display_seek_if_needed("Amount:", prepareForApprovalOfRRI);
}

static void prepareForApprovalOfAddress() {
    prepare_display_with_transfer_data_step(ReviewAddress);
    display_seek_if_needed("To address:", prepareForApprovalOfAmount);
}

static void proceedWithNextTransfer()
{
    assert(ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress);

    reset_ui();
    size_t lengthOfTransferAtIndexString = DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE;
    snprintf(G_ui_state.fullString, lengthOfTransferAtIndexString, "tx@index: %d", ctx->numberOfTransfersToNotMyAddressApproved);
    G_ui_state.lengthOfFullString = lengthOfTransferAtIndexString;
    ui_fullStr_to_partial();

    display_seek_if_needed("Approve TX:", prepareForApprovalOfAddress);
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
            snprintf(
                G_ui_state.partialString12Char,
                DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
                "no of tx:%2d", 
                ctx->numberOfTransfersToNotMyAddress
            );
            
            display_seek_if_needed("Found #TX:", proceedWithNextTransfer);
        }
    }
}

// ===== START ====== APPROVE NON-TRANSFER DATA =================
static const bagl_element_t ui_sign_approve_nonTransferData[] = APPROVAL_SCREEN_TWO_LINES("Non-transfer", "data found!!");

static unsigned int ui_sign_approve_nonTransferData_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingTransfersIfAny);
}

static void notifyNonTransferDataFound() {    
    UX_DISPLAY(ui_sign_approve_nonTransferData, NULL);
}
// ===== END ====== APPROVE NON-TRANSFER DATA =================



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