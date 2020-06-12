#include "ux.h"
#include "base_conversion.h"

static signAtomContext_t *ctx = &global.signAtomContext;

typedef enum {
    ReviewAddress = 0,
    ReviewAmount,
    ReviewRRI
} ReviewAtomStep;


// ===== START ===== HELPERS =========
#define APPROVAL_SCREEN(textLine1) APPROVAL_SCREEN_TWO_LINES(textLine1, global.signAtomContext.partialString12Char)

#define SEEK_SCREEN(textLine1) SEEK_SCREEN_TWO_LINES(textLine1, global.signAtomContext.partialString12Char)

static unsigned int reject_or_approve(
    unsigned int button_mask, 
    unsigned int button_mask_counter,
    void (*didApproveCallback)(void)
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // Approve
            didApproveCallback();
            break;
        }
    }
    return 0;
}

static unsigned int seek_left_right_or_approve(
    unsigned int button_mask, 
    unsigned int button_mask_counter,
    void (*didApproveCallback)(void)
) {
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		// Decrement the displayIndex when the left button is pressed (or held).
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialString12Char, ctx->fullString + ctx->displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < sizeof(ctx->fullString) - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialString12Char, ctx->fullString + ctx->displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
        didApproveCallback();
        break;
    }
	return 0;
}

static Transfer* nextTransfer() {
    assert(ctx->numberOfTransfersToNotMyAddress > 0);

    uint8_t indexOfNextTransferToNotMyAddress = ctx->indiciesTransfersToNotMyAddress[ctx->numberOfTransfersToNotMyAddressApproved];
   
    assert(indexOfNextTransferToNotMyAddress < ctx->numberOfTransferrableTokensParticlesParsed);
    return &(ctx->transfers[indexOfNextTransferToNotMyAddress]);
}

static const bagl_element_t* preprocessor_for_seeking(const bagl_element_t *element) {
    if (
        (element->component.userid == 1 && ctx->displayIndex == 0) 
        ||
        (element->component.userid == 2 
        && 
        (ctx->displayIndex == (ctx->lengthOfFullString - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)))) 
    {
        return NULL;
    }
    return element;
}

static void clearFullString() {
    os_memset(ctx->fullString, 0x00, MAX_LENGTH_FULL_STR_DISPLAY);
}

static void resetDisplay() {
    os_memset(ctx->partialString12Char, 0x00, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    os_memmove(ctx->partialString12Char, ctx->fullString, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    ctx->partialString12Char[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';
    ctx->displayIndex = 0;
}

static void copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewAtomStep step)
{
    clearFullString();
    Transfer *transfer = nextTransfer();
    switch (step)
    {
    case ReviewAddress:
    {
        size_t number_of_chars_to_copy = RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
        ctx->lengthOfFullString = to_string_radix_address(&(transfer->address), ctx->fullString, number_of_chars_to_copy);
        break;
    }
    case ReviewAmount:
    {
        size_t number_of_chars_to_copy = UINT256_DEC_STRING_MAX_LENGTH + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
        ctx->lengthOfFullString = to_string_uint256(&(transfer->amount), ctx->fullString, number_of_chars_to_copy);
        break;
    }
    case ReviewRRI: {

        size_t offset = to_string_rri_null_term_or_not(
            &(transfer->tokenDefinitionReference), 
            ctx->fullString, 
            RADIX_RRI_MAX_LENGTH_SYMBOL, 
            true,
            false
        );

        size_t length_of_string___comma_space_Full_Identifier_color_space = 19;
        os_memcpy(
            ctx->fullString + offset,
            ", Full Identifier: ",
            length_of_string___comma_space_Full_Identifier_color_space
        );
        offset += length_of_string___comma_space_Full_Identifier_color_space;

        offset += to_string_rri_null_term_or_not(
            &(transfer->tokenDefinitionReference), 
            ctx->fullString + offset, 
            MAX_LENGTH_FULL_STR_DISPLAY - offset,
            false,
            true
        );

        ctx->lengthOfFullString = offset;
        break;
    }
    default:
        FATAL_ERROR("Unknown step: %d", step);
    }

    resetDisplay();
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

static const bagl_element_t ui_sign_approve_hash_compare[] = SEEK_SCREEN("Verify Hash");
static unsigned int ui_sign_approve_hash_compare_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, askUserForFinalConfirmation);
}

static void prepareForDisplayingHash()
{
    clearFullString();
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL

    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, ctx->fullString);

    ctx->lengthOfFullString = lengthOfHashString;
    resetDisplay();

    UX_DISPLAY(ui_sign_approve_hash_compare, preprocessor_for_seeking);
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

// ==== START ======= STEP 4/4: RRI ========
static const bagl_element_t ui_sign_approve_tx_step4of4_rri[] = SEEK_SCREEN("Token:");
static unsigned int ui_sign_approve_tx_step4of4_rri_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, proceedWithNextTransferIfAnyElseDisplayHash);
}

static void prepareForApprovalOfRRI()
{
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewRRI);
    UX_DISPLAY(ui_sign_approve_tx_step4of4_rri, preprocessor_for_seeking);
}
// ==== END ======= STEP 4/4: RRI ========



// ==== START ======= STEP 3/4: Amount ========

static const bagl_element_t ui_sign_approve_tx_step3of4_amount_no_seek[] = APPROVAL_SCREEN("Amount:");
static unsigned int ui_sign_approve_tx_step3of4_amount_no_seek_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, prepareForApprovalOfRRI);
}

static const bagl_element_t ui_sign_approve_tx_step3of4_amount_seek[] = SEEK_SCREEN("Amount:");
static unsigned int ui_sign_approve_tx_step3of4_amount_seek_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, prepareForApprovalOfRRI);
}

static void prepareForApprovalOfAmount() {
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewAmount);
    if (ctx->lengthOfFullString > DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE) {
        UX_DISPLAY(ui_sign_approve_tx_step3of4_amount_seek, preprocessor_for_seeking);
    } else {
        UX_DISPLAY(ui_sign_approve_tx_step3of4_amount_no_seek, NULL);
    }
}
// ==== END ======= STEP 3/4: Amount ========




// ==== START ======= STEP 2/4: Address ========
static const bagl_element_t ui_sign_approve_tx_step2of4_address[] = SEEK_SCREEN("To address:");
static unsigned int ui_sign_approve_tx_step2of4_address_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, prepareForApprovalOfAmount);
}

static void prepareForApprovalOfAddress() {
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewAddress);
    UX_DISPLAY(ui_sign_approve_tx_step2of4_address, preprocessor_for_seeking);
}
// ==== END ======= STEP 2/4: Address ========




// ==== START ==== APPROVE TX DETAILS STEP 1/4: Transfer number =====
static const bagl_element_t ui_sign_approve_tx_step1of4_txid[] = APPROVAL_SCREEN("Approve TX:");
static unsigned int ui_sign_approve_tx_step1of4_txid_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    return reject_or_approve(button_mask, button_mask_counter, prepareForApprovalOfAddress);
}

static void proceedWithNextTransfer() {
    assert(ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress);

    clearFullString();
    size_t lengthOfTransferAtIndexString = DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE;
    snprintf(ctx->fullString, lengthOfTransferAtIndexString, "tx@index: %d", ctx->numberOfTransfersToNotMyAddressApproved);
    ctx->lengthOfFullString = lengthOfTransferAtIndexString;
    resetDisplay();

    UX_DISPLAY(ui_sign_approve_tx_step1of4_txid, NULL);
}
// ==== END ==== APPROVE TX DETAILS STEP 1/4: Transfer number =====

static void proceedToDisplayingDetailsForEachTransfer() {
    proceedWithNextTransfer();
}
// ===== END ====== APPROVE DETAILS OF EACH TRANSFER  =================



// ===== START ====== APPROVE NO OF TRANSFERS =================
static const bagl_element_t ui_sign_approve_transfers[] = APPROVAL_SCREEN("Found #TX:");

static unsigned int ui_sign_approve_transfers_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingDetailsForEachTransfer);
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
                ctx->partialString12Char,
                DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
                "no of tx:%2d", 
                ctx->numberOfTransfersToNotMyAddress
            );
            
            UX_DISPLAY(ui_sign_approve_transfers, NULL);
        }
    }
}
// ===== END ====== APPROVE NO OF TRANSFERS =================



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