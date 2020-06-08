#include "ux.h"

static signAtomContext_t *ctx = &global.signAtomContext;

typedef enum {
    ReviewStart = 0,
    ReviewAddress,
    ReviewAmount,
    ReviewRRI
} ReviewTransferStep;


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
    return &(ctx->transfers[indexOfNextTransferToNotMyAddress]);
}

static const bagl_element_t* preprocessor_for_seeking(const bagl_element_t *element, size_t lengthOfStringSeekedIn) {
    if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
        (element->component.userid == 2 && ctx->displayIndex == lengthOfStringSeekedIn - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)) {
        return NULL;
    }
    return element;
}


static void resetDisplay() {
    os_memset(ctx->partialString12Char, 0x00, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    os_memmove(ctx->partialString12Char, ctx->fullString, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    ctx->partialString12Char[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';
    ctx->displayIndex = 0;
}

static void copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewTransferStep step) {

    os_memset(ctx->fullString, 0x00, MAX_LENGTH_FULL_STR_DISPLAY);

    Transfer *transfer = nextTransfer();
    switch (step)
    {
    case ReviewStart: 
    {
        size_t lengthOfTransferAtIndexString = DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE;
        snprintf(ctx->fullString, lengthOfTransferAtIndexString, "tx@index: %d", ctx->numberOfTransfersToNotMyAddressApproved);
        ctx->lengthOfFullString = lengthOfTransferAtIndexString;
        break;
    }
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
    case ReviewRRI:
    {
        size_t number_of_chars_to_copy = RADIX_RRI_STRING_LENGTH_MAX + 1;
        assert(number_of_chars_to_copy <= MAX_LENGTH_FULL_STR_DISPLAY);
        ctx->lengthOfFullString = to_string_rri(&(transfer->tokenDefinitionReference), ctx->fullString, number_of_chars_to_copy, false);
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
    int tx = deriveSignRespond(ctx->bip32Path, ctx->hash);
    io_exchange_with_code(SW_OK, tx);
    ui_idle();
}

static const bagl_element_t ui_sign_confirm_signing[] = APPROVAL_SCREEN_TWO_LINES("Sign w key", global.signAtomContext.bip32PathString);

static unsigned int ui_sign_confirm_signing_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    return reject_or_approve(button_mask, button_mask_counter, didFinishSignAtomFlow);
}

static const bagl_element_t ui_sign_approve_hash_compare[] = SEEK_SCREEN("Verify Hash");

static const bagl_element_t *ui_prepro_sign_approve_hash_compare(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, HASH256_BYTE_COUNT * 2);
}

static void didApproveHashProceedWithFinalConfirmationBeforeSigning() {
    UX_DISPLAY(ui_sign_confirm_signing, NULL);
}

static unsigned int ui_sign_approve_hash_compare_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, didApproveHashProceedWithFinalConfirmationBeforeSigning);
}

static void proceedToDisplayingHash() {
    // PRINTF("\nHash should be visible on display: %.*H\n", HASH256_BYTE_COUNT, ctx->hash);
    size_t lengthOfHashString = HASH256_BYTE_COUNT * 2 + 1; // + 1 for NULL
    bin2hex(ctx->fullString, lengthOfHashString, ctx->hash, HASH256_BYTE_COUNT); 
    ctx->lengthOfFullString = lengthOfHashString;
    resetDisplay();
    UX_DISPLAY(ui_sign_approve_hash_compare, ui_prepro_sign_approve_hash_compare);
}
// ===== END ====== APPROVE HASH->SIGN =================



// ===== START ====== APPROVE DETAILS OF EACH TRANSFER  =================
static void proceedWithNextTransfer();

static void proceedWithNextTransferIfAnyElseDisplayHash()
{
    // approved RRI -> finished with this transfer => proceed
    ctx->numberOfTransfersToNotMyAddressApproved++;
    if (ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress) {
        proceedWithNextTransfer();
    } else {
        // Finished accepting all transfers
        proceedToDisplayingHash();
    }
}



// ==== START ======= STEP 4/4: RRI ========
static const bagl_element_t ui_sign_approve_tx_step4of4_rri[] = SEEK_SCREEN("Token:");

static const bagl_element_t *ui_prepro_sign_approve_tx_step4of4_rri(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, RADIX_RRI_STRING_LENGTH_MAX);
}

static unsigned int ui_sign_approve_tx_step4of4_rri_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, proceedWithNextTransferIfAnyElseDisplayHash);
}

static void prepareForApprovalOfRRI() {
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewRRI);
    UX_DISPLAY(ui_sign_approve_tx_step4of4_rri, ui_prepro_sign_approve_tx_step4of4_rri);
}
// ==== END ======= STEP 4/4: RRI ========



// ==== START ======= STEP 3/4: Amount ========

// ==== START == NO SEEK
static const bagl_element_t ui_sign_approve_tx_step3of4_amount_no_seek[] = APPROVAL_SCREEN("Amount:");

static unsigned int ui_sign_approve_tx_step3of4_amount_no_seek_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, prepareForApprovalOfRRI);
}
// === END == NO SEEK

static const bagl_element_t ui_sign_approve_tx_step3of4_amount_seek[] = SEEK_SCREEN("Amount:");

static const bagl_element_t *ui_prepro_sign_approve_tx_step3of4_amount_seek(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, UINT256_DEC_STRING_MAX_LENGTH);
}

static unsigned int ui_sign_approve_tx_step3of4_amount_seek_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, prepareForApprovalOfRRI);
}

static void prepareForApprovalOfAmount() {
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewAmount);
    if (ctx->lengthOfFullString > DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE) {
        UX_DISPLAY(ui_sign_approve_tx_step3of4_amount_seek, ui_prepro_sign_approve_tx_step3of4_amount_seek);
    } else {
        UX_DISPLAY(ui_sign_approve_tx_step3of4_amount_no_seek, NULL);
    }
}
// ==== END ======= STEP 3/4: Amount ========




// ==== START ======= STEP 2/4: Address ========
static const bagl_element_t ui_sign_approve_tx_step2of4_address[] = SEEK_SCREEN("To address:");

static const bagl_element_t *ui_prepro_sign_approve_tx_step2of4_address(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, UINT256_DEC_STRING_MAX_LENGTH);
}

static unsigned int ui_sign_approve_tx_step2of4_address_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return seek_left_right_or_approve(button_mask, button_mask_counter, prepareForApprovalOfAmount);
}

static void prepareForApprovalOfAddress() {
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewAddress);
    UX_DISPLAY(ui_sign_approve_tx_step2of4_address, ui_prepro_sign_approve_tx_step2of4_address);
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
    copyOverTransferDataToFullStringAndResetDisplayForStep(ReviewStart);

    UX_DISPLAY(ui_sign_approve_tx_step1of4_txid, NULL);
}
// ==== END ==== APPROVE TX DETAILS STEP 1/4: Transfer number =====

static void proceedToDisplayingDetailsForEachTransfer() {
    ctx->numberOfTransfersToNotMyAddressApproved = 0;
    proceedWithNextTransfer();
}
// ===== END ====== APPROVE DETAILS OF EACH TRANSFER  =================



// ===== START ====== APPROVE NO OF TRANSFERS =================
static const bagl_element_t ui_sign_approve_transfers[] = APPROVAL_SCREEN("Found #TX:");

static unsigned int ui_sign_approve_transfers_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingDetailsForEachTransfer);
}

static void printRRI(RadixResourceIdentifier *rri) {
    const size_t max_length = RADIX_RRI_STRING_LENGTH_MAX;
    char rri_utf8_string[max_length];
    to_string_rri(rri, rri_utf8_string, max_length, true);
    PRINTF("%s", rri_utf8_string);
}

static void printTokenAmount(TokenAmount *tokenAmount) {
    const size_t max_length = (UINT256_DEC_STRING_MAX_LENGTH + 1); // +1 for null
    char dec_string[max_length];
    to_string_uint256(tokenAmount, dec_string, max_length);
    PRINTF("%s", dec_string);
}

static void filterOutTransfersBackToMeFromAllTransfers(bool debugPrintTransferToConsole) {

    cx_ecfp_public_key_t myPublicKeyCompressed;
    
    deriveRadixKeyPair(
        ctx->bip32Path, 
        &myPublicKeyCompressed, 
        NULL // dont write private key
    );

    for (int transferIndex = 0; transferIndex < ctx->numberOfTransferrableTokensParticlesParsed; ++transferIndex)
    {
        Transfer transfer = ctx->transfers[transferIndex];
        if (matchesPublicKey(&transfer.address, &myPublicKeyCompressed))
        {
            continue; // dont display "change" (money back) to you (transferIndex.e. transfers to your own address.)
        } else {
            ctx->indiciesTransfersToNotMyAddress[ctx->numberOfTransfersToNotMyAddress] = transferIndex;
            ctx->numberOfTransfersToNotMyAddress++;
        }

        if (!debugPrintTransferToConsole) {
            continue;
        }
        // DEBUG PRINT ALL PARSED TransferrableTokensParticles
        if (transferIndex == 0) {
            PRINTF("\n**************************************\n");
        }
        PRINTF("Transfer %u\n", ctx->numberOfTransfersToNotMyAddress);
        PRINTF("    recipient address: "); printRadixAddress(&transfer.address); PRINTF("\n");
        PRINTF("    amount: "), printTokenAmount(&transfer.amount); PRINTF(" E-18\n");
        PRINTF("    token (RRI): "); printRRI(&transfer.tokenDefinitionReference); PRINTF("\n");
        PRINTF("\n");
        if (transferIndex == ctx->numberOfTransferrableTokensParticlesParsed - 1) {
            PRINTF("**************************************\n");
        }
    }
}

static void proceedToDisplayingTransfersIfAny() {

    if (ctx->numberOfTransferrableTokensParticlesParsed == 0)
    {
        proceedToDisplayingHash();
    }
    else
    {
        bool debugPrintTransfers = false;
        filterOutTransfersBackToMeFromAllTransfers(debugPrintTransfers);

        if (ctx->numberOfTransfersToNotMyAddress == 1) {
            prepareForApprovalOfAddress();
        } else {
            if (ctx->numberOfTransfersToNotMyAddress > 9) {
                snprintf(ctx->partialString12Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "no of tx:%02d\0", ctx->numberOfTransfersToNotMyAddress);
            } else {
                snprintf(ctx->partialString12Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "no of tx: %d\0", ctx->numberOfTransfersToNotMyAddress);
            }
        }
        UX_DISPLAY(ui_sign_approve_transfers, NULL);
    }
}
// ===== END ====== APPROVE NO OF TRANSFERS =================



// ===== START ====== APPROVE NON-TRANSFER DATA =================
static const bagl_element_t ui_sign_approve_nonTransferData[] = APPROVAL_SCREEN_TWO_LINES("Non-transfer", "data found!!");

static unsigned int ui_sign_approve_nonTransferData_button(unsigned int button_mask, unsigned int button_mask_counter) {
    return reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingTransfersIfAny);
}

static void notifyNonTransferDataFound() {
    // PRINTF("Non-tranfer\ndata found!!\n");
    UX_DISPLAY(ui_sign_approve_nonTransferData, NULL);
}
// ===== END ====== APPROVE NON-TRANSFER DATA =================



void presentAtomContentsOnDisplay() {

    if (ctx->numberOfNonTransferrableTokensParticlesIdentified > 0) {
        notifyNonTransferDataFound();
    } else {
        proceedToDisplayingTransfersIfAny();
    }
}