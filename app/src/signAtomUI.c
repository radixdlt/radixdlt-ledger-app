// #include "global_state.h"
// #include "radix.h"
#include "ux.h"

static signAtomContext_t *ctx = &global.signAtomContext;


// ===== START ===== HELPERS =========

#define APPROVAL_SCREEN(textLine1, textLine2)   \
 {                                              \
    UI_BACKGROUND(),                            \
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),  \
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK), \
    UI_TEXT(0x00, 0, 11, 128, textLine1),       \
    UI_TEXT(0x00, 0, 26, 128, textLine2),       \
}

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

static void resetDisplayAndDisplayFieldInStructTransfer(ParticleField field) {

    os_memset(ctx->fullString, 0x00, RADIX_RRI_STRING_LENGTH_MAX);

    Transfer *transfer = nextTransfer();
    switch (field)
    {
    case AddressField:
    {
        to_string_radix_address(&(transfer->address), ctx->fullString, RADIX_ADDRESS_BASE58_CHAR_COUNT_MAX + 1);
        break;
    }
    case AmountField:
    {
        to_string_uint256(&(transfer->amount), ctx->fullString, UINT256_DEC_STRING_MAX_LENGTH + 1);
        break;
    }
    case TokenDefinitionReferenceField:
    {
        to_string_rri(&(transfer->tokenDefinitionReference), ctx->fullString, RADIX_RRI_STRING_LENGTH_MAX + 1, false);
        break;
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }

    resetDisplay();
}
// ===== END ===== HELPERS =========







// ===== START ====== APPROVE HASH->SIGN =================
static void didFinishSignAtomFlow()
{
    deriveSignRespond(ctx->bip32Path, ctx->hash);
    PRINTF("\n\nWOHO!!! DID FINISH FLOW!\n\n");
    ui_idle();
}

static const bagl_element_t ui_sign_confirm_signing[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	UI_TEXT(0x00, 0, 11, 128, "Sign w key"),
	UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.bip32PathString),
};

static unsigned int ui_sign_confirm_signing_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    reject_or_approve(button_mask, button_mask_counter, didFinishSignAtomFlow);
}

static const bagl_element_t ui_sign_approve_hash_compare[] = {
    UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 11, 128, "Verify Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

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
    seek_left_right_or_approve(button_mask, button_mask_counter, didApproveHashProceedWithFinalConfirmationBeforeSigning);
}

static void proceedToDisplayingHash() {
    PRINTF("\nHash should be visible on display: %.*H\n", HASH256_BYTE_COUNT, ctx->hash);
	bin2hex(ctx->fullString, HASH256_BYTE_COUNT*2+1, ctx->hash, HASH256_BYTE_COUNT); // + 1 for NULL
    resetDisplay();
    UX_DISPLAY(ui_sign_approve_hash_compare, ui_prepro_sign_approve_hash_compare);
}
// ===== END ====== APPROVE HASH->SIGN =================











// ===== START ====== APPROVE DETAILS OF EACH TRANSFER  =================
static void proceedToDisplayingDetailsForTransfer();

// ==== START ======= STEP 4/4: RRI ========
static const bagl_element_t ui_sign_approve_tx_step4of4_rri[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x00, 0, 11, 128, "Token:"),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static const bagl_element_t *ui_prepro_sign_approve_tx_step4of4_rri(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, RADIX_RRI_STRING_LENGTH_MAX);
}

static void didConfirmRRIEitherProceedWithNextTransferOrDisplayHashIfDone()
{
    // approved RRI -> finished with this transfer => proceed
    ctx->numberOfTransfersToNotMyAddressApproved++;
    if (ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress) {
        // Proceed with next transfer
        proceedToDisplayingDetailsForTransfer();
    } else {
        // Finished accepting all transfers
        proceedToDisplayingHash();
    }
}

static unsigned int ui_sign_approve_tx_step4of4_rri_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    seek_left_right_or_approve(button_mask, button_mask_counter, didConfirmRRIEitherProceedWithNextTransferOrDisplayHashIfDone);
}

static void prepareForApprovalOfRRI() {
    resetDisplayAndDisplayFieldInStructTransfer(TokenDefinitionReferenceField);
    UX_DISPLAY(ui_sign_approve_tx_step4of4_rri, ui_prepro_sign_approve_tx_step4of4_rri);
}
// ==== END ======= STEP 4/4: RRI ========






// ==== START ======= STEP 3/4: Amount ========
static const bagl_element_t ui_sign_approve_tx_step3of4_amount[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x00, 0, 11, 128, "Amount:"),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static const bagl_element_t *ui_prepro_sign_approve_tx_step3of4_amount(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, UINT256_DEC_STRING_MAX_LENGTH);
}

static void didApproveAmountInTransferProceedWithRRI()
{
    prepareForApprovalOfRRI();
}

static unsigned int ui_sign_approve_tx_step3of4_amount_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    seek_left_right_or_approve(button_mask, button_mask_counter, didApproveAmountInTransferProceedWithRRI);
}

static void prepareForApprovalOfAmount() {
    resetDisplayAndDisplayFieldInStructTransfer(AmountField);
    UX_DISPLAY(ui_sign_approve_tx_step3of4_amount, ui_prepro_sign_approve_tx_step3of4_amount);
}
// ==== END ======= STEP 3/4: Amount ========






// ==== START ======= STEP 2/4: Address ========
static const bagl_element_t ui_sign_approve_tx_step2of4_address[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x00, 0, 11, 128, "To address: "),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static const bagl_element_t *ui_prepro_sign_approve_tx_step2of4_address(const bagl_element_t *element) {
    return preprocessor_for_seeking(element, UINT256_DEC_STRING_MAX_LENGTH);
}

static void didApproveAaddressInTransferProceedWithAmount()
{
    prepareForApprovalOfAmount();
}

static unsigned int ui_sign_approve_tx_step2of4_address_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    seek_left_right_or_approve(button_mask, button_mask_counter, didApproveAaddressInTransferProceedWithAmount);
}

static void prepareForApprovalOfAddress() {
    resetDisplayAndDisplayFieldInStructTransfer(AddressField);
    UX_DISPLAY(ui_sign_approve_tx_step2of4_address, ui_prepro_sign_approve_tx_step2of4_address);
}
// ==== END ======= STEP 2/4: Address ========







static const bagl_element_t ui_sign_approve_tx_step1of4_txid[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x00, 0, 11, 128, "Approve TX:"),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static void proceedWithApprovalOfTransferAddress() {
    prepareForApprovalOfAddress();
}

static unsigned int ui_sign_approve_tx_step1of4_txid_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    reject_or_approve(button_mask, button_mask_counter, proceedWithApprovalOfTransferAddress);
}

static void proceedToDisplayingDetailsForTransfer() {
    assert(ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress);

    PRINTF("\nNow displaying details for transfer: %d\n", ctx->numberOfTransfersToNotMyAddressApproved);

    snprintf(ctx->fullString, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "tx@index: %d\0", ctx->numberOfTransfersToNotMyAddressApproved);
    resetDisplay();

    UX_DISPLAY(ui_sign_approve_tx_step1of4_txid, NULL);
}

// ==== END ==== APPROVE TX DETAILS STEP 1/4: Transfer number =====
static void proceedToDisplayingDetailsForEachTransfer() {
    PRINTF("\nNow displaying details for each transfer on display\n");
    
    ctx->numberOfTransfersToNotMyAddressApproved = 0;
    proceedToDisplayingDetailsForTransfer();
}

// ===== END ====== APPROVE DETAILS OF EACH TRANSFER  =================


// ===== START ====== APPROVE NO OF TRANSFERS =================
static const bagl_element_t ui_sign_approve_transfers[] = APPROVAL_SCREEN("Found #TX:", global.signAtomContext.partialString12Char);

// static const bagl_element_t ui_sign_approve_transfers[] = {
//     UI_BACKGROUND(),
//     UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
//     UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
//     UI_TEXT(0x00, 0, 11, 128, "Found #TX:"),
//     UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
// };


static unsigned int ui_sign_approve_transfers_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingDetailsForEachTransfer);
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
    if (ctx->numberOfTransferrableTokensParticlesParsed > 0) {

        filterOutTransfersBackToMeFromAllTransfers(true);

        if (ctx->numberOfTransfersToNotMyAddress > 9) {
            snprintf(ctx->partialString12Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "no of tx:%02d\0", ctx->numberOfTransfersToNotMyAddress);
        } else {
            snprintf(ctx->partialString12Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "no of tx: %d\0", ctx->numberOfTransfersToNotMyAddress);
        }

        UX_DISPLAY(ui_sign_approve_transfers, NULL);
    } else {
        proceedToDisplayingHash();
    }
}
// ===== END ====== APPROVE NO OF TRANSFERS =================











// ===== START ====== APPROVE NON-TRANSFER DATA =================
static const bagl_element_t ui_sign_approve_nonTransferData[] = {
    UI_BACKGROUND(),
    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
    UI_TEXT(0x00, 0, 11, 128, "Non-transfer"),
    UI_TEXT(0x00, 0, 26, 128, "data found!!"),
};


static unsigned int ui_sign_approve_nonTransferData_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    reject_or_approve(button_mask, button_mask_counter, proceedToDisplayingTransfersIfAny);
}

static void notifyNonTransferDataFound() {
    PRINTF("Non-tranfer\ndata found!!\n");
    UX_DISPLAY(ui_sign_approve_nonTransferData, NULL);
}
// ===== END ====== APPROVE NON-TRANSFER DATA =================






void presentAtomContentsOnDisplay(
    volatile unsigned int *flags
) {

    if (ctx->numberOfNonTransferrableTokensParticlesIdentified > 0) {
        notifyNonTransferDataFound();
    } else {
        proceedToDisplayingTransfersIfAny();
    }
}