// #include "global_state.h"
// #include "radix.h"
#include "ux.h"

static signAtomContext_t *ctx = &global.signAtomContext;


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

	UI_TEXT(0x00, 0, 12, 128, "Sign w key"),
	UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.bip32PathString),
};

static unsigned int ui_sign_confirm_signing_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // Approve
            didFinishSignAtomFlow();
            break;
        }
    }
    return 0;
}










static const bagl_element_t ui_sign_approve_hash_compare[] = {
    UI_BACKGROUND(),

	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),

	UI_TEXT(0x00, 0, 12, 128, "Verify Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

// === start ==== SEEK IN HASH =====
static const bagl_element_t *ui_prepro_sign_approve_hash_compare(const bagl_element_t *element) {
    int fullSize = HASH256_BYTE_COUNT * 2;
    if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
        (element->component.userid == 2 && ctx->displayIndex == fullSize - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)) {
        return NULL;
    }
    return element;
}

static unsigned int ui_sign_approve_hash_compare_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		// Decrement the displayIndex when the left button is pressed (or held).
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialString12Char, ctx->fullString64Char + ctx->displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < sizeof(ctx->fullString64Char)-DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialString12Char, ctx->fullString64Char + ctx->displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		UX_DISPLAY(ui_sign_confirm_signing, NULL);
		break;
	}
	return 0;
}

// === end   ==== SEEK IN HASH ======


static void proceedToDisplayingHash() {
    PRINTF("\nHash should be visible on display: %.*H\n", HASH256_BYTE_COUNT, ctx->hash);
    	
	bin2hex(ctx->fullString64Char, HASH256_BYTE_COUNT*2+1, ctx->hash, HASH256_BYTE_COUNT); // + 1 for NULL
	os_memmove(ctx->partialString12Char, ctx->fullString64Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
	ctx->partialString12Char[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';
	ctx->displayIndex = 0;

    UX_DISPLAY(ui_sign_approve_hash_compare, ui_prepro_sign_approve_hash_compare);
}
// ===== END ====== APPROVE HASH->SIGN =================











// ===== START ====== APPROVE DETAILS OF EACH TRANSFER  =================
static const bagl_element_t ui_sign_approve_tx[] = {
    UI_BACKGROUND(),

    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),


    UI_TEXT(0x00, 0, 12, 128, "Approve TX:"),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static void proceedToDisplayingDetailsForTransfer();

static unsigned int ui_sign_approve_tx_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // Approve
            ctx->numberOfTransfersToNotMyAddressApproved++;
            if (ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress) {
                // Proceed with next transfer
                proceedToDisplayingDetailsForTransfer();
            }
            else
            {
                // Finished accepting all transfers
                proceedToDisplayingHash();
            }
            break;
        }
    }
    return 0;
}


static void proceedToDisplayingDetailsForTransfer() {
    assert(ctx->numberOfTransfersToNotMyAddressApproved < ctx->numberOfTransfersToNotMyAddress);
    PRINTF("\nNow displaying details for transfer: %d\n", ctx->numberOfTransfersToNotMyAddressApproved);
    snprintf(ctx->partialString12Char, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, "tx@index: %d\0", ctx->numberOfTransfersToNotMyAddressApproved);
    UX_DISPLAY(ui_sign_approve_tx, NULL);
}

static void proceedToDisplayingDetailsForEachTransfer() {
    PRINTF("\nNow displaying details for each transfer on display\n");
    
    ctx->numberOfTransfersToNotMyAddressApproved = 0;
    proceedToDisplayingDetailsForTransfer();
}
// ===== END ====== APPROVE DETAILS OF EACH TRANSFER  =================










// ===== START ====== APPROVE NO OF TRANSFERS =================
static const bagl_element_t ui_sign_approve_transfers[] = {
    UI_BACKGROUND(),

    UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
    UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),


    UI_TEXT(0x00, 0, 12, 128, "Found #TX:"),
    UI_TEXT(0x00, 0, 26, 128, global.signAtomContext.partialString12Char),
};

static unsigned int ui_sign_approve_transfers_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // Approve
            proceedToDisplayingDetailsForEachTransfer();
            break;
        }
    }
    return 0;
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

    for (int i = 0; i < ctx->numberOfTransferrableTokensParticlesParsed; ++i)
    {
        Transfer transfer = ctx->transfers[i];
        if (matchesPublicKey(&transfer.address, &myPublicKeyCompressed))
        {
            continue; // dont display "change" (money back) to you (i.e. transfers to your own address.)
        } else {
            ctx->numberOfTransfersToNotMyAddress++;
        }

        if (!debugPrintTransferToConsole) {
            continue;
        }
        // DEBUG PRINT ALL PARSED TransferrableTokensParticles
        if (i == 0) {
            PRINTF("\n**************************************\n");
        }
        PRINTF("Transfer %u\n", ctx->numberOfTransfersToNotMyAddress);
        PRINTF("    recipient address: "); printRadixAddress(&transfer.address); PRINTF("\n");
        PRINTF("    amount: "), printTokenAmount(&transfer.amount); PRINTF(" E-18\n");
        PRINTF("    token (RRI): "); printRRI(&transfer.tokenDefinitionReference); PRINTF("\n");
        PRINTF("\n");
        if (i == ctx->numberOfTransferrableTokensParticlesParsed - 1) {
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

    UI_TEXT(0x00, 0, 12, 128, "Non-transfer"),
    UI_TEXT(0x00, 0, 26, 128, "data found!!"),
};

static unsigned int ui_sign_approve_nonTransferData_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // Approve
            proceedToDisplayingTransfersIfAny();
            break;
        }
    }
    return 0;
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