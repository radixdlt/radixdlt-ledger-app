#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ux.h"
#include "stringify_bip32_path.h"
#include "base_conversion.h"

static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

static const bagl_element_t ui_getPublicKey_compare[] = {
        UI_BACKGROUND(),
        ICON_LEFT_ARROW,
        ICON_RIGHT_ARROW,

        UI_TEXT(0x00, 0, 12, 128, "Compare:"),
        // The visible portion of the public key or address.
        UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.partialStr),
};

static const bagl_element_t *ui_prepro_getPublicKey_compare(const bagl_element_t *element) {
    int fullSize = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT * 2;
    if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
        (element->component.userid == 2 && ctx->displayIndex == fullSize - 12)) {
        return NULL;
    }
    return element;
}

static unsigned int ui_getPublicKey_compare_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    int fullSize = PUBLIC_KEY_COMPRESSEED_BYTE_COUNT * 2;
    switch (button_mask) {
        case BUTTON_LEFT:
        case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
            if (ctx->displayIndex > 0) {
                ctx->displayIndex--;
            }
            os_memmove(ctx->partialStr, ctx->fullStr + ctx->displayIndex, 12);
            UX_REDISPLAY();
            break;

        case BUTTON_RIGHT:
        case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
            if (ctx->displayIndex < fullSize - 12) {
                ctx->displayIndex++;
            }
            os_memmove(ctx->partialStr, ctx->fullStr + ctx->displayIndex, 12);
            UX_REDISPLAY();
            break;

        case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
            // The user has finished comparing, so return to the main screen.
            ui_idle();
            break;
    }
    return 0;
}

// Define the approval screen. This is where the user will approve the
// generation of the public key (or address).
static const bagl_element_t ui_getPublicKey_approve[] = {
        UI_BACKGROUND(),

        ICON_CROSS_L,
        ICON_CHECK_R,

        // These two lines form a complete sentence:
        //
        //    Gen PubKey
        //     44'/536'/0'/0/0?
        //
        // Since both lines differ based on user-supplied parameters, we can't use
        // compile-time string literals for either of them.
        UI_TEXT(0x00, 0, 12, 128, global.getPublicKeyContext.typeStr),
        UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.bip32PathString),
};

static void genPubKey() {

    // The response APDU will contain multiple objects, which means we need to
    // remember our offset within G_io_apdu_buffer. By convention, the offset
    // variable is named 'tx'.
    uint16_t tx = 0;
    cx_ecfp_public_key_t publicKey;
    
    derive_radix_key_pair(
        ctx->bip32Path, 
        &publicKey, 
        NULL // dont write private key
    );

    os_memmove(G_io_apdu_buffer + tx, publicKey.W, publicKey.W_len);
    tx += publicKey.W_len;
    PRINTF("Public Key compressed: %.*h\n", 33, G_io_apdu_buffer);

    if (ctx->requireConfirmationOfDisplayedPubKey) {
        // Prepare the comparison screen, filling in the header and body text.
        os_memmove(ctx->typeStr, "Compare:", 9);

        // The APDU buffer contains the raw bytes of the public key.
        // So, first we need to convert to a human-readable form.
        hexadecimal_string_from(G_io_apdu_buffer, publicKey.W_len, ctx->fullStr);

        os_memmove(ctx->partialStr, ctx->fullStr, 12);
        ctx->partialStr[12] = '\0';
        ctx->displayIndex = 0;

        // Display the comparison screen.
        UX_DISPLAY(ui_getPublicKey_compare, ui_prepro_getPublicKey_compare);
    } else {
        ui_idle();
    }

    io_exchange_with_code(SW_OK, tx);

}

static unsigned int ui_getPublicKey_approve_button(
    unsigned int button_mask, 
    unsigned int button_mask_counter
) {
    switch (button_mask) {
        case BUTTON_EVT_RELEASED | BUTTON_LEFT: { // REJECT
            io_exchange_with_code(SW_USER_REJECTED, 0);
            ui_idle();
            break;
        }
        case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // APPROVE
            genPubKey();
            break;
        }
    }
    return 0;
}

// These are APDU parameters that control the behavior of the getPublicKey
// command. See `ux.h` or `APDUSPEC.md` for more details
#define P1_NO_CONFIRMATION_BEFORE_GENERATION        0x00
#define P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION   0x01

#define P2_NO_CONFIRMATION_OF_DISPLAYED_PUBKEY      0x00
#define P2_REQUIRE_CONFIRMATION_OF_DISPLAYED_PUBKEY 0x01

// handleGetPublicKey is the entry point for the getPublicKey command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handleGetPublicKey(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx)
{
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_data_length = expected_number_of_bip32_compents * byte_count_bip_component;
    
    if (dataLength != expected_data_length) {
        PRINTF("'dataLength' must be: %u, but was: %d\n", expected_data_length, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    if ((p1 != P1_NO_CONFIRMATION_BEFORE_GENERATION) && (p1 != P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION)) {
        PRINTF("p1 must be 0 or 1, but was: %u\n", p1);
        THROW(SW_INVALID_PARAM);
    }

    if ((p2 != P2_NO_CONFIRMATION_OF_DISPLAYED_PUBKEY) && (p2 != P2_REQUIRE_CONFIRMATION_OF_DISPLAYED_PUBKEY)) {
        PRINTF("p2 must be 0 or 1, but was: %u\n", p2);
        THROW(SW_INVALID_PARAM);
    }

    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString));
    PRINTF("BIP 32 Path used for PublicKey generation: %s\n", ctx->bip32PathString);

    ctx->requireConfirmationBeforeGeneration = (p1 == P1_REQUIRE_CONFIRMATION_BEFORE_GENERATION);
    ctx->requireConfirmationOfDisplayedPubKey = (p2 == P2_REQUIRE_CONFIRMATION_OF_DISPLAYED_PUBKEY);

    // Prepare the approval screen, filling in the header and body text.
    if (ctx->requireConfirmationBeforeGeneration) {
        os_memmove(ctx->typeStr, "Generate PubKey", 16);
        UX_DISPLAY(ui_getPublicKey_approve, NULL);
        *flags |= IO_ASYNCH_REPLY;
    } else {
        genPubKey();
    }
}
