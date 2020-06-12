#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ux.h"

static signHashContext_t *ctx = &global.signHashContext;

static const bagl_element_t ui_signHash_approve[] = {
	UI_BACKGROUND(),

	ICON_CROSS_L,
	ICON_CHECK_R,

	UI_TEXT(0x00, 0, 12, 128, "Sign this Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.bip32PathString),
};

static unsigned int ui_signHash_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {

	switch (button_mask) {
		case BUTTON_EVT_RELEASED | BUTTON_LEFT: {// REJECT
			io_exchange_with_code(SW_USER_REJECTED, 0);
			// Return to the main screen.
			ui_idle();
			break;
		}

		case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // APPROVE

			int tx = derive_sign_move_to_global_buffer(ctx->bip32Path, ctx->hash);
		    io_exchange_with_code(SW_OK, tx);

			ui_idle();
			break;
		}
	}
	return 0;
}

static const bagl_element_t ui_signHash_compare[] = {
	UI_BACKGROUND(),

	ICON_LEFT_ARROW,
	ICON_RIGHT_ARROW,

	UI_TEXT(0x00, 0, 12, 128, "Compare Hashes:"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.partialHashStr),
};

static const bagl_element_t* ui_prepro_signHash_compare(const bagl_element_t *element) {
	switch (element->component.userid) {
	case 1:
		// 0x01 is the left icon (see screen definition above), so return NULL
		// if we're displaying the beginning of the text.
		return (ctx->displayIndex == 0) ? NULL : element;
	case 2:
		// 0x02 is the right, so return NULL if we're displaying the end of the text.
		return (ctx->displayIndex == sizeof(ctx->hexHash)-12) ? NULL : element;
	default:
		// Always display all other elements.
		return element;
	}
}

static unsigned int ui_signHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {

	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < sizeof(ctx->hexHash)-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialHashStr, ctx->hexHash+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
		UX_DISPLAY(ui_signHash_approve, NULL);
		break;
	}
	return 0;
}

void handleSignHash(
	uint8_t p1, 
	uint8_t p2, 
	uint8_t *dataBuffer,
	uint16_t dataLength, 
	volatile unsigned int *flags, 
	volatile unsigned int *tx
) {
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    uint16_t byte_count_hash = 32;
	uint16_t expected_data_length = expected_bip32_byte_count + byte_count_hash;
    
    if (dataLength != expected_data_length) {
        PRINTF("'dataLength' must be: %u, but was: %d\n", expected_data_length, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString));

	// // Read the hash.
	os_memmove(ctx->hash, dataBuffer+expected_bip32_byte_count, sizeof(ctx->hash));
	
	// Prepare to display the comparison screen by converting the hash to hex
    hexadecimal_string_from(ctx->hash, HASH256_BYTE_COUNT, ctx->hexHash);
	// and moving the first 12 characters into the partialHashStr buffer.
	os_memmove(ctx->partialHashStr, ctx->hexHash, 12);

	ctx->partialHashStr[12] = '\0';
	ctx->displayIndex = 0;

	UX_DISPLAY(ui_signHash_compare, ui_prepro_signHash_compare);

	*flags |= IO_ASYNCH_REPLY;
}
