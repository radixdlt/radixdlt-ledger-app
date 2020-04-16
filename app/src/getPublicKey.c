// This file contains the implementation of the getPublicKey command. It is
// broadly similar to the signHash command, but with a few new features. Since
// much of the code is the same, expect far fewer comments.
//
// A high-level description of getPublicKey is as follows. The user initiates
// the command on their computer by requesting the generation of a specific
// public key. The command handler then displays a screen asking the user to
// confirm the action. If the user presses the 'approve' button, the requested
// key is generated, sent to the computer, and displayed on the device. The
// user may then visually compare the key shown on the device to the key
// received by the computer. Augmenting this, the user may optionally request
// that an address be generated from the public key, in which case this
// address is displayed instead of the public key. A final two-button press
// returns the user to the main screen.
//
// Note that the order of the getPublicKey screens is the reverse of signHash:
// first approval, then comparison.
//
// Keep this description in mind as you read through the implementation.

#include "getPublicKey.h"
#include "bip32.h"
#include "ux.h"
#include "zxmacros.h"
#include "apdu_constants.h"
#include "parse_input.h"
#include <stdio.h> 
#include <stdlib.h>
#include "os_io_seproxyhal.h"

// Get a pointer to getPublicKey's state variables.
static getPublicKeyContext_t *ctx = &global.getPublicKeyContext;

// Define the comparison screen. This is where the user will compare the
// public key (or address) on their device to the one shown on the computer.
static const bagl_element_t ui_getPublicKey_compare[] = {
	UI_BACKGROUND(),
	UI_ICON_LEFT(0x01, BAGL_GLYPH_ICON_LEFT),
	UI_ICON_RIGHT(0x02, BAGL_GLYPH_ICON_RIGHT),
	UI_TEXT(0x00, 0, 12, 128, "Compare:"),
	// The visible portion of the public key or address.
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.partialStr),
};

// Define the preprocessor for the comparison screen. As in signHash, this
// preprocessor selectively hides the left/right arrows. The only difference
// is that, since public keys and addresses have different lengths, checking
// for the end of the string is slightly more complicated.
static const bagl_element_t* ui_prepro_getPublicKey_compare(const bagl_element_t *element) {
	int fullSize = ctx->displayType ? 76 : 64;
	if ((element->component.userid == 1 && ctx->displayIndex == 0) ||
	    (element->component.userid == 2 && ctx->displayIndex == fullSize-12)) {
		return NULL;
	}
	return element;
}

// Define the button handler for the comparison screen. Again, this is nearly
// identical to the signHash comparison button handler.
static unsigned int ui_getPublicKey_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	int fullSize = ctx->displayType ? 76 : 64;
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (ctx->displayIndex < fullSize-12) {
			ctx->displayIndex++;
		}
		os_memmove(ctx->partialStr, ctx->fullStr+ctx->displayIndex, 12);
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
	UI_ICON_LEFT(0x00, BAGL_GLYPH_ICON_CROSS),
	UI_ICON_RIGHT(0x00, BAGL_GLYPH_ICON_CHECK),
	// These two lines form a complete sentence:
	//
	//    Generate Public
	//       Key #123?
	//
	// or:
	//
	//    Generate Address
	//     from Key #123?
	//
	// Since both lines differ based on user-supplied parameters, we can't use
	// compile-time string literals for either of them.
	UI_TEXT(0x00, 0, 12, 128, global.getPublicKeyContext.typeStr),
	UI_TEXT(0x00, 0, 26, 128, global.getPublicKeyContext.keyStr),
};

// This is the button handler for the approval screen. If the user approves,
// it generates and sends the public key and address. (For simplicity, we
// always send both, regardless of which one the user requested.)
static unsigned int ui_getPublicKey_approve_button(
	unsigned int button_mask, 
	unsigned int button_mask_counter
) {
	// The response APDU will contain multiple objects, which means we need to
	// remember our offset within G_io_apdu_buffer. By convention, the offset
	// variable is named 'tx'.
	uint16_t tx = 0;
	cx_ecfp_public_key_t publicKey;
	switch (button_mask) {
	case BUTTON_EVT_RELEASED | BUTTON_LEFT: // REJECT
		io_exchange_with_code(SW_USER_REJECTED, 0);
		ui_idle();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_RIGHT: // APPROVE

		PRINTF("Before deriving publicKey variable:\n %.*H \n\n", 32, publicKey);
		PRINTF("Before deriving publicKey variable, bip32 path is:\n %.*H \n\n", 20, ctx->bip32Path);

		// Derive the public key and address and store them in the APDU
		// buffer. Even though we know that tx starts at 0, it's best to
		// always add it explicitly; this prevents a bug if we reorder the
		// statements later.
		deriveRadixKeypairFromBip32Path(
			ctx->bip32Path,
			5, 
			NULL, // privateKey
			&publicKey
		);


		PRINTF("After having derived publicKey variable:\n %.*H \n\n", 32, &publicKey);
		
		PRINTF("Before copied over publicKey to buffer:\n %.*H \n\n", 32, G_io_apdu_buffer);
		
		extractPubkeyBytes(G_io_apdu_buffer + tx, &publicKey);

		PRINTF("After having copied over publicKey to buffer:\n %.*H \n\n", 32, G_io_apdu_buffer);


		tx += 32;
		// pubkeyToSiaAddress(G_io_apdu_buffer + tx, &publicKey);
		// tx += 76;

		// Flush the APDU buffer, sending the response.
		io_exchange_with_code(SW_OK, tx);

		// Prepare the comparison screen, filling in the header and body text.
		os_memmove(ctx->typeStr, "Compare:", 9);

		// switch (ctx->displayType) {
		// 	case DISPLAY_PUBKEY: {
				// The APDU buffer contains the raw bytes of the public key, so
				// first we need to convert to a human-readable form.
				bin2hex(ctx->fullStr, G_io_apdu_buffer, 32);
		// 	}

		// 	case DISPLAY_ADDRESS: {}
		// 		// The APDU buffer already contains the hex-encoded address, so
		// 		// copy it directly.
		// 		// os_memmove(ctx->fullStr, G_io_apdu_buffer + 32, 76);
		// 		// ctx->fullStr[76] = '\0';
		// 		THROW(SW_INS_NOT_SUPPORTED);
		// }
		
		os_memmove(ctx->partialStr, ctx->fullStr, 12);
		ctx->partialStr[12] = '\0';
		ctx->displayIndex = 0;
		// Display the comparison screen.
		UX_DISPLAY(ui_getPublicKey_compare, ui_prepro_getPublicKey_compare);
		break;
	}
	return 0;
}

// https://stackoverflow.com/a/2182581/1311272
void SwapBytes(void *pv, size_t n)
{
    char *p = pv;
    size_t lo, hi;
    for(lo=0, hi=n-1; hi>lo; lo++, hi--)
    {
        char tmp=p[lo];
        p[lo] = p[hi];
        p[hi] = tmp;
    }
}

void byte_array_from_number(char *buffer, uint32_t number) {
    int i;
    for (i=0; i<sizeof(uint32_t); i++) {
        buffer[i] = number & 0xFF; // place bottom 8 bits in char
        number = number >> 8; // shift down remaining bits
    }
    return; // the long is now stored in the first few (2,4,or 8) bytes of buffer
}



int stringify_bip32_path_single_component(
	uint32_t input_bip32_component,
	char *output_bip32_component_string
) {

	// uint8_t most_significant_byte = input_bip32_component[0];
	// PRINTF("string from bip uint32 component: %u\n", input_bip32_component);
	uint8_t parsed[4];
	// os_memcpy(parsed, input_bip32_component, 4);
	byte_array_from_number(parsed, input_bip32_component);
	SwapBytes(parsed, 4);
	bool is_hardened = false;
	if (parsed[0] >= 0x80) {
		is_hardened = true;
		parsed[0] -= 0x80;
		PRINTF("Was hardened, now unhardened...\n");
	}

	uint32_t unhardened_bip32_path_component_uint32 = U4BE(parsed, 0);

	char str[12];
	SPRINTF(str, "%d", unhardened_bip32_path_component_uint32);

	int length = strlen(str);
	if (is_hardened) {
		str[length] = '\'';
		str[length + 1] = '\0';
		length += 1;
	}
	os_memcpy(output_bip32_component_string, str, length);
	PRINTF("output_bip32_component_string: %s\n", output_bip32_component_string);
	return length;
}

int stringify_bip32_path(
	uint32_t *input_bip32_bytes,
	char *output_bip32_string
) {
	
	int length_of_output_string = 0;
	for (int i = 0; i < BIP32_PATH_FULL_NUMBER_OF_COMPONENTS; i++) {
		char string_form_path_comp[20]; // will not need 20 chars, just placeholder...
		int length_of_string_for_this_component = stringify_bip32_path_single_component(input_bip32_bytes[i], string_form_path_comp);
		os_memcpy(output_bip32_string + length_of_output_string, string_form_path_comp, length_of_string_for_this_component);
		length_of_output_string += length_of_string_for_this_component;

		if (i < (BIP32_PATH_FULL_NUMBER_OF_COMPONENTS - 1)) {
			os_memset(output_bip32_string + strlen(output_bip32_string), '/', 1);
			length_of_output_string += 1;
		}
	}
	return length_of_output_string;
}

void doGetPublicKey(
	genAddr_displayType_e displayType,
	uint32_t bip32_path_account, 
	uint32_t bip32_path_change, 
	uint32_t bip32_path_addressIndex, 
	volatile unsigned int *flags
) {

	ctx->displayType = displayType;

	bip32PathFromComponents(
		bip32_path_account,
		bip32_path_change,
		bip32_path_addressIndex,
		ctx->bip32Path,
		20
		// sizeof(ctx->bip32Path)
	);
	PRINTF("After setting bip32Path variable:\n %.*H \n\n", 20, ctx->bip32Path);

	// Prepare the approval screen, filling in the header and body text.
	// switch (displayType) {
	// 	case DISPLAY_PUBKEY: {
			char title1[] = "Gen PubKey";
			unsigned int title1_null_ended_length = strlen(title1) + 1; // +1 for null end
			os_memmove(ctx->typeStr, title1, title1_null_ended_length);
			// char title2[] = "B: "; // "Bip32 path: "
			// unsigned int title2_null_ended_length = strlen(title2) + 1; // +1 for null end
			unsigned int title2_null_ended_length = 0;
			// os_memmove(ctx->keyStr, title2, title2_null_ended_length);
			PRINTF("About to get string from bip32 path....\n");
			char bip32String[100]; // 100 will not be needed....
			int length_of_bip32_string_path = stringify_bip32_path(ctx->bip32Path, bip32String);

			PRINTF("bip32String: %s\n", bip32String);
			// PRINTF("bip32String: %s\n", length_of_bip32_string_path, bip32String);
			os_memmove(ctx->keyStr + title2_null_ended_length, bip32String, length_of_bip32_string_path);
			// bin2hex(ctx->keyStr+title2_null_ended_length, ctx->bip32Path, sizeof(ctx->bip32Path));
			os_memmove(ctx->keyStr+title2_null_ended_length+length_of_bip32_string_path, "?", 2);
	// 	}
	// 	case DISPLAY_ADDRESS: {

	// 		THROW(0x9123); // impl me
	// 	}
	// }

	// MAGIC! This MAGICALLY expects the existence of a method name `ui_getPublicKey_approve_button`
	UX_DISPLAY(ui_getPublicKey_approve, NULL);
	
	*flags |= IO_ASYNCH_REPLY;
}

// handleGetPublicKey is the entry point for the `writePublicKeyToBuffer` command. It
// reads the command parameters, prepares and displays the approval screen,
// and sets the IO_ASYNC_REPLY flag.
void handleGetPublicKey(
	uint8_t p1, 
	uint8_t p2, 
	uint8_t *dataBuffer, 
	uint16_t dataLength, 
	volatile unsigned int *flags, 
	volatile unsigned int *output_response_apdu_size_aka_tx
) {

	if (dataLength != BIP32_PATH_COMPONENTS_INPUT_EXPECTED_BYTE_COUNT) { 
		THROW(SW_INCORRECT_LENGTH);
	}

	PRINTF("'dataBuffer':\n %.*H \n\n", dataLength, dataBuffer);

	uint32_t bip32_path_account = U4BE(dataBuffer, 0*4);
	PRINTF("'bip32_path_account': %u\n", bip32_path_account);

	uint32_t bip32_path_change = U4BE(dataBuffer, 1*4);
	PRINTF("'bip32_path_change': %u\n", bip32_path_change);

	uint32_t bip32_path_addressIndex = U4BE(dataBuffer, 2*4);
	PRINTF("'bip32_path_addressIndex': %u\n", bip32_path_addressIndex);


	// Sanity-check the command parameters.
	if ((p1 != DISPLAY_ADDRESS) && (p1 != DISPLAY_PUBKEY)) {
		// Although THROW is technically a general-purpose exception
		// mechanism, within a command handler it is basically just a
		// convenient way of bailing out early and sending an error code to
		// the computer. The exception will be caught by sia_main, which
		// appends the code to the response APDU and sends it, much like
		// io_exchange_with_code. THROW should not be called from
		// preprocessors or button handlers.
		THROW(SW_INCORRECT_DATA);
	}

	int displayTypeRaw = (int) p1;
	genAddr_displayType_e displayType;
	displayType = ( genAddr_displayType_e ) displayTypeRaw;

	doGetPublicKey(
		displayType,
		bip32_path_account,
		bip32_path_change,
		bip32_path_addressIndex,
		flags
	);
}