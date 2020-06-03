// This file contains the implementation of the signHash command. The files
// for the other commands will have the same basic structure: A set of screens
// (comprising the screen elements, preprocessor, and button handler) followed
// by the command handler itself.
//
// A high-level description of signHash is as follows. The user initiates the
// command on their computer, specifying the hash they would like to sign and
// the key they would like to sign with. The command handler then displays the
// hash on the device and asks the user to compare it to the hash shown on the
// computer. The user can press the left and right buttons to scroll through
// the hash. When the user finishes comparing, they press both buttons to
// proceed to the next screen, which asks the user to approve or deny signing
// the hash. If the user presses the left button, the action is denied and a
// rejection code is sent to the computer. If they press the right button, the
// action is approved and the requested signature is computed and sent to the
// computer. In either case, the command ends by returning to the main screen.
//
// Keep this description in mind as you read through the implementation.

#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signHashContext_t *ctx = &global.signHashContext;

// Define the approval screen. This is where the user will confirm that they
// want to sign the hash. This UI layout is very common: a background, two
// buttons, and two lines of text.
//
// Screens are arrays of elements; the order of elements determines the order
// in which they are rendered. Elements cannot be modified at runtime.
static const bagl_element_t ui_signHash_approve[] = {
	UI_BACKGROUND(),

	ICON_CROSS_L,
	ICON_CHECK_R,

	UI_TEXT(0x00, 0, 12, 128, "Sign this Hash"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.bip32PathString),
};

// This is the button handler for the approval screen. When you call
// UX_DISPLAY on screen "foo", it looks for a button handler named
// "foo_button", and it calls this handler whenever a button is pressed while
// foo is displayed. If you don't define a _button handler, you'll get a
// compile-time error.
//
// The 'button_mask' argument is a bitfield that indicates which buttons are
// being pressed, while 'button_mask_counter' counts how many "ticks" the
// buttons have been held for, where each tick is 100ms. I haven't come across
// any apps that use this counter, but it could be useful for e.g. performing
// an action only if a button is held for 3 seconds.
static unsigned int ui_signHash_approve_button(unsigned int button_mask, unsigned int button_mask_counter) {

	switch (button_mask) {
		case BUTTON_EVT_RELEASED | BUTTON_LEFT: {// REJECT
			// Send an error code to the computer. The application on the computer
			// should recognize this code and display a "user refused to sign"
			// message instead of a generic error.
			io_exchange_with_code(SW_USER_REJECTED, 0);
			// Return to the main screen.
			ui_idle();
			break;
		}

		case BUTTON_EVT_RELEASED | BUTTON_RIGHT: { // APPROVE

			deriveSignRespond(ctx->bip32Path, ctx->hash);

			// Return to the main screen.
			ui_idle();
			break;
		}

		default: {
			PRINTF("Unknown button combo...\n");
		}
	}
	return 0;
}

// Define the comparison screen. This is where the user will compare the hash
// on their device to the one shown on the computer. This UI is identical to
// the approval screen, but with left/right buttons instead of reject/approve.
static const bagl_element_t ui_signHash_compare[] = {
	UI_BACKGROUND(),

	// Left and right buttons for scrolling the text. The 0x01 and 0x02 are
	// called userids; they allow the preprocessor (below) to know which
	// element it's examining.
	ICON_LEFT_ARROW,
	ICON_RIGHT_ARROW,

	// Two lines of text: a header and the contents of the hash. We will be
	// implementing a fancy scrollable text field, so the second line only
	// needs to hold the currently-visible portion of the hash.
	//
	// Note that the userid of these fields is 0: this is a convention that
	// most apps use to indicate that the element should always be displayed.
	// UI_BACKGROUND() also has userid == 0. And if you revisit the approval
	// screen, you'll see that all of those elements have userid == 0 as well.
	UI_TEXT(0x00, 0, 12, 128, "Compare Hashes:"),
	UI_TEXT(0x00, 0, 26, 128, global.signHashContext.partialHashStr),
};

// This is a "preprocessor" function that controls which elements of the
// screen are displayed. This function is passed to UX_DISPLAY, which calls it
// on each element of the screen. It should return NULL for elements that
// should not be displayed, and otherwise return the element itself. Elements
// can be identified by their userid.
//
// For the comparison screen, we use the preprocessor to make the scroll
// buttons more intuitive: we only display them if there is more text hidden
// off-screen.
//
// Note that we did not define a preprocessor for the approval screen. This is
// because we always want to display every element of that screen. The
// preprocessor acts a filter that selectively hides elements; since we did
// not want to hide any elements, no preprocessor was necessary.
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

// This is the button handler for the comparison screen. Unlike the approval
// button handler, this handler doesn't send any data to the computer.
static unsigned int ui_signHash_compare_button(unsigned int button_mask, unsigned int button_mask_counter) {
	switch (button_mask) {
	// The available button mask values are LEFT, RIGHT, EVT_RELEASED, and
	// EVT_FAST. EVT_FAST is set when a button is held for 8 "ticks," i.e.
	// 800ms.
	//
	// The comparison screens in the Sia app allow the user to scroll using
	// the left and right buttons. The user should be able to hold a button
	// and scroll at a constant rate. When the user first presses the left
	// button, we'll hit the LEFT case; after they've held the button for 8
	// ticks, we'll hit the EVT_FAST | LEFT case. Since we want to scroll at a
	// constant rate regardless, we handle both cases identically.
	//
	// Also note that, unlike the approval screen, we don't check for
	// EVT_RELEASED. In fact, when a single button is released, none of the
	// switch cases will be hit, so we'll stop scrolling.
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		// Decrement the displayIndex when the left button is pressed (or held).
		if (ctx->displayIndex > 0) {
			ctx->displayIndex--;
		}
		// Use the displayIndex to recalculate the displayed portion of the
		// text. os_memmove is the Ledger SDK's version of memmove (there is
		// no os_memcpy). In practice, I don't think it matters whether you
		// use os_memmove or the standard memmove from <string.h>.
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
		// Prepare to display the approval screen by printing the key index
		// into the bip32PathString buffer. 
		// Note that because the approval screen does not have a preprocessor,
		// we must pass NULL.
		UX_DISPLAY(ui_signHash_approve, NULL);
		break;
	}
	// (The return value of a button handler is irrelevant; it is never
	// checked.)
	return 0;
}

// handleSignHash is the entry point for the signHash command. Like all
// command handlers, it is responsible for reading command data from
// dataBuffer, initializing the command context, and displaying the first
// screen of the command.
void handleSignHash(uint8_t p1, uint8_t p2, uint8_t *dataBuffer, uint16_t dataLength, volatile unsigned int *flags, volatile unsigned int *tx) {
	PRINTF("Received APDU of length: %u\n", dataLength);
    PRINTF("Received APDU hex: %.*H\n", dataLength, dataBuffer);

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
    PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

	// // Read the hash.
	os_memmove(ctx->hash, dataBuffer+expected_bip32_byte_count, sizeof(ctx->hash));
	PRINTF("Sign hash: %.*H\n", byte_count_hash, ctx->hash);
	
	// Prepare to display the comparison screen by converting the hash to hex
	// and moving the first 12 characters into the partialHashStr buffer.
	bin2hex(ctx->hexHash, byte_count_hash*2+1, ctx->hash, byte_count_hash); // + 1 for NULL
	PRINTF("ctx->hexHash: %s\n", ctx->hexHash);
	os_memmove(ctx->partialHashStr, ctx->hexHash, 12);
	ctx->partialHashStr[12] = '\0';
	ctx->displayIndex = 0;

	// Call UX_DISPLAY to display the comparison screen, passing the
	// corresponding preprocessor. You might ask: Why doesn't UX_DISPLAY
	// also take the button handler as an argument, instead of using macro
	// magic? To which I can only reply: ¯\_(ツ)_/¯
	UX_DISPLAY(ui_signHash_compare, ui_prepro_signHash_compare);

	// Set the IO_ASYNC_REPLY flag. This flag tells function 'radix_main' in file 'main.c' that we aren't
	// sending data to the computer immediately; we need to wait for a button
	// press first.
	*flags |= IO_ASYNCH_REPLY;
}

// Now that we've seen the individual pieces, we can construct a full picture
// of what the signHash command looks like.
//
// The command begins when function 'radix_main' in file 'main.c' reads an APDU packet from the computer
// with INS == INS_SIGN_HASH. function 'radix_main' in file 'main.c' looks up the appropriate handler,
// handleSignHash, and calls it. handleSignHash reads the command data,
// prepares and displays the comparison screen, and sets the IO_ASYNC_REPLY
// flag. Control returns to function 'radix_main' in file 'main.c', which blocks when it reaches the
// io_exchange call.
//
// UX_DISPLAY was called with the ui_prepro_signHash_compare preprocessor, so
// that preprocessor is now called each time the compare screen is rendered.
// Since we are initially displaying the beginning of the hash, the
// preprocessor hides the left arrow. The user presses and holds the right
// button, which triggers the button handler to advance the displayIndex every
// 100ms. Each advance requires redisplaying the screen via UX_REDISPLAY(),
// and thus rerunning the preprocessor. As soon as the right button is
// pressed, the preprocessor detects that text has scrolled off the left side
// of the screen, so it unhides the left arrow; when the end of the hash is
// reached, it hides the right arrow.
//
// When the user has finished comparing the hashes, they press both buttons
// together, triggering ui_signHash_compare_button to prepare the approval
// screen and call UX_DISPLAY on ui_signHash_approve. A NULL preprocessor is
// specified for this screen, since we don't need to filter out any of its
// elements. We'll assume that the user presses the 'approve' button, causing
// the button handler to place the hash in G_io_apdu_buffer and call
// io_exchange_with_code, which sends the response APDU to the computer with
// the IO_RETURN_AFTER_TX flag set. The button handler then calls ui_idle,
// thus returning to the main menu.
//
// This completes the signHash command. Back in function 'radix_main' in file 'main.c', io_exchange is still
// blocked, waiting for the computer to send a new request APDU. For the next
// section of this walkthrough, we will assume that the next APDU requests the
// getPublicKey command, so proceed to getPublicKey.c.
