#include "ux.h"
#include <os_io_seproxyhal.h>

ui_state_t G_ui_state;

void reset_ui() {
    os_memset(G_ui_state.partialString12Char, 0x00, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    os_memset(G_ui_state.fullString, 0x00, MAX_LENGTH_FULL_STR_DISPLAY);
    G_ui_state.lengthOfFullString = 0;
    G_ui_state.displayIndex = 0;
}

void ui_fullStr_to_partial() {
    os_memset(G_ui_state.partialString12Char, 0x00, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    os_memmove(G_ui_state.partialString12Char, G_ui_state.fullString, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
    G_ui_state.partialString12Char[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE] = '\0';
}

const bagl_element_t* preprocessor_for_seeking(const bagl_element_t *element) {
    if (
        (element->component.userid == 1 && G_ui_state.displayIndex == 0) 
        ||
        (element->component.userid == 2 
        && 
        (G_ui_state.displayIndex == (G_ui_state.lengthOfFullString - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)))) 
    {
        return NULL;
    }
    return element;
}

unsigned int reject_or_approve(
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

unsigned int seek_left_right_or_approve(
    unsigned int button_mask, 
    unsigned int button_mask_counter,
    void (*didApproveCallback)(void)
) {
	switch (button_mask) {
	case BUTTON_LEFT:
	case BUTTON_EVT_FAST | BUTTON_LEFT: // SEEK LEFT
		// Decrement the displayIndex when the left button is pressed (or held).
		if (G_ui_state.displayIndex > 0) {
			G_ui_state.displayIndex--;
		}
		os_memmove(G_ui_state.partialString12Char, G_ui_state.fullString + G_ui_state.displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		// Re-render the screen.
		UX_REDISPLAY();
		break;

	case BUTTON_RIGHT:
	case BUTTON_EVT_FAST | BUTTON_RIGHT: // SEEK RIGHT
		if (G_ui_state.displayIndex < (G_ui_state.lengthOfFullString - DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE)) {
			G_ui_state.displayIndex++;
		}
		os_memmove(G_ui_state.partialString12Char, G_ui_state.fullString + G_ui_state.displayIndex, DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);
		UX_REDISPLAY();
		break;

	case BUTTON_EVT_RELEASED | BUTTON_LEFT | BUTTON_RIGHT: // PROCEED
        didApproveCallback();
        break;
    }
	return 0;
}
