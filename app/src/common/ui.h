#ifndef UI_H
#define UI_H

#include "stdint.h"
#include <seproxyhal_protocol.h>
#include <os_io_seproxyhal.h>

// assuming a font size of 11 (`BAGL_FONT_OPEN_SANS_REGULAR_11px`)
#define DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE 12

// Size of some string used for displaying long text on disaply
#define MAX_LENGTH_FULL_STR_DISPLAY 103 // "ABCD0123456789E, Full Identifier: /9hTaTtgqxhAGRryeMs5htePmJA53tpjDgJK1FY3H1tLrmiZjv6j/ABCD0123456789E\0"

typedef struct {

	uint8_t lower_line_display_offset;
	uint8_t lower_line_long[MAX_LENGTH_FULL_STR_DISPLAY]; // the RRI is the longest data we wanna display
	uint8_t length_lower_line_long;
	uint8_t lower_line_short[DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE + 1]; //+1 for NULL
} ui_state_t;

extern ui_state_t G_ui_state;

typedef void (*callback_t)(void);

// BOLOS stuff
extern ux_state_t ux;

// ui_idle displays the main menu screen. Command handlers should call ui_idle
// when they finish.
void ui_idle(void);

// io_exchange_with_code is a helper function for sending APDUs, primarily
// from button handlers. It appends code to G_io_apdu_buffer and calls
// io_exchange with the IO_RETURN_AFTER_TX flag. tx is the current offset
// within G_io_apdu_buffer (before the code is appended).
void io_exchange_with_code(uint16_t code, uint16_t tx);

void display_lines(
	const char *row_1_max_12_chars,
	const char *row_2_max_12_chars,
	callback_t didApproveCallback);

void display_value(
	const char *title_max_12_chars,
	callback_t didApproveCallback);

void clear_partialStr();

void reset_ui();

void clear_lower_line_long();

#endif