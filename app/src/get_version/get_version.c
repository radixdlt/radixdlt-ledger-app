#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "common_macros.h"

// handle_get_version is the entry point for the getVersion command. It
// unconditionally sends the app version.
void handle_get_version(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *data_buffer,
    uint16_t data_length, 
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {
	G_io_apdu_buffer[0] = APPVERSION[0] - '0';
	G_io_apdu_buffer[1] = APPVERSION[2] - '0';
	G_io_apdu_buffer[2] = APPVERSION[4] - '0';
	io_exchange_with_code(SW_OK, 3);
}
