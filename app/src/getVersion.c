#include "getVersion.h"
#include "bip32.h"
#include "ux.h"

void writeVersionToBuffer() {
	G_io_apdu_buffer[0] = APPVERSION[0] - '0';
	G_io_apdu_buffer[1] = APPVERSION[2] - '0';
	G_io_apdu_buffer[2] = APPVERSION[4] - '0';
	io_exchange_with_code(SW_OK, 3);
}

// handleGetVersion is the entry point for the getVersion command. It
// unconditionally sends the app version.
void handleGetVersion(
	uint8_t p1, 
	uint8_t p2, 
	uint8_t *dataBuffer, 
	uint16_t dataLength, 
	volatile unsigned int *flags, 
	volatile unsigned int *output_response_apdu_size_aka_tx
) {
	// none of the arguments passed are used...
	writeVersionToBuffer();
}