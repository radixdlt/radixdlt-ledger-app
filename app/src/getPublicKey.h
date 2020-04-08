#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>

void handleGetPublicKey(
	uint8_t p1, 
	uint8_t p2, 
	uint8_t *dataBuffer, 
	uint16_t dataLength, 
	volatile unsigned int *flags, 
	volatile unsigned int *output_response_apdu_size_aka_tx
);