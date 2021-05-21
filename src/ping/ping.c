#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "common_macros.h"

void handle_ping(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *data_buffer,
    uint16_t data_length,
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {
    int pingLength = 4;
    uint8_t expected[pingLength];
    expected[0] = 'p';
    expected[1] = 'i';
    expected[2] = 'n';
    expected[3] = 'g';

	if (memcmp(data_buffer, expected, pingLength) != 0) {
        PRINTF("Received unexpected data: '%.*s', expected: '%s'\n", data_length, data_buffer, expected);
        int len = 5;
        os_memmove(G_io_apdu_buffer, "hello", len);
        io_exchange_with_code(SW_OK, len);
	} else {
        int pongLength = 4;
        os_memmove(G_io_apdu_buffer, "pong", pongLength);
        io_exchange_with_code(SW_OK, pongLength);
	}
}
