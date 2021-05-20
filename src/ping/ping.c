#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "common_macros.h"
#include <string.h>

void handle_ping(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *data_buffer,
    uint16_t data_length,
    volatile unsigned int *flags,
    volatile unsigned int *tx
) {
	if (strcmp((char *)data_buffer, "ping") == 0) {
        int len = 4;
        os_memmove(G_io_apdu_buffer, "pong", len);
        io_exchange_with_code(SW_OK, len);
	} else {
        PRINTF("Received PING command, but payload was not 'ping'");
        PRINTF("Recived string: '%.*s'\n", data_length, data_buffer);
        int len = 5;
        os_memmove(G_io_apdu_buffer, "hello", len);
        io_exchange_with_code(SW_OK, len);
	}
}

// ixdlt-ledger-app git:(main) ✗ python3 -m ledgerblue.genCAPair
//Public key : 0422c5e9a8156db284d660eca98cc849aa8326a33361068d2b6c394fd2a93cb3803175f5b35ec1bda4471895c4c002bd859ca8e08b69f555164ba5d8d35e2dbc7f
//Private key: b5b2eacb2debcf4903060e0fa2a139354fe29be9e4ac7c433f694a3d93297eaa