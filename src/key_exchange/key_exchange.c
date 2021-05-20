#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "ui.h"
#include "common_macros.h"

void handle_key_exchange(
        uint8_t p1,
        uint8_t p2,
        uint8_t *data_buffer,
        uint16_t data_length,
        volatile unsigned int *flags,
        volatile unsigned int *tx
) {
    PRINTF("Function 'key_exchange' is not implemented yet.\n");
    THROW(SW_FATAL_ERROR_INCORRECT_IMPLEMENTATION);
}
