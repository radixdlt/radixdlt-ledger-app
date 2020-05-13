#include "RadixResourceIdentifier.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
// #include <os_io_seproxyhal.h>

size_t to_string_rri(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer
) {
    assert(size_of_buffer >= RADIX_RRI_STRING_LENGTH_MAX);

    uint8_t length = 0;
    for (unsigned i = 0; i < RADIX_RRI_MAX_BYTE_COUNT; ++i)
    {
        uint8_t valueAtI = *(rri->bytes + i);
        
        if (valueAtI == 0x00)
            break;

        SPRINTF(output_buffer + i, "%c", valueAtI);
        length++;
    }
    output_buffer[length] = '\0';
    return length + 1; // +1 for NULL
}