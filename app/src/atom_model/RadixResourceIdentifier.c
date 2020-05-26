#include "RadixResourceIdentifier.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include "radix.h"
// #include <os_io_seproxyhal.h>

size_t to_string_rri(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address
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

    assert(output_buffer[0] == '/'); // All RRIs start with leading slash

    uint8_t length_of_symbol = 0;
    if (skip_address)
    {
        unsigned int index_from_start_of_slash = 0;
        // First seek from back until we hit '/', and save the index (counting from start, not back)
        for (unsigned int i = length - 1; (length - i) < RADIX_RRI_MAX_LENGTH_SYMBOL; --i) {
            if (output_buffer[i] == '/') {
                index_from_start_of_slash = i;
                break;
            }
            length_of_symbol++;
        }
        assert((length - index_from_start_of_slash) < RADIX_RRI_MAX_LENGTH_SYMBOL);

        length = length_of_symbol;
        os_memcpy(output_buffer, output_buffer + index_from_start_of_slash + 1, length_of_symbol);
    }

    output_buffer[length] = '\0';
    return length + 1; // +1 for NULL
}