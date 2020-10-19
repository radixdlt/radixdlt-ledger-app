#include "RadixResourceIdentifier.h"
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include "key_and_signatures.h"
#include "common_macros.h"

size_t to_string_rri(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address
) {
    return to_string_rri_null_term_or_not(rri, output_buffer, size_of_buffer, skip_address, true);
}

size_t to_string_rri_null_term_or_not(
    RadixResourceIdentifier *rri,
    char *output_buffer,
    const size_t size_of_buffer,
    bool skip_address,
    bool null_terminate
) {
   if (skip_address) {
       assert(size_of_buffer >= RADIX_RRI_MAX_LENGTH_SYMBOL);
   }
   else
   {
       assert(size_of_buffer >= RADIX_RRI_STRING_LENGTH_MAX);
   }

    uint8_t length = 0;
    bool address_parsed = false;
    for (unsigned i = 0; i < RADIX_RRI_MAX_BYTE_COUNT; ++i)
    {
        uint8_t valueAtI = *(rri->bytes + i);
        if (!valueAtI)
            break;

        if (!address_parsed && i > 0 && valueAtI == '/')
        {
            address_parsed = true;
        }

        if (skip_address && !address_parsed)
        {
            continue;
        }
        output_buffer[length] = valueAtI;
        length++;
    }

    if (skip_address) { // remove leading "/" from symbol
        os_memmove(output_buffer, output_buffer + 1, length - 1);
        length--;
    }

    if (null_terminate) {
        output_buffer[length] = '\0';
        return length + 1; 
    } else {
        return length;
    }
}

void printRRI(RadixResourceIdentifier *rri) {
    const size_t max_length = RADIX_RRI_STRING_LENGTH_MAX;
    char rri_utf8_string[max_length];
    to_string_rri(rri, rri_utf8_string, max_length, true);
    PRINTF("%s", rri_utf8_string);
}
