#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "stringify_bip32_path.h"

// https://stackoverflow.com/a/2182581/1311272
static void SwapBytes(void *pv, size_t n) {
    char *p = pv;
    size_t lo, hi;
    for(lo=0, hi=n-1; hi>lo; lo++, hi--)
    {
        char tmp=p[lo];
        p[lo] = p[hi];
        p[hi] = tmp;
    }
}

static void byte_array_from_number(char *buffer, uint32_t number) {
    int i;
    for (i=0; i<sizeof(uint32_t); i++) {
        buffer[i] = number & 0xFF; // place bottom 8 bits in char
        number = number >> 8; // shift down remaining bits
    }
    return; 
}


static int stringify_bip32_path_single_component(
	uint32_t input_bip32_component,
	char *output_bip32_component_string
) {

	uint8_t parsed[4];
	byte_array_from_number(parsed, input_bip32_component);
	SwapBytes(parsed, 4);
	bool is_hardened = false;
	if (parsed[0] >= 0x80) {
		is_hardened = true;
		parsed[0] -= 0x80;
	}

	uint32_t unhardened_bip32_path_component_uint32 = U4BE(parsed, 0);

	char str[12];
	SPRINTF(str, "%d", unhardened_bip32_path_component_uint32);

	int length = strlen(str);
	if (is_hardened) {
		str[length] = '\'';
		str[length + 1] = '\0';
		length += 1;
	}
	os_memcpy(output_bip32_component_string, str, length);
	return length;
}

int stringify_bip32_path(
	uint32_t *input_bip32_bytes,
	unsigned int number_of_bip32_components,
	char *output_bip32_string
) {
	
	int length_of_output_string = 0;
	for (int i = 0; i < number_of_bip32_components; i++) {
		char string_from_path_comp[20]; // will not need 20 chars, just placeholder...
		
		int length_of_string_for_this_component = stringify_bip32_path_single_component(
			input_bip32_bytes[i], 
			string_from_path_comp
		);

		os_memcpy(
			output_bip32_string + length_of_output_string,
			string_from_path_comp,
			length_of_string_for_this_component
		);
		
		length_of_output_string += length_of_string_for_this_component;

		if (i < (number_of_bip32_components - 1)) {
			os_memset(output_bip32_string + length_of_output_string, '/', 1);
			length_of_output_string += 1;
		}
	}
	return length_of_output_string;
}
