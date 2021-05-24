#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "stringify_bip32_path.h"

static int stringify_bip32_path_single_component(
	uint32_t input_bip32_component,
	char *output_bip32_component_string
) {
	uint32_t unhardened_bip32_path_component_uint32 = input_bip32_component;
	bool is_hardened = false;
	if (unhardened_bip32_path_component_uint32 >= 0x80000000) {
		is_hardened = true;
		unhardened_bip32_path_component_uint32 -= 0x80000000;
	}
	char str[12];
	SPRINTF(str, "%d", unhardened_bip32_path_component_uint32);

	int length = (int)strlen(str);
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
	for (unsigned int i = 0; i < number_of_bip32_components; i++) {
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
