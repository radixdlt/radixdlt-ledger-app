#include "base_conversion.h"

// Divide "number" of length "length" by "divisor" in place, returning remainder
uint8_t divmod(uint8_t *number, uint16_t length, uint8_t divisor) {
	uint8_t remainder = 0;
	for (uint16_t i = 0; i < length; i++) {
		uint16_t temp = remainder * 256 + number[i];
		number[i] = (uint8_t) (temp / divisor);
		remainder = temp % divisor;
	}
	return remainder;
}

// Returns true if first "length" bytes of "bytes" are zero, false otherwise
bool allZero(uint8_t *bytes, uint16_t length) {
	for (int i = 0; i < length; ++i) {
		if (bytes[i] != 0) {
			return false;
		}
	}
	return true;
}

// Swap element at index "i" with element at index "j" in "array"
void swap(char *array, uint16_t i, uint16_t j) {
	char temp = array[i];
	array[i] = array[j];
	array[j] = temp;
}

// Reverse the first "length" elements of "array"
void reverse(char *array, int length) {
	uint16_t swapLen = length / 2;
	uint16_t last = length - 1;
	for (uint16_t i = 0; i < swapLen; ++i) {
		swap(array, i, last - i);
	}
}

// Convert "bytes" of length "length" into decimal digits in "buffer", returning the length
uint16_t convertDecimalInto(uint8_t *bytes, int length, char *buffer) {
	uint16_t decimalIndex = 0;
	while (!allZero(bytes, length)) {
		buffer[decimalIndex++] = '0' + divmod(bytes, length, 10);
	}
	reverse(buffer, decimalIndex);
	return decimalIndex;
}

// Convert "bytes" of length "length" into base58 digits in "buffer", returning the length
uint16_t convertBase58Into(uint8_t *bytes, int length, char *buffer) {
	uint16_t index = 0;
	while (!allZero(bytes, length)) {
		buffer[index++] = '0' + divmod(bytes, length, 58);
	}
	reverse(buffer, index);
	return index;
}