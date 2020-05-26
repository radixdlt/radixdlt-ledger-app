#include "base_conversion.h"

// Divide "number" of length "length" by "divisor" in place, returning remainder
static uint8_t divmod(uint8_t *number, uint16_t length, uint8_t divisor) {
	uint8_t remainder = 0;
	for (uint16_t i = 0; i < length; i++) {
		uint16_t temp = remainder * 256 + number[i];
		number[i] = (uint8_t) (temp / divisor);
		remainder = temp % divisor;
	}
	return remainder;
}

// Returns true if first "length" bytes of "bytes" are zero, false otherwise
static bool allZero(uint8_t *bytes, uint16_t length) {
	for (int i = 0; i < length; ++i) {
		if (bytes[i] != 0) {
			return false;
		}
	}
	return true;
}

// Swap element at index "i" with element at index "j" in "array"
static void swap(char *array, uint16_t i, uint16_t j) {
	char temp = array[i];
	array[i] = array[j];
	array[j] = temp;
}

// Reverse the first "length" elements of "array"
static void reverse(char *array, int length) {
	uint16_t swapLen = length / 2;
	uint16_t last = length - 1;
	for (uint16_t i = 0; i < swapLen; ++i) {
		swap(array, i, last - i);
	}
}

// Convert "bytes" of length "length" into digits of base "base" in "buffer", returning the length
static uint16_t convertByteBufferIntoDigitsWithBase(uint8_t *bytes, int length, char *buffer, uint8_t base) {
	uint16_t de_facto_length = 0;
	while (!allZero(bytes, length)) {
		// buffer[de_facto_length++] = '0' + divmod(bytes, length, base);
		buffer[de_facto_length++] = divmod(bytes, length, base);
	}
	reverse(buffer, de_facto_length);
	return de_facto_length;
}

// ##### "PUBLIC" methods (declared in `.h`-file) #####

// Convert "bytes" of length "length" into digits of base 10 in "buffer", returning the length
uint16_t convertByteBufferIntoDecimal(uint8_t *bytes, int length, char *buffer)
{
	uint8_t number_of_digits = convertByteBufferIntoDigitsWithBase(bytes, length, buffer, 10);
	uint8_t asciiOffset_decimal = '0';
	for (unsigned int digitIndex = 0; digitIndex < number_of_digits; ++digitIndex)
	{	
		buffer[digitIndex] += asciiOffset_decimal;
	}
	buffer[number_of_digits] = '\0'; // NULL terminate
	return number_of_digits;
}

// Convert "bytes" of length "length" into digits of base 58 in "buffer", returning the length
uint16_t convertByteBufferIntoBase58(uint8_t *bytes, int length, char *buffer) {
    uint8_t number_of_digits = convertByteBufferIntoDigitsWithBase(bytes, length, buffer, 58);

    static const char base58_digits[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    for (unsigned int digitIndex = 0; digitIndex < number_of_digits; ++digitIndex)
    {
        uint8_t base58DigitIndex = (uint8_t) buffer[digitIndex];
        buffer[digitIndex] = base58_digits[base58DigitIndex];
    }
    buffer[number_of_digits] = '\0'; // NULL terminate
    return number_of_digits;
}