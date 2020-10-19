#include "dson.h"
#include "common_macros.h"

CBORBytePrefixForByteArray cborBytePrefixForParticleFieldType(ParticleFieldType field)
{
    switch (field)
    {
    case ParticleFieldTypeAddress:
    {
        return ByteStringCBORPrefixByte_address;
    }
    case ParticleFieldTypeAmount:
    {
        return ByteStringCBORPrefixByte_uint256;
    }
    case ParticleFieldTypeTokenDefinitionReference:
    {
        return ByteStringCBORPrefixByte_rri;
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }
}


// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
) {
    return (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0);
}

// Returns `true` iff `cborValue` indicates a TransferrableTokensParticle
bool parseSerializer_is_ttp(
    const size_t valueByteCount,
    CborValue *cborValue)
{
    size_t numberOfBytesReadByCBORParser = valueByteCount;
    char textString[valueByteCount]; 
    CborError cborError = cbor_value_copy_text_string(
        cborValue,
        textString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR error: '%s'\n", cbor_error_string(cborError));
    }

    assert(numberOfBytesReadByCBORParser == valueByteCount);

    bool is_TTP = is_transferrable_tokens_particle_serializer(textString, valueByteCount);
    if (!is_TTP) {
        PRINTF("\n@ Identified non TransferrableTokensParticle: '%s'\n\n", textString);
    }
    return is_TTP;
}

static void parse_particle_field(
    const size_t valueByteCount,
    CborValue *cborValue,
    ParticleFieldType field_type,
    uint8_t *output_buffer
) {

    CBORBytePrefixForByteArray cborBytePrefix = cborBytePrefixForParticleFieldType(field_type);

    size_t numberOfBytesReadByCBORParser = valueByteCount;
    uint8_t byteString[valueByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing field in atomSlice, CBOR error: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == valueByteCount);
    assert(byteString[0] == cborBytePrefix);

    // PRINTF("Parsed field value: ");
    // PRINTF("%.*h\n", valueByteCount - 1, byteString + 1);

    os_memcpy(
        output_buffer,
        byteString + 1, // Drop first CBOR prefix byte
        valueByteCount - 1);
}


ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    ParticleField *particle_field,
    uint8_t *bytes,
    Transfer *transfer
) {
    // PRINTF("Parse field and populate transfer START\n");
    // print_particle_field(particle_field);
    // PRINTF("\nFrom bytes:\n");
    // PRINTF("%.*h\n", field_byte_count, bytes);

    size_t field_byte_count = particle_field->byte_interval.byteCount;
    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        bytes,
        field_byte_count,
        0, // flags
        &cborParser,
        &cborValue);

    if (cborError)
    {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    CborType type = cbor_value_get_type(&cborValue);
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);

    if (cborError)
    {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR error: '%s'\n", cbor_error_string(cborError));
    }

    switch (particle_field->field_type)
    {
    case ParticleFieldTypeNoField: 
        FATAL_ERROR("Incorrect impl");
    case ParticleFieldTypeAddress:
        assert(type == CborByteStringType);
        assert(!transfer->is_address_set);

        parse_particle_field(
            readLength, 
            &cborValue, 
            particle_field->field_type, 
            &transfer->address.bytes
        );
        
        transfer->is_address_set = true;
        return ParseFieldResultParsedPartOfTransfer;

    case ParticleFieldTypeAmount:
        assert(type == CborByteStringType);
        assert(transfer->is_address_set);
        assert(!transfer->is_amount_set);

        parse_particle_field(
            readLength, 
            &cborValue, 
            particle_field->field_type, 
            &transfer->amount.bytes
        );
        transfer->is_amount_set = true;
        return ParseFieldResultParsedPartOfTransfer;

    case ParticleFieldTypeSerializer:
        assert(type == CborTextStringType);
        assert(!transfer->has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parseSerializer_is_ttp(readLength, &cborValue);

        assert(transfer->is_address_set == is_transferrable_tokens_particle_serializer);
        assert(transfer->is_amount_set == is_transferrable_tokens_particle_serializer);

        if (is_transferrable_tokens_particle_serializer) {
            transfer->has_confirmed_serializer = true;
            return ParseFieldResultParsedPartOfTransfer;
        } else {
            return ParseFieldResultNonTransferDataFound;
        }

    case ParticleFieldTypeTokenDefinitionReference:
        assert(type == CborByteStringType);
        assert(transfer->has_confirmed_serializer);
        assert(transfer->is_address_set);
        assert(transfer->is_amount_set);
        assert(!transfer->is_token_definition_reference_set);
        
        parse_particle_field(
            readLength, 
            &cborValue, 
            particle_field->field_type, 
            transfer->token_definition_reference.bytes
        );

        transfer->is_token_definition_reference_set = true;
        return ParseFieldResultFinishedParsingTransfer;
    }
}