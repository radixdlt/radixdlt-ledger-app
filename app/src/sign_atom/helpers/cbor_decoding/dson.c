#include "dson.h"
#include "common_macros.h"

CBORBytePrefixByteStringType cbor_byte_prefix_for_particle_field_type(ParticleFieldType field)
{
    switch (field)
    {
    case ParticleFieldTypeAddress:
    {
        return CBORBytePrefixByteStringAddress;
    }
    case ParticleFieldTypeAmount:
    {
        return CBORBytePrefixByteStringUInt256;
    }
    case ParticleFieldTypeTokenDefinitionReference:
    {
        return CBORBytePrefixByteStringRadixResourceIdentifier;
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

// Returns `true` iff `cbor_value` indicates a TransferrableTokensParticle
bool parse_serializer_check_if_transferrable_tokens_particle(
    const size_t value_byte_count,
    CborValue *cbor_value)
{
    size_t number_of_bytes_read_by_cbor_parser = value_byte_count;
    char text_string[value_byte_count]; 
    CborError cbor_error = cbor_value_copy_text_string(
        cbor_value,
        text_string,
        &number_of_bytes_read_by_cbor_parser,
        NULL);

    if (cbor_error)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR error: '%s'\n", cbor_error_string(cbor_error));
    }

    assert(number_of_bytes_read_by_cbor_parser == value_byte_count);

    bool is_transferrable_tokens_particle = is_transferrable_tokens_particle_serializer(text_string, value_byte_count);
    if (!is_transferrable_tokens_particle) {
        PRINTF("\n@ Identified non TransferrableTokensParticle: '%s'\n\n", text_string);
    }
    return is_transferrable_tokens_particle;
}

static void parse_particle_field(
    const size_t value_byte_count,
    CborValue *cbor_value,
    ParticleFieldType field_type,
    uint8_t *output_buffer
) {

    CBORBytePrefixByteStringType cbor_byte_prefix = cbor_byte_prefix_for_particle_field_type(field_type);

    size_t number_of_bytes_read_by_cbor_parser = value_byte_count;
    uint8_t byte_string[value_byte_count];
    CborError cbor_error = cbor_value_copy_byte_string(
        cbor_value,
        byte_string,
        &number_of_bytes_read_by_cbor_parser,
        NULL);

    if (cbor_error)
    {
        FATAL_ERROR("Error parsing field in atomSlice, CBOR error: '%s'\n", cbor_error_string(cbor_error));
    }

    // Sanity check
    assert(number_of_bytes_read_by_cbor_parser == value_byte_count);
    assert(byte_string[0] == cbor_byte_prefix);

    // PRINTF("Parsed field value: ");
    // PRINTF("%.*h\n", value_byte_count - 1, byte_string + 1);

    os_memcpy(
        output_buffer,
        byte_string + 1, // Drop first CBOR prefix byte
        value_byte_count - 1);
}


ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    particle_field_t *particle_field,
    uint8_t *bytes,
    transfer_t *transfer,
    CborParser *cbor_parser,
    CborValue *cbor_value
) {



    CborError cbor_error = cbor_parser_init(
        bytes,
        particle_field->byte_interval.byte_count,
        0, // flags
        cbor_parser,
        cbor_value
    );

    if (cbor_error) {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cbor_error));
    }

    CborType type = cbor_value_get_type(cbor_value);
    size_t read_length;
    cbor_error = cbor_value_calculate_string_length(cbor_value, &read_length);

    if (cbor_error) {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR error: '%s'\n", cbor_error_string(cbor_error));
    }

    switch (particle_field->field_type)
    {
    case ParticleFieldTypeNoField: 
        FATAL_ERROR("Incorrect impl");
    case ParticleFieldTypeAddress:
        assert(type == CborByteStringType);
        assert(!transfer->is_address_set);

        parse_particle_field(
            read_length, 
            cbor_value, 
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
            read_length, 
            cbor_value, 
            particle_field->field_type, 
            &transfer->amount.bytes
        );
        transfer->is_amount_set = true;
        return ParseFieldResultParsedPartOfTransfer;

    case ParticleFieldTypeSerializer:
        assert(type == CborTextStringType);
        assert(!transfer->has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parse_serializer_check_if_transferrable_tokens_particle(read_length, cbor_value);

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
            read_length, 
            cbor_value, 
            particle_field->field_type, 
            transfer->token_definition_reference.bytes
        );

        transfer->is_token_definition_reference_set = true;
        return ParseFieldResultFinishedParsingTransfer;
    }
}