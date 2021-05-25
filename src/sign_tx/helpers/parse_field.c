//
//  parse_field.c
//  LedgerXcodeProj
//
//  Created by Alexander Cyon on 2021-05-25.
//

#include "parse_field.h"



static void parse_particle_field(
    const size_t value_byte_count,
    uint8_t *bytes,
    ActionFieldType field_type,
    uint8_t *output_buffer
) {

//    CBORBytePrefixByteStringType cbor_byte_prefix = cbor_byte_prefix_for_particle_field_type(field_type);

    size_t number_of_bytes_read_by_cbor_parser = value_byte_count;
    uint8_t byte_string[value_byte_count];
//    CborError cbor_error = cbor_value_copy_byte_string(
//        cbor_value,
//        byte_string,
//        &number_of_bytes_read_by_cbor_parser,
//        NULL);
//
//    if (cbor_error)
//    {
//        FATAL_ERROR("Error parsing field in txSlice, CBOR error: '%s'\n", cbor_error_string(cbor_error));
//    }

    // Sanity check
    assert(number_of_bytes_read_by_cbor_parser == value_byte_count);
//    assert(byte_string[0] == cbor_byte_prefix);

    os_memcpy(
        output_buffer,
        byte_string + 1,
        value_byte_count - 1);
}



ParseFieldResult parse_field_from_bytes_and_populate_transfer(
    action_field_t *action_field,
    uint8_t *bytes,
    transfer_t *transfer,
    uint8_t *out_bytes,
    const size_t out_len
) {

//
//
//    CborType type = cbor_value_get_type(cbor_value);
    size_t read_length;
//    cbor_error = cbor_value_calculate_string_length(cbor_value, &read_length);
//
//    if (cbor_error) {
//        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR error: '%s'\n", cbor_error_string(cbor_error));
//    }

    switch (action_field->field_type)
    {
    case ActionFieldTypeNoField:
        FATAL_ERROR("Incorrect impl");
    case ActionFieldTypeValidatorAddress:
        FATAL_ERROR("Validator address field type is unhandled...");
    case ActionFieldTypeAccountAddress:
        assert(!transfer->is_address_set);
            
        parse_particle_field(
            read_length,
            bytes,
            action_field->field_type,
            (uint8_t *)&transfer->address.bytes
        );
        
        transfer->is_address_set = true;
        return ParseFieldResultParsedPartOfTransfer;

    case ActionFieldTypeAmount:
        assert(transfer->is_address_set);
        assert(!transfer->is_amount_set);

        parse_particle_field(
            read_length,
            bytes,
            action_field->field_type,
            (uint8_t *)&transfer->amount.bytes
        );
        transfer->is_amount_set = true;
        return ParseFieldResultParsedPartOfTransfer;

    case ActionFieldTypeActionType:
//        assert(type == CborTextStringType);
        assert(!transfer->has_confirmed_action_type);
        
//        bool is_transferrable_tokens_action_action_type = parse_action_type_check_if_transferrable_tokens_particle(read_length, cbor_value);
            bool is_transferrable_tokens_action_action_type = false;
            
        assert(transfer->is_address_set == is_transferrable_tokens_action_action_type);
        assert(transfer->is_amount_set == is_transferrable_tokens_action_action_type);

        if (is_transferrable_tokens_action_action_type) {
            transfer->has_confirmed_action_type = true;
            return ParseFieldResultParsedPartOfTransfer;
        } else {
            return ParseFieldResultNonTransferDataFound;
        }

    case ActionFieldTypeTokenDefinitionReference:
//        assert(type == CborByteStringType);
        assert(transfer->has_confirmed_action_type);
        assert(transfer->is_address_set);
        assert(transfer->is_amount_set);
        assert(!transfer->is_token_definition_reference_set);
        
        parse_particle_field(
            read_length,
            bytes,
            action_field->field_type,
            (uint8_t *)&transfer->token_definition_reference.bytes
        );

        transfer->is_token_definition_reference_set = true;
        return ParseFieldResultFinishedParsingTransfer;
    }
}
