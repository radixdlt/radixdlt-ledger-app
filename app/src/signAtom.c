#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "key_and_signatures.h"
#include "ui.h"
#include "global_state.h"
#include "sha256_hash.h"
#include "cbor.h"
#include "base_conversion.h"
#include "signAtomUI.h"
#include "common_macros.h"

static signAtomContext_t *ctx = &global.signAtomContext;

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    ByteStringCBORPrefixByte_address = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256 = 5,

    // Used for `token_definition_reference`
    ByteStringCBORPrefixByte_rri = 6
} CBORBytePrefixForByteArray;

static void printRRI(RadixResourceIdentifier *rri) {
    const size_t max_length = RADIX_RRI_STRING_LENGTH_MAX;
    char rri_utf8_string[max_length];
    to_string_rri(rri, rri_utf8_string, max_length, true);
    PRINTF("%s", rri_utf8_string);
}

static void empty_particle_meta_data() {
    explicit_bzero(&ctx->particle_meta_data, sizeof(ParticleMetaData));
    ctx->particle_meta_data.is_initialized = false;
}

static void empty_transfer() {
    explicit_bzero(&ctx->transfer, sizeof(Transfer));
    ctx->transfer.has_confirmed_serializer = false;
    ctx->transfer.is_address_set = false;
    ctx->transfer.is_amount_set = false;
    // ctx->transfer.is_token_definition_reference_set = false;
}

static void empty_atom_slice() {
    explicit_bzero(&ctx->atom_slice, MAX_ATOM_SLICE_SIZE);
}

static void reset_state() {
    ctx->atom_byte_count = 0;
    ctx->number_of_cached_bytes = 0;
    ctx->number_of_atom_bytes_received = 0;
    ctx->number_of_atom_bytes_parsed = 0;
    ctx->non_transfer_data_found = false;
    explicit_bzero(&ctx->bip32_path, NUMBER_OF_BIP32_COMPONENTS_IN_PATH * sizeof(uint32_t));
    empty_particle_meta_data();
    empty_transfer();
    empty_atom_slice();
}

static void initiate_hasher() {
    explicit_bzero(&ctx->hash, HASH256_BYTE_COUNT);
    cx_sha256_init(&ctx->hasher);
}

static void initiate_state() {
    reset_state();
    initiate_hasher();
}

static void empty_buffer() {
    explicit_bzero(G_io_apdu_buffer, IO_APDU_BUFFER_SIZE);
}

static void parse_bip_and_atom_size(
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
    // Input validation
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    size_t byte_count_of_atom_size = 2;
    uint16_t expected_data_length = expected_bip32_byte_count + byte_count_of_atom_size;
    
    if (dataLength != expected_data_length) {
        FATAL_ERROR("Incorrect 'dataLength', expected: %d, but got: %d", expected_data_length, dataLength);
    }

    // READ BIP32 path (12 bytes)
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32_path, NULL, 0);

    // READ Atom Byte Count (CBOR encoded data, max 2 bytes)
    ctx->atom_byte_count = U2BE(dataBuffer, expected_bip32_byte_count);
}

typedef enum {
    PayloadTypeIsParticleMetaData = 3,
    PayloadTypeIsAtomBytes = 4
} PayloadType;

static void parse_particle_meta_data(
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
    // READ meta data about particles from first chunk, available directly
    assert(dataLength == 20);
    
    // PRINTF("Received meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string:\n%.*H\n", dataLength, dataBuffer);
    int dataOffset = 0;

    PRINTF("Zeroing out old particle meta data now...\n");
    empty_particle_meta_data();

    ctx->particle_meta_data.particleItself.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.particleItself.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.addressOfRecipientByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.amountByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.amountByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.serializerValueByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.serializerValueByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->particle_meta_data.token_definition_referenceByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    PRINTF("Finished parsing particle meta data...\n");

    ctx->particle_meta_data.is_initialized = true;
}

static void update_hash(uint8_t* bytes, uint16_t byte_count, bool should_finalize_hash) {

    PRINTF("Updating hash with #%d bytes\n", byte_count);

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        bytes,
        byte_count,
        should_finalize_hash,
        ctx->hash);

    if (should_finalize_hash) {
          PRINTF("\nFinalizing hash!\n\n");
        // re-initiate hasher
        cx_sha256_init(&(ctx->hasher));

        // tmp copy of firstHash
        uint8_t hashedOnce[HASH256_BYTE_COUNT];
        os_memcpy(hashedOnce, ctx->hash, HASH256_BYTE_COUNT);

        sha256_hash(
            &(ctx->hasher),
            hashedOnce,
            HASH256_BYTE_COUNT,
            true,
            ctx->hash // put hash of hash in ctx->hash
        );
    }
}


/// If we just received a new ParticleMetaData this functions returns `0`, otherwise it returns the number of newly
/// recived atom bytes (i.e. bytes that needs to be use to update hash and possibly be parsed)
static uint8_t receive_bytes_from_host_machine_and_update_hash() {
    empty_buffer();
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    io_exchange(CHANNEL_APDU, 2);

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t number_of_atom_bytes_newly_received = G_io_apdu_buffer[OFFSET_LC];

    PayloadType payloadType = p1;

    switch (payloadType)
    {
    case PayloadTypeIsAtomBytes:
        ctx->number_of_atom_bytes_received += number_of_atom_bytes_newly_received;

        // Update hash
        bool should_finalize_hash = ctx->number_of_atom_bytes_received == ctx->atom_byte_count;

        update_hash(
            dataBuffer,
            number_of_atom_bytes_newly_received,
            should_finalize_hash
        );

        os_memcpy(
            ctx->atom_slice + ctx->number_of_cached_bytes,
            dataBuffer,
            number_of_atom_bytes_newly_received
        );
        return number_of_atom_bytes_newly_received;
    case PayloadTypeIsParticleMetaData:
        parse_particle_meta_data(dataBuffer, number_of_atom_bytes_newly_received);
        return 0; // Meta Data about Particle is not atom bytes, should not update hash with these
    default:
        FATAL_ERROR("Unrecognized P1 value: %d\n", p1)
    }
}

static bool is_meta_data_about_transferrable_tokens_particle() {
    assert(ctx->particle_meta_data.is_initialized);

    return (ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.amountByteInterval.byteCount > 0) &&
        (ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount > 0);
}

typedef enum {
    ParticleFieldNoField = 0,
    ParticleFieldAddress = 1,
    ParticleFieldAmount,
    ParticleFieldSerializer,
    ParticleFieldTokenDefinitionReference,
} ParticleField;

static CBORBytePrefixForByteArray cborBytePrefixForParticleField(ParticleField field)
{
    switch (field)
    {
    case ParticleFieldAddress:
    {
        return ByteStringCBORPrefixByte_address;
    }
    case ParticleFieldAmount:
    {
        return ByteStringCBORPrefixByte_uint256;
    }
    case ParticleFieldTokenDefinitionReference:
    {
        return ByteStringCBORPrefixByte_rri;
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }
}

// static ParticleField next_field_to_parse() {

//     if (!ctx->particle_meta_data.is_initialized) {
//         FATAL_ERROR("No particle meta data");
//     }

//     if (!is_meta_data_about_transferrable_tokens_particle())
//     {
//         PRINTF("Next field: 'Serializer' (since non TTP)\n");
//         return ParticleFieldSerializer;
//     }

//     if (!ctx->transfer.is_address_set) {
//         PRINTF("Next field: 'Address'\n");
//         return ParticleFieldAddress;
//     }

//     if (!ctx->transfer.is_amount_set) {
//         PRINTF("Next field: 'Amount'\n");
//         return ParticleFieldAmount;
//     }

//     if (!ctx->transfer.has_confirmed_serializer)
//     {
//         PRINTF("Next field: 'Serializer' (since not confirmed it for current TTP)\n");
//         return ParticleFieldSerializer;
//     }

//     PRINTF("Next field: 'TokenDefinitionReference'\n");
//     assert(!ctx->transfer.is_token_definition_reference_set)
//     return ParticleFieldTokenDefinitionReference;
// }


// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
static bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length
) {
    return (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0);
}

// Returns `true` iff `cborValue` indicates a TransferrableTokensParticle
static bool parseSerializer_is_ttp(
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
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    assert(numberOfBytesReadByCBORParser == valueByteCount);
    PRINTF("Parsed particle serializer: '%s'\n", textString);
    return is_transferrable_tokens_particle_serializer(textString, valueByteCount);
}


static void parseParticleField(
    const size_t valueByteCount,
    CborValue *cborValue,
    ParticleField field,

    uint8_t *output_buffer
) {

    CBORBytePrefixForByteArray cborBytePrefix = cborBytePrefixForParticleField(field);

    size_t numberOfBytesReadByCBORParser = valueByteCount;
    uint8_t byteString[valueByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == valueByteCount);
    assert(byteString[0] == cborBytePrefix);

    os_memcpy(
        output_buffer,
        byteString + 1, // Drop first CBOR prefix byte
        valueByteCount);
}

// static ByteInterval next_byte_interval(
//     ParticleField type_of_field_to_parse
// ) {
//     switch (type_of_field_to_parse)
//     {
//     case ParticleFieldAddress:
//         return ctx->particle_meta_data.addressOfRecipientByteInterval;
//     case ParticleFieldAmount:
//         return ctx->particle_meta_data.amountByteInterval;
//     case ParticleFieldSerializer:
//         return ctx->particle_meta_data.serializerValueByteInterval;
//     case ParticleFieldTokenDefinitionReference:
//         return ctx->particle_meta_data.token_definition_referenceByteInterval;
//     }
// }

static void cache_bytes_to_next_chunk(
    const uint16_t field_position_in_atom_slice,
    const uint16_t number_of_bytes_to_cache
) {
    PRINTF("number_of_bytes_to_cache: %d\n", number_of_bytes_to_cache);

    if (number_of_bytes_to_cache > MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS) {
        FATAL_ERROR("ERROR cannot cache that many bytes, max is %d\n", MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
    }

    assert(number_of_bytes_to_cache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
    uint8_t tmp[number_of_bytes_to_cache];

    os_memcpy(
        tmp,
        ctx->atom_slice + field_position_in_atom_slice,
        number_of_bytes_to_cache);

    empty_atom_slice();

    os_memcpy(
        ctx->atom_slice,
        tmp,
        number_of_bytes_to_cache);

    ctx->number_of_cached_bytes = number_of_bytes_to_cache;
}

static void print_particle_field_type(ParticleField field_type) {
    switch (field_type)
    {
    case ParticleFieldNoField:
        PRINTF("ERROR No Field\n");
        break;
    case ParticleFieldAddress:
        PRINTF("Address Field\n");
        break;
    case ParticleFieldAmount:
        PRINTF("Amount Field\n");
        break;
    case ParticleFieldSerializer:
        PRINTF("Serializer Field\n");
        break;
    case ParticleFieldTokenDefinitionReference:
        PRINTF("TokenDefinitionReference Field\n");
        break;
    }
}

// static void resume_parsing_atom() {
//     unsigned int tx = 0;
//     G_io_apdu_buffer[tx++] = 0x90;
//     G_io_apdu_buffer[tx++] = 0x00;
//     // Send back the response, do not restart the event loop
//     io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, tx);
//     // Display back the original UX
//     ui_idle();
// }

static void parse_particle_field_from_atom_slice(
    ParticleField type_of_field_to_parse,
    uint16_t offset_to_bytes_in_slice,
    const size_t field_byte_count
) {

    PRINTF("Trying to parse field\n");
    print_particle_field_type(type_of_field_to_parse);
    PRINTF("With #%dbytes\n", field_byte_count);
    PRINTF("offset_to_bytes_in_slice: %d\n", offset_to_bytes_in_slice);


    CborParser cborParser;
    CborValue cborValue;
    CborError cborError = cbor_parser_init(
        ctx->atom_slice + offset_to_bytes_in_slice,
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

    switch (type_of_field_to_parse)
    {
        case ParticleFieldNoField: 
        FATAL_ERROR("Incorrect impl");
        break;

    case ParticleFieldAddress:
        assert(type == CborByteStringType);
        assert(!ctx->transfer.is_address_set);

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAddress, 
            ctx->transfer.address.bytes
        );
        
        ctx->transfer.is_address_set = true;

        PRINTF("Parsed address\n");
        // PRINTF("Parsed address: "); printRadixAddress(&ctx->transfer.address);PRINTF("\n");

        break;

    case ParticleFieldAmount:
        assert(type == CborByteStringType);
        assert(ctx->transfer.is_address_set);
        assert(!ctx->transfer.is_amount_set);

        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldAmount, 
            ctx->transfer.amount.bytes
        );
        ctx->transfer.is_amount_set = true;

        PRINTF("Parsed amount\n");
        // PRINTF("Parsed amount: "); printTokenAmount(&ctx->transfer.amount);PRINTF("\n");

        break;

    case ParticleFieldSerializer:
        assert(type == CborTextStringType);
        assert(!ctx->transfer.has_confirmed_serializer);
        
        bool is_transferrable_tokens_particle_serializer = parseSerializer_is_ttp(readLength, &cborValue);

        assert(ctx->transfer.is_address_set == is_transferrable_tokens_particle_serializer);
        assert(ctx->transfer.is_amount_set == is_transferrable_tokens_particle_serializer);

        if (!is_transferrable_tokens_particle_serializer) {
            ctx->non_transfer_data_found = true;
        } else {
            ctx->transfer.has_confirmed_serializer = true;
        }

        break;

    case ParticleFieldTokenDefinitionReference:
        assert(type == CborByteStringType);
        assert(ctx->transfer.has_confirmed_serializer);
        assert(ctx->transfer.is_address_set);
        assert(ctx->transfer.is_amount_set);
        // assert(!ctx->transfer.is_token_definition_reference_set);
        
        parseParticleField(
            readLength, 
            &cborValue, 
            ParticleFieldTokenDefinitionReference, 
            ctx->transfer.token_definition_reference.bytes
        );

        // ctx->transfer.is_token_definition_reference_set = true;
        
        PRINTF("Parsed RRI\n");
        // PRINTF("Parsed RRI: "); printRRI(&ctx->transfer.token_definition_reference);PRINTF("\n");

        if (!is_transfer_change_back_to_me()) {
            PRINTF("Asking for input from user to approve transfer\n");
    
            // display_lines("Review", "Transfer", resume_parsing_atom);
            display_lines("Review", "Transfer", prepareForApprovalOfAddress);
    
            io_exchange(CHANNEL_APDU | IO_ASYNCH_REPLY, 0);
        } else {
            PRINTF("Found transfer, but is change back to me, so skipping it..\n");
        }

  
        PRINTF("Awesome, resumed program...now emptying transfer\n");
        empty_transfer();

        break;
    }

    // return readLength;
}

static int number_of_overlapping_bytes_in_intervals(
    ByteInterval a,
    ByteInterval b
) {
	return MAX(
		0, 
        MIN(end_index(a), end_index(b)) - MAX(a.startsAt, b.startsAt)
	);
}

static bool atom_slice_contains_particles_bytes() {
    assert(ctx->particle_meta_data.is_initialized);
    int overlapping_byte_count = number_of_overlapping_bytes_in_intervals(
       ctx->interval_of_atom_slice,
       ctx->particle_meta_data.particleItself
    );

    PRINTF("overlapping_byte_count: %d\n", overlapping_byte_count);

    return overlapping_byte_count > 0;
}

static void print_particle_metadata() {
    PRINTF("META DATA ABOUT PARTICLE [%d-%d] (#%d bytes)\n", 
        ctx->particle_meta_data.particleItself.startsAt, 
        end_index(ctx->particle_meta_data.particleItself), 
        ctx->particle_meta_data.particleItself.byteCount
    );

    PRINTF("field 'Address' [%d-%d] (#%d bytes)\n", 
        ctx->particle_meta_data.addressOfRecipientByteInterval.startsAt, 
        end_index(ctx->particle_meta_data.addressOfRecipientByteInterval), 
        ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount
    );
    
    PRINTF("field 'Amount' [%d-%d] (#%d bytes)\n", 
        ctx->particle_meta_data.amountByteInterval.startsAt, 
        end_index(ctx->particle_meta_data.amountByteInterval), 
        ctx->particle_meta_data.amountByteInterval.byteCount
    );

    PRINTF("field 'Serializer' [%d-%d] (#%d bytes)\n", 
        ctx->particle_meta_data.serializerValueByteInterval.startsAt, 
        end_index(ctx->particle_meta_data.serializerValueByteInterval), 
        ctx->particle_meta_data.serializerValueByteInterval.byteCount
    );

    PRINTF("field 'TokenDefRef' [%d-%d] (#%d bytes)\n", 
        ctx->particle_meta_data.token_definition_referenceByteInterval.startsAt, 
        end_index(ctx->particle_meta_data.token_definition_referenceByteInterval), 
        ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount
    );
}

static void print_current_atom_slice() {
     PRINTF("current atom slice [%d-%d] (#%d bytes)\n", 
                ctx->interval_of_atom_slice.startsAt, 
                end_index(ctx->interval_of_atom_slice), 
                ctx->interval_of_atom_slice.byteCount
    );
}

// static bool can_parse_any_particle_field_with_current_atom_slice() {
    
//     PRINTF("START of can_parse_any_particle_field_with_current_atom_slice\n");
//     print_current_atom_slice();
//     print_particle_metadata();

//     uint16_t first_relevant_particle_byte_index = 0;
//     uint16_t index = 0;
//     uint16_t byteCount = 0;

//     if (ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount > 0) {

//     index = ctx->particle_meta_data.token_definition_referenceByteInterval.startsAt;
//     if (index > 0) {
//         first_relevant_particle_byte_index = index;
//         byteCount = ctx->particle_meta_data.token_definition_referenceByteInterval.byteCount;
//         PRINTF("first_relevant_particle_byte_index := tokenDefRef.startsAt\n");
//     }
//     }
    
//     if (ctx->particle_meta_data.serializerValueByteInterval.byteCount > 0) {
//     index = ctx->particle_meta_data.serializerValueByteInterval.startsAt;
//     if (index < first_relevant_particle_byte_index) {
//         first_relevant_particle_byte_index = index;
//         byteCount = ctx->particle_meta_data.serializerValueByteInterval.byteCount;
//         PRINTF("first_relevant_particle_byte_index := serializerField.startsAt\n");
//     }
//     }

//  if (ctx->particle_meta_data.amountByteInterval.byteCount > 0) {

//     index = ctx->particle_meta_data.amountByteInterval.startsAt;
//     if (index < first_relevant_particle_byte_index) {
//         first_relevant_particle_byte_index = index;
//         byteCount = ctx->particle_meta_data.amountByteInterval.byteCount;
//         PRINTF("first_relevant_particle_byte_index := amountField.startsAt\n");
//     }
//  }

//  if (ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount > 0) {
//     index = ctx->particle_meta_data.addressOfRecipientByteInterval.startsAt;
//     if (index < first_relevant_particle_byte_index) {
//         first_relevant_particle_byte_index = index;
//         byteCount = ctx->particle_meta_data.addressOfRecipientByteInterval.byteCount;
//         PRINTF("first_relevant_particle_byte_index := addressField.startsAt\n");
//     }
//  }
    
//     PRINTF("first_relevant_particle_byte_index: %d\ncurrentAtomSlice.endsWith: %d\n", first_relevant_particle_byte_index, end_index(ctx->interval_of_atom_slice));

//     bool has_reached_first_relevant_bytes_in_particle_yet = first_relevant_particle_byte_index > ctx->interval_of_atom_slice.startsAt;

//     if (!has_reached_first_relevant_bytes_in_particle_yet) {
//         PRINTF("Has not yet reached any relevant bytes...\n");
//         return false;
//     }

//     if (first_relevant_particle_byte_index + byteCount > end_index(ctx->interval_of_atom_slice)) {
//         PRINTF("PROBABLY SHOULD CACHE BYTES HERE ALREADY? Skipping this atom slice...\n");
//         return false;
//     }

//     return true;
// }

// Returns true if there is a next interval to parse (populated in input param)
static bool next_field_to_parse_and_update_atom_slice(
    ByteInterval* interval, 
    ByteInterval* output, 
    bool *is_done_with_slice,
    ParticleField *output_field_type,
    ParticleField field_to_test
) {

    PRINTF("Checking if next field is");print_particle_field_type(field_to_test);
    *output_field_type = field_to_test;

    if (interval->byteCount == 0) {
        PRINTF("Skipping field since it has zero bytes: ");print_particle_field_type(field_to_test);
        return false;
    }
 
    if (end_index(ctx->interval_of_atom_slice) < end_index(*interval)) {
        PRINTF("`currentAtomSlice.endsWith < interval.endsWith` => cache bytes!?\n");
        print_particle_metadata();
        print_current_atom_slice();
        ctx->number_of_cached_bytes = ctx->interval_of_atom_slice.byteCount;
        *is_done_with_slice = true;
        return false;
    }

    if (ctx->interval_of_atom_slice.startsAt > interval->startsAt) {
        PRINTF("Interval not in atom slice, maybe another interval for the same particle?\n");
        return false;
    }

    if (ctx->interval_of_atom_slice.startsAt != interval->startsAt) {
        PRINTF("`currentAtomSlice.startsAt != interval.startsAt` => setting `currentAtomSlice.startsAt := interval.startsAt` and decreasing `currentAtomSlice.byteCount`\n");
    
        PRINTF("BEFORE\n");
        print_current_atom_slice();

        ctx->interval_of_atom_slice.byteCount -= (interval->startsAt -  ctx->interval_of_atom_slice.startsAt);

        assert(ctx->interval_of_atom_slice.byteCount >= 0);

	    ctx->interval_of_atom_slice.startsAt = interval->startsAt;

        PRINTF("AFTER\n");
        print_current_atom_slice();
    }
	
	assert(ctx->interval_of_atom_slice.startsAt == interval->startsAt);
    *output = *interval;
    return true;
}

static bool does_atom_slice_overlap_with_field(ByteInterval interval) {
    if (interval.byteCount == 0) {
        return false;
    }

    return number_of_overlapping_bytes_in_intervals(interval, ctx->interval_of_atom_slice)> 0;
}

// Returns true if there is a next interval to parse (populated in input param)
static bool get_interval_of_next_field_to_parse(
    ParticleField *field_type, 
    ByteInterval *next_field
) {
	assert(ctx->particle_meta_data.is_initialized);

    ParticleMetaData md = ctx->particle_meta_data;
    if (
        !(
            does_atom_slice_overlap_with_field(md.addressOfRecipientByteInterval) ||
            does_atom_slice_overlap_with_field(md.amountByteInterval) ||
            does_atom_slice_overlap_with_field(md.serializerValueByteInterval) ||
            does_atom_slice_overlap_with_field(md.token_definition_referenceByteInterval)
        )
    ) {
        PRINTF("Not yet reached relevant atom bytes\nSHOULD CACHE (skipped now...)??!\n");
        return false;
    }

    bool is_done_with_slice = false;

    if (
        !is_done_with_slice,
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.addressOfRecipientByteInterval, 
            next_field,
            &is_done_with_slice,
            field_type,
            ParticleFieldAddress
        )
    ) {
        return true;
    }

    if (
        !is_done_with_slice,
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.amountByteInterval,
            next_field,
            &is_done_with_slice,
            field_type,
            ParticleFieldAmount
        )
    ) {
        return true;
    }

    if (
        !is_done_with_slice,
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.serializerValueByteInterval,
            next_field,
            &is_done_with_slice,
            field_type,
            ParticleFieldSerializer
        )
    ) {
        return true;
    }

    if (
        !is_done_with_slice,
        next_field_to_parse_and_update_atom_slice(
            &ctx->particle_meta_data.token_definition_referenceByteInterval,
            next_field,
            &is_done_with_slice,
            field_type,
            ParticleFieldTokenDefinitionReference
        )
    ) {
        return true;
    }
	
    PRINTF("No next particle field in current atom slice to parse. is_done_with_slice: %s\n", is_done_with_slice ? "TRUE" : "FALSE");


    if (end_index(ctx->particle_meta_data.particleItself) < end_index(ctx->interval_of_atom_slice)) {
        PRINTF("Particle meta data not relevant anymore since current atom slice starts at a byte later than end of the particle => `setting ctx->particle_meta_data.is_initialized := false` to mark that it is not relevant any more\n");

        ctx->particle_meta_data.is_initialized = false;
    }

    return false;
}
	

static void parse_bytes_from_host_machine() {
    
    PRINTF("\n\n\n#######################################\nparse_bytes_from_host_machine START\n");

    uint8_t number_of_cached_bytes = ctx->number_of_cached_bytes;
        ctx->number_of_cached_bytes = 0;


    uint16_t chunk_start_position_in_atom = ctx->number_of_atom_bytes_received - number_of_cached_bytes;

    uint8_t number_of_newly_received_bytes = receive_bytes_from_host_machine_and_update_hash();

    if (number_of_newly_received_bytes) {
        // Parse newly received Atom bytes if able/needed

        if (!ctx->particle_meta_data.is_initialized) {
            PRINTF("Skipping parsing atom bytes since we have no particle meta data");
        	return;
        }

        assert(ctx->particle_meta_data.is_initialized);
        print_particle_metadata();

        PRINTF("Number of newly received atom bytes: %d\n", number_of_newly_received_bytes);
        PRINTF("Number of cached bytes since last payload: %d\n", number_of_cached_bytes);

        PRINTF("Chunk/payload start position in atom: %d\n", chunk_start_position_in_atom);

        if (number_of_cached_bytes > 0) {
            PRINTF("bytes received (incl cached):\n");
            PRINTF("%.*h\n", number_of_newly_received_bytes + number_of_cached_bytes, ctx->atom_slice);
        } else {
            PRINTF("bytes received (none cached):\n");
            PRINTF("%.*h\n", number_of_newly_received_bytes, ctx->atom_slice);
        }

        ctx->interval_of_atom_slice = (ByteInterval) { 
            .startsAt = chunk_start_position_in_atom,
            .byteCount = number_of_cached_bytes + number_of_newly_received_bytes
        };

        // if (!can_parse_any_particle_field_with_current_atom_slice()) {
        //     PRINTF("Skipping atom bytes since first relevant bytes according to particle meta data has not been reached yet (no need to cache...)\n");
        //     return;
        // }


        int counter_DEBUG_ONLY = 0;

        ByteInterval interval_of_next_field_to_parse;
        ParticleField particle_field_type;

        while (atom_slice_contains_particles_bytes() && ctx->particle_meta_data.is_initialized) { // will "slide" atom slice window
            PRINTF("parse_atom_bytes (ITERATION=%d)\n", counter_DEBUG_ONLY);

            print_current_atom_slice();

            bool can_parse_field = get_interval_of_next_field_to_parse(
                &particle_field_type,
                &interval_of_next_field_to_parse
            );

            if (can_parse_field) {
                PRINTF("Cool! Will try to parse field\n");
                print_particle_field_type(particle_field_type);
                PRINTF("With interval: [%d-%d] (#%d bytes)\n", interval_of_next_field_to_parse.startsAt, end_index(interval_of_next_field_to_parse), interval_of_next_field_to_parse.byteCount);
            }

            if (ctx->number_of_cached_bytes > 0) {
                assert(!can_parse_field);
                PRINTF("CACHING BYTES?\n");

                if (!does_atom_slice_overlap_with_field(interval_of_next_field_to_parse)) {
                    PRINTF("No no need to cache bytes since they are not relevant.Right?\n");
                    print_current_atom_slice();
                    print_particle_metadata();
                    PRINTF("Right!?\n");
                    break;
                }

                cache_bytes_to_next_chunk(
                    interval_of_next_field_to_parse.startsAt - chunk_start_position_in_atom,
                    ctx->number_of_cached_bytes
                );
            }

            if (!can_parse_field) {
                return;
            }


            parse_particle_field_from_atom_slice(
                particle_field_type,
                interval_of_next_field_to_parse.startsAt - chunk_start_position_in_atom,
                interval_of_next_field_to_parse.byteCount
            );

            PRINTF("Finished parsing field, updating currentAtomSlice\n~before:\n");
            print_current_atom_slice();

	        ctx->interval_of_atom_slice.startsAt = end_index(interval_of_next_field_to_parse);
            ctx->interval_of_atom_slice.byteCount -= interval_of_next_field_to_parse.byteCount;

            PRINTF("~after\n");
            print_current_atom_slice();

            counter_DEBUG_ONLY += 1;
        }

        if (
            !ctx->particle_meta_data.is_initialized 
            && 
            ctx->number_of_cached_bytes == 0 
            && end_index(ctx->interval_of_atom_slice) != end_index(ctx->particle_meta_data.particleItself)
        ) {
            PRINTF("\n\n!!!! WARNING! Might have missed caching bytes..? !!!!\n\n");
        } 

    } else {
        assert(ctx->particle_meta_data.is_initialized);
        PRINTF("Just got a new particle meta data, nothing to do.\n");
    }
}

static void parse_atom() {
    while (ctx->number_of_atom_bytes_parsed < ctx->atom_byte_count) {
        parse_bytes_from_host_machine();
    }
    PRINTF("Finished parsing all atom bytes => Asking user to confirm hash on Ledger...\n");
    askUserForConfirmationOfHash();
}

static void parse_and_sign_atom(
    const uint8_t number_of_up_particles,
    uint8_t *dataBuffer,
    const uint16_t dataLength
) {
	initiate_state();
    ctx->number_of_up_particles = number_of_up_particles;
	parse_bip_and_atom_size(dataBuffer, dataLength);
    
    parse_atom();
}

void handleSignAtom(
    uint8_t p1,
    uint8_t p2,
    uint8_t *dataBuffer,
    uint16_t dataLength,
    volatile unsigned int *flags,
    volatile unsigned int *tx)
{
    parse_and_sign_atom(
        p1,
        dataBuffer,
        dataLength
    );

    *flags |= IO_ASYNCH_REPLY;
}
