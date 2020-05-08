#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <os.h>
#include <os_io_seproxyhal.h>
#include "radix.h"
#include "ux.h"
#include "sha256_hash.h"
#include "cbor.h"
// #include "RadixAddress.h"
// #include "RadixResourceIdentifier.h"
// #include "Transfer.h"

// Get a pointer to signHash's state variables. This is purely for
// convenience, so that we can refer to these variables concisely from any
// signHash-related function.
static signAtomContext_t *ctx = &global.signAtomContext;

static bool isZeroByteInterval(ByteInterval *byteInterval) {
	if (byteInterval->byteCount > 0) {
		return false;
	}
	assert(byteInterval->startsAt == 0);
	return true;
}

static bool isMetaDataForTransferrableTokensParticle(ParticleMetaData *particleMetaData) {
	if (isZeroByteInterval(&particleMetaData->addressOfRecipientByteInterval)) {
        assert(isZeroByteInterval(&particleMetaData->amountByteInterval));
        assert(isZeroByteInterval(&particleMetaData->tokenDefinitionReferenceByteInterval));
		return false;
	}
	return true;
}

static bool isFieldSet(ParticleField field) {
    size_t byteCount;
    size_t offsetInTransferStruct;
    switch (field) {
        case AddressField: 
            byteCount = sizeof(RadixAddress);
            offsetInTransferStruct = 0;
            break;
        case AmountField:
            byteCount = sizeof(TokenAmount);
            offsetInTransferStruct = sizeof(RadixAddress);
            break;
        case TokenDefinitionReferenceField:
            byteCount = sizeof(RadixResourceIdentifier);
            offsetInTransferStruct = sizeof(RadixAddress) + sizeof(TokenAmount);
            break;
        default: FATAL_ERROR("Unknown field: %d", field);
    }

    for (size_t i = 0; i < byteCount; ++i) {
        unsigned char byte = *(
            ctx->transfers[ctx->numberOfParticlesParsed].address.bytes + offsetInTransferStruct + i
        );
        if (byte > 0x00) {
            return true;
        }
    }
    return false;
}

static void readNextChunkFromHostMachineAndUpdateHash(
    size_t chunkSize
) {
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
	unsigned rx = io_exchange(CHANNEL_APDU, 2);
	PRINTF("readNextChunkFromHostMachine: io_exchanged %d bytes\n", rx);
    // N.B. we do not provide any meta data at all for chunked data,
    // not in the databuffer any way, we might use P1, P2 here...
	uint32_t dataOffset = OFFSET_CDATA + 0;

    os_memcpy(
        /* destination */ ctx->atomSlice + ctx->numberOfCachedBytes, 
        /* source */ G_io_apdu_buffer + dataOffset, 
        /* number of bytes*/ chunkSize
    );

    bool shouldFinalizeHash = chunkSize < MAX_CHUNK_SIZE;

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atomSlice + ctx->numberOfCachedBytes,
        (size_t)chunkSize,
        shouldFinalizeHash,
        ctx->hash
    );
}

static RadixParticleTypes particleTypeFromUTF8String(
    const char *utf8_string,
    const size_t string_length
) {

    if (strncmp(utf8_string, "radix.particles.message", string_length) == 0) {
        return MessageParticleType;
    } else if (strncmp(utf8_string, "radix.particles.rri", string_length) == 0) {
        return RRIParticleType;
    } else if (strncmp(utf8_string, "radix.particles.fixed_supply_token_definition", string_length) == 0) {
        return FixedSupplyTokenDefinitionParticleType;
    } else if (strncmp(utf8_string, "radix.particles.mutable_supply_token_definition", string_length) == 0) {
        return MutableSupplyTokenDefinitionParticleType;
    } else if (strncmp(utf8_string, "radix.particles.unallocated_tokens", string_length) == 0) {
        return UnallocatedTokensParticleType;
    } else if (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0) {
        return TransferrableTokensParticleType;
    } else if (strncmp(utf8_string, "radix.particles.unique", string_length) == 0) {
        return UniqueParticleType;
    } else {
        return ParticleType_is_unknown;
    }
}

// static ParticleField nextField(
//     const size_t numberOfBytesInAtomSliceParse,
//     const size_t sizeOfAtomSlice,
//     ByteInterval *output_next_byte_interval
// ) {
//     ParticleMetaData *particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    
// }

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum {
    // ByteStringCBORPrefixByte_bytes      = 1,
    // ByteStringCBORPrefixByte_euid       = 2,
    // ByteStringCBORPrefixByte_hash       = 3,
    ByteStringCBORPrefixByte_address    = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256    = 5,

    // Used for `tokenDefinitionReference`
    ByteStringCBORPrefixByte_rri        = 6
    // ByteStringCBORPrefixByte_aid        = 8
} CBORBytePrefixForByteArray;

static bool isParticleBeingParsedTransferrableTokensParticle() {
    return isMetaDataForTransferrableTokensParticle(&(ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed]));
}

static int numberOfIdentifiedParticleTypes() {
    for (int i = ctx->numberOfParticlesWithSpinUp - 1; i >= 0; --i) {
        if (ctx->identifiedParticleTypesInAtom[i] != NoParticleTypeParsedYet) {
            return i + 1;
        }
    }
    return 0;
}

static ParticleField getNextFieldToParse() {
    if (!isParticleBeingParsedTransferrableTokensParticle()) {
        return SerializerField;
    }
    assert(isParticleBeingParsedTransferrableTokensParticle());

    if (!isFieldSet(AddressField)) {
        return AddressField;
    }
    assert(isFieldSet(AddressField));

    if (!isFieldSet(AmountField)) {
        return AmountField;
    }
    assert(isFieldSet(AmountField));

    bool haveVerifiedSerializerOfTransferrableTokensParticle = numberOfIdentifiedParticleTypes() == (ctx->numberOfParticlesParsed + 1);
    if (!haveVerifiedSerializerOfTransferrableTokensParticle) {
        return SerializerField;
    }

    if (isFieldSet(TokenDefinitionReferenceField))
    {
        FATAL_ERROR("You have forgot to update the number of parsed particles?");
    }
    assert(!isFieldSet(TokenDefinitionReferenceField));
    return TokenDefinitionReferenceField;
}


static ByteInterval getNextByteInterval() {
    ParticleMetaData particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    switch (getNextFieldToParse()) {
        case AddressField:
            PRINTF("Next field is 'Address', with byteInterval: @%u, #%u bytes\n", particleMetaData.addressOfRecipientByteInterval.startsAt, particleMetaData.addressOfRecipientByteInterval.byteCount);
            return particleMetaData.addressOfRecipientByteInterval;
        case AmountField: 
            PRINTF("Next field is 'Amount', with byteInterval: @%u, #%u bytes\n", particleMetaData.amountByteInterval.startsAt, particleMetaData.amountByteInterval.byteCount);
            return particleMetaData.amountByteInterval;
        case SerializerField: 
             PRINTF("Next field is 'Serializer', with byteInterval: @%u, #%u bytes\n", particleMetaData.serializerValueByteInterval.startsAt, particleMetaData.serializerValueByteInterval.byteCount);
            return particleMetaData.serializerValueByteInterval;
        case TokenDefinitionReferenceField: 
            PRINTF("Next field is 'TokenDefRef', with byteInterval: @%u, #%u bytes\n", particleMetaData.tokenDefinitionReferenceByteInterval.startsAt, particleMetaData.tokenDefinitionReferenceByteInterval.byteCount);
            return particleMetaData.tokenDefinitionReferenceByteInterval;
        default:
            FATAL_ERROR("Unknown identifier of field: %d", getNextFieldToParse());
        }
}



static void emptyAtomSlice() {
    os_memset(ctx->atomSlice, 0, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE);
}

static void parseAddress(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(RadixAddress)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);


    if (cborError)
    {
        FATAL_ERROR("Error parsing 'address' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_address);
    assert(!isFieldSet(AddressField));
    assert(!isFieldSet(AmountField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].address.bytes,
        // Drop first byte, since it only specifies the `address` type.
        byteString + 1,
        sizeof(RadixAddress)
    );

    // Sanity check
    assert(isFieldSet(AddressField));
}

static void parseAmount(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(TokenAmount)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);


    if (cborError)
    {
        FATAL_ERROR("Error parsing 'amount' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_uint256);
    assert(isFieldSet(AddressField));
    assert(!isFieldSet(AmountField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].amount.bytes,
        // Drop first byte, since it only specifies the `amount` type.
        byteString + 1,
        sizeof(TokenAmount));

    // Sanity check
    assert(isFieldSet(AmountField));
}

static RadixParticleTypes parseSerializer(
    const size_t fieldByteCount,
    CborValue *cborValue
) 
{
    size_t numberOfBytesReadByCBORParser;
    char textString[fieldByteCount];
    CborError cborError = cbor_value_copy_text_string(
        cborValue,
        textString,
        &numberOfBytesReadByCBORParser,
        NULL);

    assert(numberOfBytesReadByCBORParser == fieldByteCount);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
    }

    RadixParticleTypes particleType = particleTypeFromUTF8String(textString, fieldByteCount);

    // if `Address` or `Amount` is parsed, means that we expect this particle to be a TransferrableTokensParticle (since "serializer" comes before "tokenDefinitionReference" alphabetically and thus also in CBOR it is not set yet)
    if (isFieldSet(AddressField) || isFieldSet(AmountField))
    {
        if (particleType != TransferrableTokensParticleType)
        {
            FATAL_ERROR("Incorrect particle type, expected `TransferrableTokensParticle`, but got other.");
        }
    } else if (particleType == TransferrableTokensParticleType && !(isFieldSet(AddressField) && isFieldSet(AmountField))) {
        FATAL_ERROR("Got `TransferrableTokensParticle`, but amount and address fields are NULL.");
    }

    return particleType;
}

static void parseTokenDefinitionReference(
    const size_t fieldByteCount,
    CborValue *cborValue
)
{
    // +1 byte for CBOR byte string Radix additional encoding prefix
    assert(fieldByteCount == (1 + sizeof(RadixResourceIdentifier)));

    size_t numberOfBytesReadByCBORParser;
    uint8_t byteString[fieldByteCount];
    CborError cborError = cbor_value_copy_byte_string(
        cborValue,
        byteString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'tokenDefinitionReference' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    // Sanity check
    assert(numberOfBytesReadByCBORParser == fieldByteCount);
    assert(byteString[0] == ByteStringCBORPrefixByte_rri);
    assert(isFieldSet(AddressField));
    assert(isFieldSet(AmountField));
    assert(!isFieldSet(TokenDefinitionReferenceField));

    os_memcpy(
        ctx->transfers[ctx->numberOfParticlesParsed].tokenDefinitionReference.bytes,
        // Drop first byte, since it only specifies the `RRI` type.
        byteString + 1,
        sizeof(RadixResourceIdentifier));

    assert(isFieldSet(TokenDefinitionReferenceField));
}

static void print_cbor_type_string(CborType type) {
    switch (type)
    {
    case CborByteStringType:
        PRINTF("Cbor type is: ByteString\n");
        break;
    case CborTextStringType:
        PRINTF("Cbor type is: TextString\n");
        break;
    default:
        PRINTF("Found uninteresting Cbor type value: %d\n", type);
        break;
    }
}

static void parseParticleFieldFromAtomSlice(
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount
) {
    CborParser cborParser;
    CborValue cborValue;
    PRINTF("About to read CBOR value at position in atomSlice: %d, of length: %d\n", fieldPositionInAtomSlice, fieldByteCount);
    CborError cborError = cbor_parser_init(
        ctx->atomSlice + fieldPositionInAtomSlice,
        fieldByteCount,
        0, // flags
        &cborParser,
        &cborValue);

    if (cborError) {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError)); 
    }

    CborType type = cbor_value_get_type(&cborValue);
    print_cbor_type_string(type);
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);
    if (cborError) {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError)); 
    }
    PRINTF("fieldByteCount: %u, readLength: %u\n", fieldByteCount, readLength);
    assert(readLength == fieldByteCount);

    switch (getNextFieldToParse()) {
        case AddressField:
            assert(type == CborByteStringType);
            parseAddress(fieldByteCount, &cborValue);
            PRINTF("Parsed address\n");
            // ctx->nextFieldInParticleToParse = AmountField;
            break;
        case AmountField: 
            assert(type == CborByteStringType);
            parseAmount(fieldByteCount, &cborValue);
            PRINTF("Parsed amount\n");
            // ctx->nextFieldInParticleToParse = SerializerField;
            break;
        case SerializerField: 
            assert(type == CborTextStringType);
            RadixParticleTypes particleType = parseSerializer(fieldByteCount, &cborValue);
            ctx->identifiedParticleTypesInAtom[ctx->numberOfParticlesParsed] = particleType;
            PRINTF("Parsed serializer\n");

            if (particleType != TransferrableTokensParticleType) {
                ctx->numberOfParticlesParsed++;

                // if (isParticleBeingParsedTransferrableTokensParticle()) {
                //     ctx->nextFieldInParticleToParse = AddressField;
                // } else {
                //     ctx->nextFieldInParticleToParse = TokenDefinitionReferenceField;
                // }
            } 
            // else {
            //     ctx->nextFieldInParticleToParse = TokenDefinitionReferenceField;
            // }

            break;
        case TokenDefinitionReferenceField: 
            assert(type == CborByteStringType);
            parseTokenDefinitionReference(fieldByteCount, &cborValue);
            PRINTF("Parsed TokenDefRef\n");
            ctx->numberOfParticlesParsed++;
    
            // if (isParticleBeingParsedTransferrableTokensParticle()) {
            //     ctx->nextFieldInParticleToParse = AddressField;
            // } else {
            //     ctx->nextFieldInParticleToParse = TokenDefinitionReferenceField;
            // }

            break;
    }
}

static void cacheBytesIfNeeded(
    const size_t atomSliceByteCount,
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount
) {
    size_t numberOfBytesToCache = atomSliceByteCount - fieldPositionInAtomSlice;

    assert(numberOfBytesToCache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);

    uint8_t tmp[numberOfBytesToCache]; // uint8_t tmp[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];

    os_memcpy(
        tmp,
        ctx->atomSlice + fieldPositionInAtomSlice,
        numberOfBytesToCache);

    emptyAtomSlice();

    os_memcpy(
        ctx->atomSlice,
        tmp,
        numberOfBytesToCache);

    PRINTF("Caching #%u bytes\n", numberOfBytesToCache);
    ctx->numberOfCachedBytes = numberOfBytesToCache;
    ctx->atomByteCountParsed -= numberOfBytesToCache;
}

static void printAtomSliceContents() {
    PRINTF("AtomSlice contents:\n\n%.*H\n\n\n", MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE, ctx->atomSlice);
}

// Returns a boolean value indicating whether or all particles have been parsed
static bool parseParticlesAndUpdateHash() {
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
	uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);
    printAtomSliceContents();
    readNextChunkFromHostMachineAndUpdateHash((size_t)chunkSize);
    printAtomSliceContents();
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;
    size_t atomSliceByteCount = chunkSize + numberOfCachedBytes;
    PRINTF("Read chunk of bytes from host machine, atom slice contains bytes:\n%.*H\n\n", atomSliceByteCount, ctx->atomSlice);
    size_t atomByteCountParsedBeforeThisChunk = ctx->atomByteCountParsed;
    ctx->atomByteCountParsed = atomByteCountParsedBeforeThisChunk + chunkSize;

    bool doneParsingThisAtomSlice = false;

    // parse particles and their values from current atom slice
    while (!doneParsingThisAtomSlice) {
        // for good measure...
        if (ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp) {
            return true;
        }

        PRINTF("Getting next byte interval\n");
        ByteInterval fieldByteInterval = getNextByteInterval();
        PRINTF("Got next byte interval\n");

        uint16_t fieldPositionInAtom = fieldByteInterval.startsAt;
        
        // Atom slice does not contain any relevant bytes, proceed to next, without caching
        if (fieldPositionInAtom > ctx->atomByteCountParsed) {
            PRINTF("Skipping chunk (besides having feeded it to our hasher) since next byte interval starts @%u in Atom, but current slice of atom is between bytes %u-%u\n", fieldPositionInAtom, atomByteCountParsedBeforeThisChunk, ctx->atomByteCountParsed);
            doneParsingThisAtomSlice = true;
            break;
        }
        
        uint16_t fieldByteCount = fieldByteInterval.byteCount;

        uint16_t fieldPositionInAtomSlice = fieldPositionInAtom - atomByteCountParsedBeforeThisChunk; // no need to offset with `numberOfCachedBytes` since we subtract `ctx->atomByteCountParsed -= numberOfBytesToCache;` when caching...

        if (numberOfCachedBytes > 0) {
            assert(fieldPositionInAtomSlice == 0);
        }

        PRINTF("\nnext field starts at: %u (in atom), translating that position from Atom relative to relative within the current atom slice of size: %u results in new position: %u, and is #%u bytes long\n\n", fieldPositionInAtom, atomSliceByteCount, fieldPositionInAtomSlice, fieldByteCount);

        doneParsingThisAtomSlice = fieldPositionInAtomSlice + fieldByteCount >= atomSliceByteCount;
        if (doneParsingThisAtomSlice) {

            // for good measure...
            if (ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp) {
                return true;
            }

            PRINTF("doneParsingThisAtomSlice, fieldPositionInAtomSlice: %u, fieldByteCount: %u (combined, are GEQ:), atomSliceByteCount: %u\n\n", fieldPositionInAtomSlice, fieldByteCount, atomSliceByteCount);
            // Check if needs to cache
            bool fieldSpillOverToNextChunk = fieldPositionInAtomSlice + fieldByteCount > atomSliceByteCount;

            if (fieldSpillOverToNextChunk) {
                PRINTF("fieldSpillOverToNextChunk, caching bytes\n");
                cacheBytesIfNeeded(atomSliceByteCount, fieldPositionInAtomSlice, fieldByteCount);
            }
            return false;
        } else {
            // Can parse a field from current atom slice
            parseParticleFieldFromAtomSlice(fieldPositionInAtomSlice, fieldByteCount);
        }
    }
    
    emptyAtomSlice();

    return ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp;
}

static void parseAtom() {

    while(!parseParticlesAndUpdateHash()) {
        PRINTF("Finished parsing %u/%u particles\n", ctx->numberOfParticlesParsed, ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom\n", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
    assert(ctx->atomByteCountParsed == ctx->atomByteCount)
}

// p1 = #particlesWithSpinUp
// p2 = NOT USED
// dataBuffer:
//          12 bytes: BIP32 PATH
//          2 bytes:  Atom Byte Count (CBOR encoded)
//          4-240 bytes: `P1` many offsets to particles à 4 bytes.
void handleSignAtom(
    uint8_t p1, 
    uint8_t p2, 
    uint8_t *dataBuffer, 
    uint16_t dataLength, 
    volatile unsigned int *flags, 
    volatile unsigned int *tx
) {
    // INPUT VALIDATION
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;
    
    if (dataLength < expected_bip32_byte_count) {
        PRINTF("'dataLength' should be at least: %u, but was: %d\n", expected_bip32_byte_count, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->numberOfParticlesWithSpinUp = p1;
    if (ctx->numberOfParticlesWithSpinUp > MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP || ctx->numberOfParticlesWithSpinUp < 1) {
        PRINTF("Number of particles with spin up must be at least 1 and cannot exceed: %d, but got: %d\n", MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP, ctx->numberOfParticlesWithSpinUp);
        THROW(SW_INVALID_PARAM);
    }
 
    // PARSE DATA
    int dataOffset = 0;

    // READ BIP32 path from first chunk, available directly
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString)); dataOffset += expected_bip32_byte_count;
    PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

    // READ Atom Byte Count (CBOR encoded data)
    ctx->atomByteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    PRINTF("Atom byte count: %d bytes\n", ctx->atomByteCount);
    ctx->atomByteCountParsed = 0;

    // READ meta data about particles from first chunk, available directly
    PRINTF("Recived meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string\n%.*H\n", (16)*ctx->numberOfParticlesWithSpinUp, dataBuffer, dataOffset);
    ctx->numberOfParticlesParsed = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex) {
        // In this (alphabetical) order: [address, amount, serializer, tokenDefRef]
        // read the values.
        PRINTF("Decoding meta data about particle at index: %u\n", particleIndex);
        PRINTF("Decoding meta data about particle, with hex: %.*H\n", 16, (dataBuffer+dataOffset));

        uint16_t addressOfRecipientByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("Address startAt: %u\n", addressOfRecipientByteIntervalStart);
        uint16_t addressOfRecipientByteIntervalCount = U2BE(dataBuffer, dataOffset);
        PRINTF("Address byteCount: %u\n", addressOfRecipientByteIntervalCount);
        dataOffset += 2;

        ByteInterval addressOfRecipientByteInterval = { 
            .startsAt = addressOfRecipientByteIntervalStart,
            .byteCount = addressOfRecipientByteIntervalCount
        };

        uint16_t amountByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("Amount startAt: %u\n", amountByteIntervalStart);
		uint16_t amountByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("Amount byteCount: %u\n", amountByteIntervalCount);

        ByteInterval amountByteInterval = { 
            .startsAt = amountByteIntervalStart,
            .byteCount = amountByteIntervalCount
        };

        uint16_t serializerByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("Serializer startAt: %u\n", serializerByteIntervalStart);
		uint16_t serializerByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        // assert(serializerByteIntervalCount > 0);
        PRINTF("Serializer byteCount: %u\n", serializerByteIntervalCount);

        ByteInterval serializerValueByteInterval = { 
            .startsAt = serializerByteIntervalStart,
            .byteCount = serializerByteIntervalCount
        };

        uint16_t tokenDefinitionReferenceByteIntervalStart = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("RRI startAt: %u\n", tokenDefinitionReferenceByteIntervalStart);
		uint16_t tokenDefinitionReferenceByteIntervalCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;
        PRINTF("RRI byteCount: %u\n", tokenDefinitionReferenceByteIntervalCount);

        ByteInterval tokenDefinitionReferenceByteInterval = { 
            .startsAt = tokenDefinitionReferenceByteIntervalStart,
            .byteCount = tokenDefinitionReferenceByteIntervalCount
        };

        ParticleMetaData metaDataAboutParticle = {
	        .addressOfRecipientByteInterval = addressOfRecipientByteInterval,
	        .amountByteInterval = amountByteInterval,
            .serializerValueByteInterval = serializerValueByteInterval,
	        .tokenDefinitionReferenceByteInterval = tokenDefinitionReferenceByteInterval 
        };

        if (isMetaDataForTransferrableTokensParticle(&metaDataAboutParticle)) {
            // if (particleIndex == 0) {
            //     ctx->nextFieldInParticleToParse = AddressField;
            // }
            PRINTF("Got meta data about TransferrableTokensParticle\n");
        } else {
            // if (particleIndex == 0) {
            //     ctx->nextFieldInParticleToParse = SerializerField;
            // }
            PRINTF("Got meta data about NON-TransferrableTokensParticle\n");
        }

        ctx->metaDataAboutParticles[particleIndex] = metaDataAboutParticle;
    }

    // INITIATE SHA Hasher
    cx_sha256_init(&(ctx->hasher));

    // Start cached bytes buffer at 0 bytes, cached bytes are used
    // when data spans across two chunks.
    ctx->numberOfCachedBytes = 0;

    os_memset(ctx->transfers, 0, MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP * sizeof(Transfer));

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    parseAtom();
}