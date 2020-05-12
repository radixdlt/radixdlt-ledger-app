#include <stdlib.h>
#include <stddef.h>
#include <stdio.h>
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

static bool isZeroByteInterval(ByteInterval *byteInterval)
{
    if (byteInterval->byteCount > 0)
    {
        return false;
    }
    assert(byteInterval->startsAt == 0);
    return true;
}

static bool isMetaDataForTransferrableTokensParticle(ParticleMetaData *particleMetaData)
{
    if (isZeroByteInterval(&particleMetaData->addressOfRecipientByteInterval))
    {
        assert(isZeroByteInterval(&particleMetaData->amountByteInterval));
        assert(isZeroByteInterval(&particleMetaData->tokenDefinitionReferenceByteInterval));
        return false;
    }
    return true;
}

// static const uint8_t* pointerToFirstByteOfCurrentTransferStruct() {
//     return ctx->transfers[ctx->numberOfParticlesParsed].address.bytes;
// }

static ByteInterval intervalOfTransferStructField(ParticleField field)
{
    switch (field)
    {
    case AddressField:
    {
        return (ByteInterval){
            .startsAt = offsetof(Transfer, address),
            .byteCount = sizeof(RadixAddress)};
    }
    case AmountField:
    {
        return (ByteInterval){
            .startsAt = offsetof(Transfer, amount),
            .byteCount = sizeof(TokenAmount)};
    }
    case TokenDefinitionReferenceField:
    {
        return (ByteInterval){
            .startsAt = offsetof(Transfer, tokenDefinitionReference),
            .byteCount = sizeof(RadixResourceIdentifier)};
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }
}

// static bool isFieldSet(ParticleField field)
// {
//     ByteInterval intervalOfParticleField = intervalOfTransferStructField(field);
//     size_t offsetOfField = (size_t)intervalOfParticleField.startsAt;
//     for (size_t i = 0; i < intervalOfParticleField.byteCount; ++i)
//     {
//         uint8_t byte = *(
//             pointerToFirstByteOfCurrentTransferStruct() + offsetOfField + i);

//         if (byte > 0x00)
//         {
//             return true;
//         }
//     }

//     return false;
// }

static void readNextChunkFromHostMachineAndUpdateHash(
    size_t chunkSize)
{
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
        /* number of bytes*/ chunkSize);

    bool shouldFinalizeHash = chunkSize < MAX_CHUNK_SIZE;

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atomSlice + ctx->numberOfCachedBytes,
        (size_t)chunkSize,
        shouldFinalizeHash,
        ctx->hash);
}

static RadixParticleTypes particleTypeFromUTF8String(
    const char *utf8_string,
    const size_t string_length)
{

    if (strncmp(utf8_string, "radix.particles.message", string_length) == 0)
    {
        return MessageParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.rri", string_length) == 0)
    {
        return RRIParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.fixed_supply_token_definition", string_length) == 0)
    {
        return FixedSupplyTokenDefinitionParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.mutable_supply_token_definition", string_length) == 0)
    {
        return MutableSupplyTokenDefinitionParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.unallocated_tokens", string_length) == 0)
    {
        return UnallocatedTokensParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0)
    {
        return TransferrableTokensParticleType;
    }
    else if (strncmp(utf8_string, "radix.particles.unique", string_length) == 0)
    {
        return UniqueParticleType;
    }
    else
    {
        return ParticleType_is_unknown;
    }
}

// Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
typedef enum
{
    ByteStringCBORPrefixByte_address = 4,

    // Used for `amount`
    ByteStringCBORPrefixByte_uint256 = 5,

    // Used for `tokenDefinitionReference`
    ByteStringCBORPrefixByte_rri = 6
} CBORBytePrefixForByteArray;

static bool isParticleBeingParsedTransferrableTokensParticle()
{
    return isMetaDataForTransferrableTokensParticle(&(ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed]));
}

static int numberOfIdentifiedParticleTypes()
{
    for (int i = ctx->numberOfParticlesWithSpinUp - 1; i >= 0; --i)
    {
        if (ctx->identifiedParticleTypesInAtom[i] != NoParticleTypeParsedYet)
        {
            return i + 1;
        }
    }
    return 0;
}

static ParticleField getNextFieldToParse() {

    if (!isParticleBeingParsedTransferrableTokensParticle())
    {
        return SerializerField;
    }

    if ((*ctx).parsedAddressInTransfer == NULL) {
        return AddressField;
    }

     if ((*ctx).parsedAmountInTransfer == NULL) {
        return AmountField;
    }

    bool haveVerifiedSerializerOfTransferrableTokensParticle = numberOfIdentifiedParticleTypes() == (ctx->numberOfParticlesParsed + 1);
    if (!haveVerifiedSerializerOfTransferrableTokensParticle)
    {
        PRINTF("Have NOT verified serializer of transfP, so next field is 'serializer'\n");
        return SerializerField;
    }

    return TokenDefinitionReferenceField;
}

static void finishedParsingAWholeTransfer(RadixResourceIdentifier *tokenDefinitionReferenceJustParsed) {

    assert((*ctx).parsedAddressInTransfer)
    assert((*ctx).parsedAmountInTransfer)
    assert(numberOfIdentifiedParticleTypes() == (ctx->numberOfParticlesParsed + 1));
    assert(tokenDefinitionReferenceJustParsed)
    
    uint8_t *transferByteStart = ctx->transfers[ctx->numberOfParticlesParsed].address.bytes;
    // Transfer *transfer = &(ctx->transfers[ctx->numberOfParticlesParsed]);

    ByteInterval fieldByteInterval = intervalOfTransferStructField(AddressField);
   

    // Copy `ctx->parsedAddressInTransfer` -> `ctx->transfers[ctx->numberOfParticlesParsed]`
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        ctx->parsedAddressInTransfer->bytes,
        fieldByteInterval.byteCount
    );
    ctx->parsedAddressInTransfer = NULL;

    fieldByteInterval = intervalOfTransferStructField(AmountField);
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        ctx->parsedAmountInTransfer->bytes,
        fieldByteInterval.byteCount
    );
    ctx->parsedAmountInTransfer = NULL;

    fieldByteInterval = intervalOfTransferStructField(TokenDefinitionReferenceField);
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        tokenDefinitionReferenceJustParsed->bytes,
        fieldByteInterval.byteCount
    );

    ctx->numberOfParticlesParsed++;
}

// static ParticleField getNextFieldToParse()
// {
//     if (!isParticleBeingParsedTransferrableTokensParticle())
//     {
//         return SerializerField;
//     }
//     assert(isParticleBeingParsedTransferrableTokensParticle());

//     if (!isFieldSet(AddressField))
//     {
//         return AddressField;
//     }
//     assert(isFieldSet(AddressField));

//     if (!isFieldSet(AmountField))
//     {
//         return AmountField;
//     }
//     assert(isFieldSet(AmountField));

//     bool haveVerifiedSerializerOfTransferrableTokensParticle = numberOfIdentifiedParticleTypes() == (ctx->numberOfParticlesParsed + 1);
//     if (!haveVerifiedSerializerOfTransferrableTokensParticle)
//     {
//         PRINTF("Have NOT verified serializer of transfP, so next field is 'serializer'\n");
//         return SerializerField;
//     }

//     if (isFieldSet(TokenDefinitionReferenceField))
//     {
//         FATAL_ERROR("You have forgot to update the number of parsed particles?");
//     }
//     assert(!isFieldSet(TokenDefinitionReferenceField));
//     return TokenDefinitionReferenceField;
// }

static ByteInterval getNextByteInterval()
{
    ParticleMetaData particleMetaData = ctx->metaDataAboutParticles[ctx->numberOfParticlesParsed];
    switch (getNextFieldToParse())
    {
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

static void emptyAtomSlice()
{
    os_memset(ctx->atomSlice, 0, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE);
}

static CBORBytePrefixForByteArray cborBytePrefixForParticleField(ParticleField field)
{
    switch (field)
    {
    case AddressField:
    {
        return ByteStringCBORPrefixByte_address;
    }
    case AmountField:
    {
        return ByteStringCBORPrefixByte_uint256;
    }
    case TokenDefinitionReferenceField:
    {
        return ByteStringCBORPrefixByte_rri;
    }
    default:
        FATAL_ERROR("Unknown field: %d", field);
    }
}

// TODO improvement, remove `valueByteCount`, since it SHOULD
// always be `sizeof(ResultingStruct)+1`
static void parseParticleField(
    const size_t valueByteCount,
    CborValue *cborValue,
    ParticleField field,

    uint8_t *output_buffer
) {

    CBORBytePrefixForByteArray cborBytePrefix = cborBytePrefixForParticleField(field);
    ByteInterval intervalOfParticleField = intervalOfTransferStructField(field);
    size_t sizeOfResultingStruct = intervalOfParticleField.byteCount;
    PRINTF("sizeOfResultingStruct: %u, valueByteCount: %u, intervalOfParticleField.startsAt: %u\n", sizeOfResultingStruct, valueByteCount, intervalOfParticleField.startsAt);

    // +1 byte for CBOR byte string Radix additional encoding prefix
    // assert(valueByteCount == (1 + sizeOfResultingStruct));

    size_t numberOfBytesReadByCBORParser;
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
    // assert(numberOfBytesReadByCBORParser == valueByteCount);
    assert(byteString[0] == cborBytePrefix);
    // assert(isFieldSet(AddressField));
    // assert(isFieldSet(AmountField));
    // assert(!isFieldSet(TokenDefinitionReferenceField));

    os_memcpy(
        // (pointerToFirstByteOfCurrentTransferStruct() + intervalOfParticleField.startsAt),
        output_buffer,

        byteString + 1, // Drop first CBOR prefix byte
        sizeOfResultingStruct);

    // assert(isFieldSet(TokenDefinitionReferenceField));
}

static RadixParticleTypes parseSerializer(
    const size_t valueByteCount,
    CborValue *cborValue)
{
    size_t numberOfBytesReadByCBORParser;
    char textString[80]; // byte=>2hex char, +1 for NULL
    CborError cborError = cbor_value_copy_text_string(
        cborValue,
        textString,
        &numberOfBytesReadByCBORParser,
        NULL);

    if (cborError)
    {
        FATAL_ERROR("Error parsing 'serializer' field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError)); // will terminate app
    }

    PRINTF("numberOfBytesReadByCBORParser: %u, valueByteCount: %u\n", numberOfBytesReadByCBORParser, valueByteCount);
    assert(numberOfBytesReadByCBORParser == valueByteCount);
    PRINTF("Successfully CBOR decoded textstring: %.*s\n", numberOfBytesReadByCBORParser, textString);
    RadixParticleTypes particleType = particleTypeFromUTF8String(textString, valueByteCount);

    // if `Address` or `Amount` is parsed, means that we expect this particle to be a TransferrableTokensParticle (since "serializer" comes before "tokenDefinitionReference" alphabetically and thus also in CBOR it is not set yet)
    if (
        ((*ctx).parsedAddressInTransfer) || ((*ctx).parsedAmountInTransfer)
    )
    {
        if (particleType != TransferrableTokensParticleType)
        {
            FATAL_ERROR("Incorrect particle type, expected `TransferrableTokensParticle`, but got other.");
        }
    }
    else if (
        particleType == TransferrableTokensParticleType
        && 
        (((*ctx).parsedAddressInTransfer == NULL) || ((*ctx).parsedAmountInTransfer == NULL))
    )
    {
        FATAL_ERROR("Got `TransferrableTokensParticle`, but amount and address fields are NULL.");
    }

    return particleType;
}

static void print_cbor_type_string(CborType type)
{
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
    const size_t fieldByteCount)
{
    CborParser cborParser;
    CborValue cborValue;
    PRINTF("About to read CBOR value at position in atomSlice: %d, of length: %d\n", fieldPositionInAtomSlice, fieldByteCount);
    CborError cborError = cbor_parser_init(
        ctx->atomSlice + fieldPositionInAtomSlice,
        fieldByteCount,
        0, // flags
        &cborParser,
        &cborValue);

    if (cborError)
    {
        FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    CborType type = cbor_value_get_type(&cborValue);
    print_cbor_type_string(type);
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);
    if (cborError)
    {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }
    PRINTF("fieldByteCount: %u, readLength: %u\n", fieldByteCount, readLength);

    switch (getNextFieldToParse())
    {
    case AddressField:
        assert(type == CborByteStringType);

        assert((*ctx).parsedAddressInTransfer == NULL);
        RadixAddress address;

        parseParticleField(
            readLength, 
            &cborValue, 
            AddressField, 
            address.bytes
        );

        ctx->parsedAddressInTransfer = &address;
        assert((*ctx).parsedAddressInTransfer);

        PRINTF("Successfully parsed address: %.*H\n", sizeof(RadixAddress), ctx->parsedAddressInTransfer->bytes);

        break;
    case AmountField:
        assert(type == CborByteStringType);
        // assert(isFieldSet(AddressField));
        // assert(!isFieldSet(AmountField));

        assert((*ctx).parsedAmountInTransfer == NULL);
        TokenAmount amount;
        ctx->parsedAmountInTransfer = &amount;

        parseParticleField(
            readLength, 
            &cborValue, 
            AmountField, 
            amount.bytes
        );
        
        assert((*ctx).parsedAmountInTransfer);

        PRINTF("Successfully parsed amount: %.*H\n", sizeof(TokenAmount), ctx->parsedAmountInTransfer->bytes);
        break;
    case SerializerField:
        assert(type == CborTextStringType);
        RadixParticleTypes particleType = parseSerializer(readLength, &cborValue);
        ctx->identifiedParticleTypesInAtom[ctx->numberOfParticlesParsed] = particleType;

        if (particleType != TransferrableTokensParticleType)
        {
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
        // assert(isFieldSet(AddressField));
        // assert(isFieldSet(AmountField));
        // assert(!isFieldSet(TokenDefinitionReferenceField));

        RadixResourceIdentifier rri;
        parseParticleField(readLength, &cborValue, TokenDefinitionReferenceField, rri.bytes);
        finishedParsingAWholeTransfer(&rri);

        // assert(isFieldSet(TokenDefinitionReferenceField));
    


        // if (isParticleBeingParsedTransferrableTokensParticle()) {
        //     ctx->nextFieldInParticleToParse = AddressField;
        // } else {
        //     ctx->nextFieldInParticleToParse = TokenDefinitionReferenceField;
        // }

        break;
    }
}

static void cacheBytesToNextChunk(
    // const size_t atomSliceByteCount,
    // const size_t fieldPositionInAtomSlice,
    // const size_t fieldByteCount)
    const size_t fieldPositionInSlice,
    const size_t numberOfBytesToCache
) {
    // size_t numberOfBytesToCache = atomSliceByteCount - fieldPositionInAtomSlice;

    assert(numberOfBytesToCache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);

    uint8_t tmp[numberOfBytesToCache]; // uint8_t tmp[MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS];

    os_memcpy(
        tmp,
        ctx->atomSlice + fieldPositionInSlice,
        numberOfBytesToCache);

    emptyAtomSlice();

    os_memcpy(
        ctx->atomSlice,
        tmp,
        numberOfBytesToCache);

    PRINTF("Caching #%u bytes\n", numberOfBytesToCache);
    ctx->numberOfCachedBytes = numberOfBytesToCache;
    // ctx->atomByteCountParsed -= numberOfBytesToCache;
}

static void printAtomSliceContents()
{
    PRINTF("AtomSlice contents:\n\n%.*H\n\n\n", MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE, ctx->atomSlice);
}

// Returns true if `doneWithCurrentSlice`, i.e. all fields that can be parsed in current atom slice has been parsed
static bool tryParseParticleFieldFromAtomSlice(
    const size_t chunkStartPositionInAtom, // chunk, not slice, i.e. possibly cached bytes from last chunk not used to offset byte start position
    const size_t chunkByteCount, // chunk, not slice, i.e. possibly cached bytes from last chunk not included
    const size_t cachedBytesCount
) {
    size_t chunkEndPositionInAtom = chunkStartPositionInAtom + chunkByteCount;
    ByteInterval fieldByteInterval = getNextByteInterval();
    size_t fieldStartPositionInAtom = fieldByteInterval.startsAt;
    size_t fieldByteCount = fieldByteInterval.byteCount;
    size_t fieldEndPositionInAtom = fieldStartPositionInAtom + fieldByteCount;

    size_t fieldPositionInSlice = cachedBytesCount + fieldStartPositionInAtom - chunkStartPositionInAtom;

    bool canParseNextField = fieldEndPositionInAtom <= chunkEndPositionInAtom;
    bool doneWithCurrentSlice = false;
    if (canParseNextField)
    {
        parseParticleFieldFromAtomSlice(fieldPositionInSlice, fieldByteCount);
    }
    else
    {
        doneWithCurrentSlice = true;
        bool needsToCacheBytes = !canParseNextField && (fieldStartPositionInAtom < chunkEndPositionInAtom);

        if (needsToCacheBytes)
        {
            size_t numberOfBytesToCache = chunkEndPositionInAtom - fieldStartPositionInAtom;
            cacheBytesToNextChunk(fieldPositionInSlice, numberOfBytesToCache);
        }
    }
    return doneWithCurrentSlice;
}

// Returns a boolean value indicating whether or all particles have been parsed
static bool parseParticlesAndUpdateHash()
{
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
    uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);
    printAtomSliceContents();
    readNextChunkFromHostMachineAndUpdateHash((size_t)chunkSize);
    printAtomSliceContents();
    
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;
    size_t chunkPositionInAtom = ctx->atomByteCountParsed;
    bool doneWithCurrentSlice = false;

    while (!doneWithCurrentSlice) {
        doneWithCurrentSlice = tryParseParticleFieldFromAtomSlice(
            chunkPositionInAtom, 
            chunkSize, 
            numberOfCachedBytes
        );
    }

    ctx->atomByteCountParsed += chunkSize;
    return ctx->numberOfParticlesParsed >= ctx->numberOfParticlesWithSpinUp;
}

static void parseAtom()
{

    while (!parseParticlesAndUpdateHash())
    {
        PRINTF("Finished parsing %u/%u particles\n", ctx->numberOfParticlesParsed, ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom\n", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
    assert(ctx->atomByteCountParsed == ctx->atomByteCount)
}

// static void testCborStuff()
// {
//     CborParser cborParser;
//     CborValue cborValue;

//     PRINTF("Debugging CBOR decoding of byte strings...\n");

//     // 58270402026D5E07CFDE5DF84B5EF884B629D28D15B0F6C66BE229680699767CD57C6182882A49DC34
//     // which is CBOR encoding of `0x04 | 02026D5E07CFDE5DF84B5EF884B629D28D15B0F6C66BE229680699767CD57C6182882A49DC34`
//     // where 0x04 is Radix CBOR additional info byte prefix for "address" and the rest
//     // is a Radix address
//     uint8_t hardCodedAddressCbor[] = {0x58, 0x27, 0x04, 0x02, 0x02, 0x6D, 0x5E, 0x07, 0xCF, 0xDE, 0x5D, 0xF8, 0x4B, 0x5E, 0xF8, 0x84, 0xB6, 0x29, 0xD2, 0x8D, 0x15, 0xB0, 0xF6, 0xC6, 0x6B, 0xE2, 0x29, 0x68, 0x06, 0x99, 0x76, 0x7C, 0xD5, 0x7C, 0x61, 0x82, 0x88, 0x2A, 0x49, 0xDC, 0x34};

//     size_t byteCountCborBuffer = 41;

//     CborError cborError = cbor_parser_init(
//         hardCodedAddressCbor,
//         47,
//         0, // flags
//         &cborParser,
//         &cborValue);

//     if (cborError)
//     {
//         FATAL_ERROR("Failed to init cbor parser, CBOR eror: '%s'\n", cbor_error_string(cborError));
//     }

//     CborType type = cbor_value_get_type(&cborValue);
//     print_cbor_type_string(type);
//     assert(type == CborByteStringType);
//     size_t readLength;
//     cborError = cbor_value_calculate_string_length(&cborValue, &readLength);
//     if (cborError)
//     {
//         FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError));
//     }
//     PRINTF("byteCountCborBuffer: %u, readLength: %u\n", byteCountCborBuffer, readLength);
//     uint8_t byteString[readLength];
//     size_t numberOfBytesReadByCBORParser;
//     cborError = cbor_value_copy_byte_string(
//         &cborValue,
//         byteString,
//         &numberOfBytesReadByCBORParser,
//         NULL);

//     if (cborError)
//     {
//         FATAL_ERROR("Error parsing field in atomSlice, CBOR eror: '%s'\n", cbor_error_string(cborError));
//     }

//     PRINTF("numberOfBytesReadByCBORParser: %u, \n", numberOfBytesReadByCBORParser);
//     assert(numberOfBytesReadByCBORParser == readLength);
//     PRINTF("Successfully parsed hard coded address: %.*H\n", numberOfBytesReadByCBORParser, byteString);
// }

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
    volatile unsigned int *tx)
{

    // testCborStuff();
    // return io_exchange_with_code(SW_OK, 0);

    // INPUT VALIDATION
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;

    if (dataLength < expected_bip32_byte_count)
    {
        PRINTF("'dataLength' should be at least: %u, but was: %d\n", expected_bip32_byte_count, dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->numberOfParticlesWithSpinUp = p1;
    if (ctx->numberOfParticlesWithSpinUp > MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP || ctx->numberOfParticlesWithSpinUp < 1)
    {
        PRINTF("Number of particles with spin up must be at least 1 and cannot exceed: %d, but got: %d\n", MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP, ctx->numberOfParticlesWithSpinUp);
        THROW(SW_INVALID_PARAM);
    }

    // PARSE DATA
    int dataOffset = 0;

    // READ BIP32 path from first chunk, available directly
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, ctx->bip32PathString, sizeof(ctx->bip32PathString));
    dataOffset += expected_bip32_byte_count;
    PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

    // READ Atom Byte Count (CBOR encoded data)
    ctx->atomByteCount = U2BE(dataBuffer, dataOffset);
    dataOffset += 2;
    PRINTF("Atom byte count: %d bytes\n", ctx->atomByteCount);
    ctx->atomByteCountParsed = 0;

    // READ meta data about particles from first chunk, available directly
    PRINTF("Recived meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string\n%.*H\n", (16) * ctx->numberOfParticlesWithSpinUp, dataBuffer, dataOffset);
    ctx->numberOfParticlesParsed = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex)
    {
        // In this (alphabetical) order: [address, amount, serializer, tokenDefRef]
        // read the values.
        PRINTF("Decoding meta data about particle at index: %u\n", particleIndex);
        PRINTF("Decoding meta data about particle, with hex: %.*H\n", 16, (dataBuffer + dataOffset));

        uint16_t addressOfRecipientByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("Address startAt: %u\n", addressOfRecipientByteIntervalStart);
        uint16_t addressOfRecipientByteIntervalCount = U2BE(dataBuffer, dataOffset);
        PRINTF("Address byteCount: %u\n", addressOfRecipientByteIntervalCount);
        dataOffset += 2;

        ByteInterval addressOfRecipientByteInterval = {
            .startsAt = addressOfRecipientByteIntervalStart,
            .byteCount = addressOfRecipientByteIntervalCount};

        uint16_t amountByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("Amount startAt: %u\n", amountByteIntervalStart);
        uint16_t amountByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("Amount byteCount: %u\n", amountByteIntervalCount);

        ByteInterval amountByteInterval = {
            .startsAt = amountByteIntervalStart,
            .byteCount = amountByteIntervalCount};

        uint16_t serializerByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("Serializer startAt: %u\n", serializerByteIntervalStart);
        uint16_t serializerByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        // assert(serializerByteIntervalCount > 0);
        PRINTF("Serializer byteCount: %u\n", serializerByteIntervalCount);

        ByteInterval serializerValueByteInterval = {
            .startsAt = serializerByteIntervalStart,
            .byteCount = serializerByteIntervalCount};

        uint16_t tokenDefinitionReferenceByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("RRI startAt: %u\n", tokenDefinitionReferenceByteIntervalStart);
        uint16_t tokenDefinitionReferenceByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        PRINTF("RRI byteCount: %u\n", tokenDefinitionReferenceByteIntervalCount);

        ByteInterval tokenDefinitionReferenceByteInterval = {
            .startsAt = tokenDefinitionReferenceByteIntervalStart,
            .byteCount = tokenDefinitionReferenceByteIntervalCount};

        ParticleMetaData metaDataAboutParticle = {
            .addressOfRecipientByteInterval = addressOfRecipientByteInterval,
            .amountByteInterval = amountByteInterval,
            .serializerValueByteInterval = serializerValueByteInterval,
            .tokenDefinitionReferenceByteInterval = tokenDefinitionReferenceByteInterval};

        if (isMetaDataForTransferrableTokensParticle(&metaDataAboutParticle))
        {
            // if (particleIndex == 0) {
            //     ctx->nextFieldInParticleToParse = AddressField;
            // }
            PRINTF("Got meta data about TransferrableTokensParticle\n");
        }
        else
        {
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

    for (int i = 0; i < ctx->numberOfParticlesWithSpinUp; ++i)
    {
        ctx->identifiedParticleTypesInAtom[i] = NoParticleTypeParsedYet;
    }

    os_memset(ctx->transfers, 0, MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP * sizeof(Transfer));

    (*ctx).parsedAddressInTransfer = NULL;
    (*ctx).parsedAmountInTransfer = NULL;

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.

    parseAtom();
}