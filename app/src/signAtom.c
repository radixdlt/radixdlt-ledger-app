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
#include "base_conversion.h"
#include "signAtomUI.h"

static signAtomContext_t *ctx = &global.signAtomContext;

static unsigned short ux_visible_element_index = 0;

static bool isZeroByteInterval(ByteInterval *byteInterval)
{
    if (byteInterval->byteCount > 0)
    {
        return false;
    }
    assert(byteInterval->startsAt == 0);
    return true;
}

static bool isAddressEmpty() {
    size_t sizeOfRadixAddress = sizeof(RadixAddress);
    for (size_t i = 0; i < sizeOfRadixAddress; ++i)
    {
        const uint8_t *pointerToAddressByte = (ctx->parsedAddressInTransfer).bytes + i;
        uint8_t byteAtMemPos = *pointerToAddressByte;

        if (byteAtMemPos > 0x00) {
            return false;
        }
    }
    return true;
}
static void zeroOutAddress() {
    os_memset(ctx->parsedAddressInTransfer.bytes, 0x00, sizeof(RadixAddress));
}

static bool isAmountEmpty() {
    size_t sizeOfTokenAmount = sizeof(TokenAmount);
    for (size_t i = 0; i < sizeOfTokenAmount; ++i) {
        const uint8_t *pointerToAmountByte = (ctx->parsedAmountInTransfer).bytes + i;
        uint8_t byteAtMemPos = *pointerToAmountByte;

        if (byteAtMemPos > 0x00) {
            return false;
        }
    }
    return true;
}
static void zeroOutAmount() {
    os_memset(ctx->parsedAmountInTransfer.bytes, 0x00, sizeof(TokenAmount));
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

static void readNextChunkFromHostMachineAndUpdateHash(
    size_t chunkSize)
{
    os_memset(G_io_apdu_buffer, 0x00, IO_APDU_BUFFER_SIZE);
    G_io_apdu_buffer[0] = 0x90;
    G_io_apdu_buffer[1] = 0x00;
    /* unsigned rx = */ io_exchange(CHANNEL_APDU, 2);

    // N.B. we do not provide any meta data at all for chunked data,
    // not in the databuffer any way, we might use P1, P2 here...
    uint32_t dataOffset = OFFSET_CDATA + 0;

    os_memcpy(
        /* destination */ ctx->atomSlice + ctx->numberOfCachedBytes,
        /* source */ G_io_apdu_buffer + dataOffset,
        /* number of bytes*/ chunkSize);

    bool shouldFinalizeHash = chunkSize < MAX_CHUNK_SIZE;
    if (shouldFinalizeHash) {
        PRINTF("\nFinalizing hash!\n\n");
    }

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atomSlice + ctx->numberOfCachedBytes,
        (size_t)chunkSize,
        shouldFinalizeHash,
        ctx->hash);

    if (shouldFinalizeHash) {
        PRINTF("Hashing the hash once again, since we at Radix do SHA256-SHA256...\n");
        // In Radix we take the hash of the hash

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

static void printParticleType(RadixParticleTypes particleType) {
    switch (particleType) {
        case NoParticleTypeParsedYet:
            PRINTF("NO PARTICLE INFO YET\n");
            break;
        case MessageParticleType:
            PRINTF("MessageParticle\n");
            break;
        case RRIParticleType:
            PRINTF("RRIParticle\n");
            break;
        case FixedSupplyTokenDefinitionParticleType:
            PRINTF("FixedSupplyTokenDefinitionParticle\n");
            break;
        case MutableSupplyTokenDefinitionParticleType:
            PRINTF("MutableSupplyTokenDefinitionParticle\n");
            break;
        case UnallocatedTokensParticleType:
            PRINTF("UnallocatedTokensParticle\n");
            break;
        case TransferrableTokensParticleType:
            PRINTF("TransferrableTokensParticle\n");
            break;
        case UniqueParticleType:
            PRINTF("UniqueParticle\n");
            break;

        case ParticleType_is_unknown:
        default:
            PRINTF("UNKNOWN PARTICLE TYPE: %d\n", particleType);
            break;
        }
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

static uint8_t totalNumberOfParticlesParsed() {
    return ctx->numberOfNonTransferrableTokensParticlesIdentified + ctx->numberOfTransferrableTokensParticlesParsed;
}

static bool isParticleBeingParsedTransferrableTokensParticle()
{
    return isMetaDataForTransferrableTokensParticle(&(ctx->metaDataAboutParticles[totalNumberOfParticlesParsed()]));
}

static ParticleField getNextFieldToParse() {

    if (!isParticleBeingParsedTransferrableTokensParticle())
    {
        return SerializerField;
    }

    if (isAddressEmpty()) {
        return AddressField;
    }

     if (isAmountEmpty()) {
        return AmountField;
    }

    if (!ctx->hasConfirmedSerializerOfTransferrableTokensParticle)
    {
        return SerializerField;
    }

    return TokenDefinitionReferenceField;
}

static void finishedParsingAWholeTransfer(
    RadixResourceIdentifier *tokenDefinitionReferenceJustParsed
) {
    assert(!isAddressEmpty());
    assert(!isAmountEmpty());
    assert(tokenDefinitionReferenceJustParsed);

    uint8_t *transferByteStart = ctx->transfers[ctx->numberOfTransferrableTokensParticlesParsed].address.bytes;
    ByteInterval fieldByteInterval;

    // SET ADDRESS
    fieldByteInterval = intervalOfTransferStructField(AddressField);
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        ctx->parsedAddressInTransfer.bytes,
        fieldByteInterval.byteCount
    );
    zeroOutAddress();

    // SET AMOUNT
    fieldByteInterval = intervalOfTransferStructField(AmountField);
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        ctx->parsedAmountInTransfer.bytes,
        fieldByteInterval.byteCount
    );
    zeroOutAmount();

    // SET TokenDefRef
    fieldByteInterval = intervalOfTransferStructField(TokenDefinitionReferenceField);
    os_memcpy(
        transferByteStart + fieldByteInterval.startsAt,
        (*tokenDefinitionReferenceJustParsed).bytes,
        fieldByteInterval.byteCount
    );

    ctx->hasConfirmedSerializerOfTransferrableTokensParticle = false;
    ctx->numberOfTransferrableTokensParticlesParsed++;
}

static ByteInterval getNextByteInterval()
{
    ParticleMetaData particleMetaData = ctx->metaDataAboutParticles[totalNumberOfParticlesParsed()];
    switch (getNextFieldToParse())
    {
    case AddressField:
        return particleMetaData.addressOfRecipientByteInterval;
    case AmountField:
        return particleMetaData.amountByteInterval;
    case SerializerField:
        return particleMetaData.serializerValueByteInterval;
    case TokenDefinitionReferenceField:
        return particleMetaData.tokenDefinitionReferenceByteInterval;
    default:
        FATAL_ERROR("Unknown identifier of field: %d", getNextFieldToParse());
    }
}

static void emptyAtomSlice()
{
    os_memset(ctx->atomSlice, 0x00, MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS + MAX_CHUNK_SIZE);
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

static RadixParticleTypes parseSerializer(
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
    RadixParticleTypes particleType = particleTypeFromUTF8String(textString, valueByteCount);

    // if `Address` or `Amount` is parsed, means that we expect this particle to be a TransferrableTokensParticle (since "serializer" comes before "tokenDefinitionReference" alphabetically and thus also in CBOR it is not set yet)
    if (
        (!isAddressEmpty() || !isAmountEmpty())
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
        (isAddressEmpty() || isAmountEmpty())
    )
    {
        FATAL_ERROR("Got `TransferrableTokensParticle`, but amount and address fields are NULL.");
    }

    return particleType;
}

static void parseParticleFieldFromAtomSlice(
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount)
{
    CborParser cborParser;
    CborValue cborValue;
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
    size_t readLength;
    cborError = cbor_value_calculate_string_length(&cborValue, &readLength);
    if (cborError)
    {
        FATAL_ERROR("Failed to calculate length of coming cbor value, CBOR eror: '%s'\n", cbor_error_string(cborError));
    }

    switch (getNextFieldToParse())
    {
    case AddressField:
        assert(type == CborByteStringType);

        parseParticleField(
            readLength, 
            &cborValue, 
            AddressField, 
            ctx->parsedAddressInTransfer.bytes
        );

        break;
    case AmountField:
        assert(type == CborByteStringType);

        parseParticleField(
            readLength, 
            &cborValue, 
            AmountField, 
            ctx->parsedAmountInTransfer.bytes
        );

        break;
    case SerializerField:
        assert(type == CborTextStringType);
        assert(!(ctx->hasConfirmedSerializerOfTransferrableTokensParticle));
        RadixParticleTypes particleType = parseSerializer(readLength, &cborValue);

        if (particleType != TransferrableTokensParticleType)
        {
            ctx->nonTransferrableTokensParticlesIdentified[ctx->numberOfNonTransferrableTokensParticlesIdentified] = particleType;
            ctx->numberOfNonTransferrableTokensParticlesIdentified++;
            PRINTF("\n\n**************************************\n");
            PRINTF("Found particle:\n    ");
            printParticleType(particleType);
            PRINTF("**************************************\n\n");
        } else {
            ctx->hasConfirmedSerializerOfTransferrableTokensParticle = true;
        }
        break;
    case TokenDefinitionReferenceField:
        assert(type == CborByteStringType);
        assert(ctx->hasConfirmedSerializerOfTransferrableTokensParticle);
        RadixResourceIdentifier rri;
        os_memset(rri.bytes, 0x00, sizeof(RadixResourceIdentifier));
        parseParticleField(readLength, &cborValue, TokenDefinitionReferenceField, rri.bytes);
        finishedParsingAWholeTransfer(&rri);
        break;
    }
}

static void cacheBytesToNextChunk(
    const size_t fieldPositionInSlice,
    const size_t numberOfBytesToCache
) {
    assert(numberOfBytesToCache <= MAX_AMOUNT_OF_CACHED_BYTES_BETWEEN_CHUNKS);
    uint8_t tmp[numberOfBytesToCache];

    os_memcpy(
        tmp,
        ctx->atomSlice + fieldPositionInSlice,
        numberOfBytesToCache);

    emptyAtomSlice();

    os_memcpy(
        ctx->atomSlice,
        tmp,
        numberOfBytesToCache);

    // PRINTF("Caching #%u bytes\n", numberOfBytesToCache);
    ctx->numberOfCachedBytes = numberOfBytesToCache;
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

// Returns a boolean value indicating whether the whole atom has been received so that 
// the we can hash the content and parse out all particles
static bool parseParticlesAndUpdateHash()
{
    uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
    uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);

    size_t chunkPositionInAtom = ctx->atomByteCountParsed;
    PRINTF("\nParsing atom chunk: [%u-%u]\n", chunkPositionInAtom, (chunkPositionInAtom+chunkSize));

    readNextChunkFromHostMachineAndUpdateHash((size_t)chunkSize);
    
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;

    bool doneWithCurrentSlice = false;
    while (
        !doneWithCurrentSlice 
        && 
        // Not finished parsing all particles
        totalNumberOfParticlesParsed() < ctx->numberOfParticlesWithSpinUp
        ) {
        doneWithCurrentSlice = tryParseParticleFieldFromAtomSlice(
            chunkPositionInAtom, 
            chunkSize, 
            numberOfCachedBytes
        );
    }

    ctx->atomByteCountParsed += chunkSize;
    return ctx->atomByteCountParsed == ctx->atomByteCount && totalNumberOfParticlesParsed() == ctx->numberOfParticlesWithSpinUp;
}




// ==== START ==== UI PROGRESS UPDATE ========
static const ux_menu_entry_t ui_hack_as_menu_progress_update[] = {
	{NULL, NULL, 0, NULL, "Parsing TX..", global.signAtomContext.partialString12Char, 0, 0},
	UX_MENU_END,
};

static void updateProgressDisplay() {
    snprintf(
        ctx->partialString12Char, 
        DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE, 
        "Part: %02d/%02d",
        (ctx->atomByteCountParsed/MAX_CHUNK_SIZE),
        (ctx->atomByteCount/MAX_CHUNK_SIZE)
    );
    
    UX_REDISPLAY_IDX(ux_visible_element_index);
}
// ==== END ==== UI PROGRESS UPDATE ========




static void parseAtom()
{
    bool finishedParsingWholeAtomAndAllParticles = false;
    while (!finishedParsingWholeAtomAndAllParticles)
    {
        finishedParsingWholeAtomAndAllParticles = parseParticlesAndUpdateHash();

        updateProgressDisplay();

        PRINTF("Finished parsing %u/%u particles\n", totalNumberOfParticlesParsed(), ctx->numberOfParticlesWithSpinUp);
        PRINTF("Finished parsing %u/%u bytes of the Atom\n", ctx->atomByteCountParsed, ctx->atomByteCount);
    }
    assert(ctx->atomByteCountParsed == ctx->atomByteCount);
    assert(totalNumberOfParticlesParsed() == ctx->numberOfParticlesWithSpinUp);

    PRINTF("\n\n.-~=*#^^^ FINISHED PARSING _all_ PARTICLES ^^^#*=~-.\n\n");
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
    volatile unsigned int *tx)
{
    // INPUT VALIDATION
    uint16_t expected_number_of_bip32_compents = 3;
    uint16_t byte_count_bip_component = 4;
    uint16_t expected_bip32_byte_count = expected_number_of_bip32_compents * byte_count_bip_component;

    size_t byte_count_of_atom_size = 2;
    size_t max_size_particle_meta_data = MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP * sizeof(ParticleMetaData);

    // Meta sanity check
    assert(MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP < MAX_AMOUNT_OF_PARTICLES_WITH_SPIN_UP);
    assert(max_size_particle_meta_data <= (MAX_CHUNK_SIZE - byte_count_of_atom_size - expected_bip32_byte_count));

    if (dataLength < (expected_bip32_byte_count + byte_count_of_atom_size + sizeof(ParticleMetaData))) // expect at least one particle
    {
        PRINTF("'dataLength' is to small, only: %d\n", dataLength);
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
    parse_bip32_path_from_apdu_command(dataBuffer, ctx->bip32Path, NULL, 0);
    dataOffset += expected_bip32_byte_count;
    // PRINTF("BIP 32 Path used for signing: %s\n", ctx->bip32PathString);

    // READ Atom Byte Count (CBOR encoded data)
    ctx->atomByteCount = U2BE(dataBuffer, dataOffset);
    dataOffset += byte_count_of_atom_size;
    PRINTF("Atom byte count: %d bytes\n", ctx->atomByteCount);
    ctx->atomByteCountParsed = 0;

    // READ meta data about particles from first chunk, available directly
    PRINTF("Recived meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string\n%.*H\n", (16) * ctx->numberOfParticlesWithSpinUp, dataBuffer, dataOffset);

    uint8_t numberOfTransferrableTokensParticlesToParse = 0;
    for (uint8_t particleIndex = 0; particleIndex < ctx->numberOfParticlesWithSpinUp; ++particleIndex)
    {
        // In this (alphabetical) order: [address, amount, serializer, tokenDefRef]
        // read the values.

        uint16_t addressOfRecipientByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        uint16_t addressOfRecipientByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;

        ByteInterval addressOfRecipientByteInterval = {
            .startsAt = addressOfRecipientByteIntervalStart,
            .byteCount = addressOfRecipientByteIntervalCount};

        uint16_t amountByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        uint16_t amountByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;

        ByteInterval amountByteInterval = {
            .startsAt = amountByteIntervalStart,
            .byteCount = amountByteIntervalCount};

        uint16_t serializerByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        uint16_t serializerByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;

        ByteInterval serializerValueByteInterval = {
            .startsAt = serializerByteIntervalStart,
            .byteCount = serializerByteIntervalCount};

        uint16_t tokenDefinitionReferenceByteIntervalStart = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;
        uint16_t tokenDefinitionReferenceByteIntervalCount = U2BE(dataBuffer, dataOffset);
        dataOffset += 2;

        ByteInterval tokenDefinitionReferenceByteInterval = {
            .startsAt = tokenDefinitionReferenceByteIntervalStart,
            .byteCount = tokenDefinitionReferenceByteIntervalCount};

        ParticleMetaData metaDataAboutParticle = {
            .addressOfRecipientByteInterval = addressOfRecipientByteInterval,
            .amountByteInterval = amountByteInterval,
            .serializerValueByteInterval = serializerValueByteInterval,
            .tokenDefinitionReferenceByteInterval = tokenDefinitionReferenceByteInterval};

        if (isMetaDataForTransferrableTokensParticle(&metaDataAboutParticle)) {
            numberOfTransferrableTokensParticlesToParse++;
            if (numberOfTransferrableTokensParticlesToParse > MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP) {
                FATAL_ERROR("Cannot parse and hold data for more than %u TransferrableTokensParticles with spin up, but encountered more than that\n", MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP);
            }
        }

        ctx->metaDataAboutParticles[particleIndex] = metaDataAboutParticle;
    }

    // INITIATE SHA Hasher
    cx_sha256_init(&(ctx->hasher));

    // Start cached bytes buffer at 0 bytes, cached bytes are used
    // when data spans across two chunks.
    ctx->numberOfCachedBytes = 0;

    for (int i = 0; i < ctx->numberOfNonTransferrableTokensParticlesIdentified; ++i)
    {
        ctx->nonTransferrableTokensParticlesIdentified[i] = NoParticleTypeParsedYet;
    }

    os_memset(ctx->transfers, 0x00, MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP * sizeof(Transfer));
    os_memset(ctx->indiciesTransfersToNotMyAddress, 0x00, MAX_AMOUNT_OF_TRANSFERRABLE_TOKENS_PARTICLES_WITH_SPIN_UP * sizeof(uint8_t));

    zeroOutAddress();
    zeroOutAmount();
    ctx->hasConfirmedSerializerOfTransferrableTokensParticle = false;
    ctx->numberOfNonTransferrableTokensParticlesIdentified = 0;
    ctx->numberOfTransferrableTokensParticlesParsed = 0;
    ctx->numberOfTransfersToNotMyAddress = 0;
    ctx->lengthOfFullString = 0;


    UX_MENU_DISPLAY(0, ui_hack_as_menu_progress_update, NULL);
    ux_visible_element_index = G_ux.stack[0].element_index;

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.
    parseAtom();

    *flags |= IO_ASYNCH_REPLY;

    presentAtomContentsOnDisplay();

}