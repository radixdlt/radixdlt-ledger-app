#include <stdlib.h>
#include <stddef.h>
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

static unsigned short ux_visible_element_index = 0;

typedef enum {
    AddressField = 0,
    AmountField,
    SerializerField,
    TokenDefinitionReferenceField
} ParticleField;



static void zeroOutTransfer() {
    os_memset(&(ctx->transfer), 0x00, sizeof(Transfer));
}

static bool isParticleMetaDataEmpty() {
    return ctx->metaDataAboutParticle.addressOfRecipientByteInterval.startsAt == 0 &&
    ctx->metaDataAboutParticle.addressOfRecipientByteInterval.byteCount == 0 &&
    ctx->metaDataAboutParticle.amountByteInterval.startsAt == 0 &&
    ctx->metaDataAboutParticle.amountByteInterval.byteCount == 0 &&
    ctx->metaDataAboutParticle.serializerValueByteInterval.startsAt == 0 &&
    ctx->metaDataAboutParticle.serializerValueByteInterval.byteCount == 0 &&
    ctx->metaDataAboutParticle.tokenDefinitionReferenceByteInterval.startsAt == 0 &&
    ctx->metaDataAboutParticle.tokenDefinitionReferenceByteInterval.byteCount == 0;
}

static void zeroOutParticleMetaData() {
    os_memset(&(ctx->metaDataAboutParticle), 0x00, sizeof(ParticleMetaData));
    assert(isParticleMetaDataEmpty())
}

static bool isAddressEmpty() {
    size_t sizeOfRadixAddress = sizeof(RadixAddress);
    for (size_t i = 0; i < sizeOfRadixAddress; ++i)
    {
        const uint8_t *pointerToAddressByte = ctx->transfer.address.bytes + i;
        uint8_t byteAtMemPos = *pointerToAddressByte;

        if (byteAtMemPos > 0x00) {
            return false;
        }
    }
    return true;
}

static bool isAmountEmpty() {
    size_t sizeOfTokenAmount = sizeof(TokenAmount);
    for (size_t i = 0; i < sizeOfTokenAmount; ++i) {
        const uint8_t *pointerToAmountByte = ctx->transfer.amount.bytes + i;
        uint8_t byteAtMemPos = *pointerToAmountByte;

        if (byteAtMemPos > 0x00) {
            return false;
        }
    }
    return true;
}


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


static void parseMetaDataAboutNextParticle(uint8_t* dataBuffer, uint16_t dataLength) {
        // READ meta data about particles from first chunk, available directly
    assert(dataLength == sizeof(ParticleMetaData));
    // PRINTF("Received meta data about: #%u particles\n", ctx->numberOfParticlesWithSpinUp);
    PRINTF("Received particle meta data hex string:\n%.*H\n", dataLength, dataBuffer);
    int dataOffset = 0;

    PRINTF("Zeroing out old particle meta data now...\n");
    zeroOutParticleMetaData();

    // ctx->metaDataAboutParticle.particleItself.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    // ctx->metaDataAboutParticle.particleItself.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->metaDataAboutParticle.addressOfRecipientByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->metaDataAboutParticle.addressOfRecipientByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->metaDataAboutParticle.amountByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->metaDataAboutParticle.amountByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->metaDataAboutParticle.serializerValueByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->metaDataAboutParticle.serializerValueByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    ctx->metaDataAboutParticle.tokenDefinitionReferenceByteInterval.startsAt = U2BE(dataBuffer, dataOffset); dataOffset += 2;
    ctx->metaDataAboutParticle.tokenDefinitionReferenceByteInterval.byteCount = U2BE(dataBuffer, dataOffset); dataOffset += 2;

    PRINTF("\nFinished parsing particle meta data...\n\n");
}

typedef enum {
    PayloadTypeParticleMetaData = 0,
    PayloadTypeAtomBytes = 1
} PayloadType;

// Returns `false` if the received data was metadata about a particle (identified by `p1`), otherwise `true` (indicating that it was atom bytes...)
static int readNextChunkFromHostMachineAndUpdateHash()
{
    os_memset(G_io_apdu_buffer, 0x00, IO_APDU_BUFFER_SIZE);
    G_io_apdu_buffer[0] = 0x90; // 0x9000 == 'SW_OK'
    G_io_apdu_buffer[1] = 0x00; // 0x9000 == 'SW_OK'
    PRINTF("Invoking 'io_exchange' now...\n");
    io_exchange(CHANNEL_APDU, 2);

    // uint32_t dataOffset = OFFSET_CDATA + 0;
    // uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];

    uint8_t p1 = G_io_apdu_buffer[OFFSET_P1];
    uint8_t p2 = G_io_apdu_buffer[OFFSET_P2];
    uint8_t* dataBuffer = G_io_apdu_buffer + OFFSET_CDATA;
    uint16_t dataLength = G_io_apdu_buffer[OFFSET_LC];

    PRINTF("P1: %d\n", p1);
    PRINTF("Received #%d bytes...\n", dataLength);
    // PRINTF("bytes received: %.*h\n", dataLength, dataBuffer);

    if (p1 == PayloadTypeParticleMetaData) {
        zeroOutParticleMetaData();
        parseMetaDataAboutNextParticle(dataBuffer, dataLength);
        return 0;
    }

    assert(p1 == PayloadTypeAtomBytes);

    // uint16_t bytesLeftToRead = ctx->atomByteCount - ctx->atomByteCountParsed;
    // uint16_t chunkSize = MIN(MAX_CHUNK_SIZE, bytesLeftToRead);

    os_memcpy(
        ctx->atomSlice + ctx->numberOfCachedBytes,
        dataBuffer,
        dataLength
    );

    bool shouldFinalizeHash = ctx->atomByteCountParsed + dataLength == ctx->atomByteCount;
    if (shouldFinalizeHash) {
        PRINTF("\nFinalizing hash!\n\n");
    }

    // UPDATE HASH
    sha256_hash(
        &(ctx->hasher),
        /* bytes to hash */ ctx->atomSlice + ctx->numberOfCachedBytes,
        (size_t)dataLength,
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

    return dataLength;
}


// Returns `true` iff `utf8_string` indicates a TransferrableTokensParticle
static bool is_transferrable_tokens_particle_serializer(
    const char *utf8_string,
    const size_t string_length)
{
    return (strncmp(utf8_string, "radix.particles.transferrable_tokens", string_length) == 0);
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
    return isMetaDataForTransferrableTokensParticle(&(ctx->metaDataAboutParticle));
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

static void askUserToConfirmTransferIfNeeded() {
    FATAL_ERROR("IMPL ME");
}

static void finishedParsingAWholeTransfer() {

    ctx->hasConfirmedSerializerOfTransferrableTokensParticle = false;
    ctx->numberOfTransferrableTokensParticlesParsed++;

    askUserToConfirmTransferIfNeeded();
}

static ByteInterval getNextByteInterval()
{
    switch (getNextFieldToParse())
    {
    case AddressField:
        return ctx->metaDataAboutParticle.addressOfRecipientByteInterval;
    case AmountField:
        return ctx->metaDataAboutParticle.amountByteInterval;
    case SerializerField:
        return ctx->metaDataAboutParticle.serializerValueByteInterval;
    case TokenDefinitionReferenceField:
        return ctx->metaDataAboutParticle.tokenDefinitionReferenceByteInterval;
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

// Returns `true` iff the cborValue indicates a particle of type `TransferrableTokensParticle`
static bool parseSerializer(
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
    PRINTF("Found serializer: '%.*s'\n", valueByteCount, textString);
    bool isTransferrableTokensParticle = is_transferrable_tokens_particle_serializer(textString, valueByteCount);

    // if `Address` or `Amount` is parsed, means that we expect this particle to be a TransferrableTokensParticle (since "serializer" comes before "tokenDefinitionReference" alphabetically and thus also in CBOR it is not set yet)
    if (
        (!isAddressEmpty() || !isAmountEmpty())
    )
    {
        if (!isTransferrableTokensParticle)
        {
            FATAL_ERROR("Incorrect particle type, expected `TransferrableTokensParticle`, but got other.");
        }
    }
    else if (
        isTransferrableTokensParticle
        && 
        (isAddressEmpty() || isAmountEmpty())
    )
    {
        FATAL_ERROR("Got `TransferrableTokensParticle`, but amount and address fields are NULL.");
    }

    return isTransferrableTokensParticle;
}

static void parseParticleFieldFromAtomSlice(
    const size_t fieldPositionInAtomSlice,
    const size_t fieldByteCount)
{

    PRINTF("Start of parseParticleFieldFromAtomSlice\n");
    PRINTF("bytes parsed: #%d\n", ctx->atomByteCountParsed);

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
            ctx->transfer.address.bytes
        );

        break;
    case AmountField:
        assert(type == CborByteStringType);

        parseParticleField(
            readLength, 
            &cborValue, 
            AmountField, 
            ctx->transfer.amount.bytes
            // ctx->parsedAmountInTransfer.bytes
        );

        break;
    case SerializerField:
        assert(type == CborTextStringType);
        assert(!(ctx->hasConfirmedSerializerOfTransferrableTokensParticle));
        bool isTransferrableTokensParticle = parseSerializer(readLength, &cborValue);

        if (!isTransferrableTokensParticle)
        {
            PRINTF("Particle is NOT TTP, increasing 'numberOfNonTransferrableTokensParticlesIdentified'\n");
            ctx->numberOfNonTransferrableTokensParticlesIdentified++;
        } else {
            ctx->hasConfirmedSerializerOfTransferrableTokensParticle = true;
        }
        break;
    case TokenDefinitionReferenceField:
        assert(type == CborByteStringType);
        assert(ctx->hasConfirmedSerializerOfTransferrableTokensParticle);
        // RadixResourceIdentifier rri;
        // os_memset(rri.bytes, 0x00, sizeof(RadixResourceIdentifier));
        parseParticleField(readLength, &cborValue, TokenDefinitionReferenceField, ctx->transfer.tokenDefinitionReference.bytes);
        // finishedParsingAWholeTransfer(&rri);
        PRINTF("\nWOHO! Finished parsing a transfer!\n");
        askUserForConfirmationOfTransferIfNeeded();
        ctx->hasConfirmedSerializerOfTransferrableTokensParticle = false;
        break;
    }
    return readLength;
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

    ctx->numberOfCachedBytes = numberOfBytesToCache;
}

// Returns true if `doneWithCurrentSlice`, i.e. all fields that can be parsed in current atom slice has been parsed
static bool tryParseParticleFieldFromAtomSlice(
    const size_t chunkStartPositionInAtom, // chunk, not slice, i.e. possibly cached bytes from last chunk not used to offset byte start position
    const size_t chunkByteCount, // chunk, not slice, i.e. possibly cached bytes from last chunk not included
    const size_t cachedBytesCount
) {
    PRINTF("trying to parse Particle field from AtomSlice with paramters:\n");
    PRINTF("chunkStartPositionInAtom: %d\n", chunkStartPositionInAtom);
    PRINTF("chunkByteCount: %d\n", chunkByteCount);
    PRINTF("cachedBytesCount: %d\n", cachedBytesCount);
    size_t chunkEndPositionInAtom = chunkStartPositionInAtom + chunkByteCount;
    ByteInterval fieldByteInterval = getNextByteInterval();
    size_t fieldStartPositionInAtom = fieldByteInterval.startsAt;
    size_t fieldByteCount = fieldByteInterval.byteCount;
    size_t fieldEndPositionInAtom = fieldStartPositionInAtom + fieldByteCount;

    size_t fieldPositionInSlice = cachedBytesCount + fieldStartPositionInAtom - chunkStartPositionInAtom;

    bool canParseNextField = fieldEndPositionInAtom <= chunkEndPositionInAtom;
    bool doneWithCurrentSlice = false;
    PRINTF("canParseNextField: %s (fieldEndPositionInAtom (%d) <= chunkEndPositionInAtom (%d))\n", canParseNextField ? "true" : "false", fieldEndPositionInAtom, chunkEndPositionInAtom);
    if (canParseNextField)
    {
        int lengtOfParsedField = parseParticleFieldFromAtomSlice(fieldPositionInSlice, fieldByteCount);
        if (fieldPositionInSlice + ) {

        }
    }
    else
    {
        doneWithCurrentSlice = true;
        bool needsToCacheBytes = !canParseNextField && (fieldStartPositionInAtom < chunkEndPositionInAtom);

        if (needsToCacheBytes)
        {
            size_t numberOfBytesToCache = chunkEndPositionInAtom - fieldStartPositionInAtom;
            PRINTF("Caching #%d bytes\n", numberOfBytesToCache);
            cacheBytesToNextChunk(fieldPositionInSlice, numberOfBytesToCache);
        }
    }
    PRINTF("tryParseParticleFieldFromAtomSlice:doneWithCurrentSlice: %s\n", doneWithCurrentSlice ? "true" : "false");
    return doneWithCurrentSlice;
}

// Returns a boolean value indicating whether the whole atom has been received so that 
// the we can hash the content and parse out all particles
static bool parseParticlesAndUpdateHash()
{

    // PRINTF("\nParsing atom chunk: [%u-%u]\n", chunkPositionInAtom, (chunkPositionInAtom+chunkSize));
    int atomBytesToParse = readNextChunkFromHostMachineAndUpdateHash();

    if (atomBytesToParse == 0) {
        return false;
    }
    size_t chunkPositionInAtom = ctx->atomByteCountParsed;
    
    size_t numberOfCachedBytes = ctx->numberOfCachedBytes;
    ctx->numberOfCachedBytes = 0;

    bool doneWithCurrentSlice = isParticleMetaDataEmpty();


    while (!doneWithCurrentSlice) {

        doneWithCurrentSlice = tryParseParticleFieldFromAtomSlice(
            chunkPositionInAtom, 
            atomBytesToParse, 
            numberOfCachedBytes
        );

        PRINTF("parseParticlesAndUpdateHash:doneWithCurrentSlice: %s\n", doneWithCurrentSlice ? "true" : "false");
    }

    ctx->atomByteCountParsed += atomBytesToParse;
    return ctx->atomByteCountParsed == ctx->atomByteCount && totalNumberOfParticlesParsed() == ctx->numberOfParticlesWithSpinUp;
}


// ==== START ==== UI PROGRESS UPDATE ========
static const ux_menu_entry_t ui_hack_as_menu_progress_update[] = {
	{NULL, NULL, 0, NULL, "Parsing TX..", G_ui_state.lower_line_short, 0, 0},
	UX_MENU_END,
};

static void updateProgressDisplay() {
    os_memset(G_ui_state.lower_line_long, 0x00,
              MAX_LENGTH_FULL_STR_DISPLAY);

    os_memset(G_ui_state.lower_line_short, 0x00,
              DISPLAY_OPTIMAL_NUMBER_OF_CHARACTERS_PER_LINE);

    snprintf(
        G_ui_state.lower_line_short, 
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


#define SKIP_CONFIRMATION_WHEN_SIGNING_ATOM_FOR_TEST 0xFF



static void setupState() {
    zeroOutTransfer();

    // INITIATE SHA Hasher
    cx_sha256_init(&(ctx->hasher));

    ctx->hasApprovedNonTransferData = false;
    ctx->atomByteCountParsed = 0;
    ctx->numberOfCachedBytes = 0;
    ctx->hasConfirmedSerializerOfTransferrableTokensParticle = false;
    ctx->numberOfNonTransferrableTokensParticlesIdentified = 0;
    ctx->numberOfTransferrableTokensParticlesParsed = 0;
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

    if (dataLength != (expected_bip32_byte_count + byte_count_of_atom_size))
    {
        PRINTF("incorrect 'dataLength' was: %d\n", dataLength);
        THROW(SW_INVALID_PARAM);
    }

    ctx->numberOfParticlesWithSpinUp = p1;

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

    setupState();
    PRINTF("State initialized\n");
    UX_MENU_DISPLAY(0, ui_hack_as_menu_progress_update, NULL);
    ux_visible_element_index = G_ux.stack[0].element_index;

    // INSTRUCTIONS ON HOW TO PARSE PARTICLES FROM ATOM RECEIVED => start parsing
    // This will be done in `ctx->atomByteCount / CHUNK_SIZE` number of chunks
    // by 'streaming' data in this chunks using multiple `io_exchange` calls.
    PRINTF("invoking 'parseAtom' now...\n");
    parseAtom();
    
    *flags |= IO_ASYNCH_REPLY;
   
    if (p2 == SKIP_CONFIRMATION_WHEN_SIGNING_ATOM_FOR_TEST) {
        askUserForFinalConfirmation();
    } else {
        askUserForConfirmationOfHash();
        // presentAtomContentsOnDisplay();
    }
}