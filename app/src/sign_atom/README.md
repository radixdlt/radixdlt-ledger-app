# Description

Signing a transaction (list of user actions), that is represented by an "Atom" on the Radix ledger, requires metadata about said atom in order for the Ledger to be able to sign it. To understand why one needs to know about Radix's Atom Model and the fact that we only ever have access to `~1.000` bytes of memory on the Ledger Nano S device. In order to parse tokens transfers, if any, found in an Atom, one needs to be able to:
1. [`DSON`](https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding) ([CBOR - Consice Binary Object Representation](http://cbor.io/)) **decode**
2. Know type of particle field before starting to parse it
3. Know location of relevant information (fields) of particle and byte count

Since our CBOR encoding **sorts** key-value pairs of "map" type (CBOR major type 5) in **lexicographical order** and since the key describing the type of particle is "serializer", it comes late in the encoding of said particle. Naive solution would be to put the serializer key-value first by changing it to "!serializer" or similar. However that only solves one problem - identifying the type of the particle. We still have the problem with large particles and the fact that the Ledger app only gets to see 255 bytes of chunk at any time. And any key or value of a field might be split across chunks. So instead of trying to CBOR decode every byte in the Atom we have chosen to use a different solution - we require any wallet interacting with our Ledger Nano S app to provide meta data about all relevant fields inside all particles with spin UP. That way we only need to try to CBOR decode the values found at these locations (byte intervals). And since we know the byte intervals of fields of interest before we recive the (max 255 bytes large) chunks of data, we can also more easily implement logic taking care of edge cases where these relevant bytes are spread across chunks (e.g. by making sure the bytes for a particle field never is split accross multiple chunks/packets).

The particle field meta data consists of a touple (`startsAtByte`, `byte_count`) each consisting of 2 bytes => the byte interval is thus 4 bytes.

These byte intervals points to the following fields within the spun `UP` particle (`address`, `amount`, `serializer`, `tokenDefinitionReference`) - in that order - for being able to parse `TransferableTokensParticles` (TokenTransfers). 

In the case of **non**-`TransferrableTokensParticles` (e.g. `MessageParticle`, `RRIParticle` etc), only the byte interval for `serializer` field is used.

# Pseudocode

## Host machine

```swift
func stream(
    atom: Atom, 
    toLedgerAndSignItWithKeyAtPath bip32_path: BIP32Path
) -> ECDSASignature {

    var particleFields: [ParticleFieldMetadata] = calculateMetaDataAboutRelevantFieldsIn(upParticles: atom.upParticles())

    var remainingBytesInAtom: [Byte] = atom.dsonEncodedData()

    // Send initial "setup" packet
    
    let atomByteCount = remainingBytesInAtom.count
    sendToLedger(
        p1: atom.spunParticles(spin: .up).count,
        p2: atom.transferrableTokensParticles(spin: .up).count,
        payload: bip32_path.data() + atomByteCount.data()
    )

    // Stream atom to Ledger

    var numberOfAtomBytesSent = 0

    func sendToLedgerAtomBytes(count atomByteCount: Int) -> [Byte] {
        // atomBytes: [Byte]

        let response = sendToLedger(
            p1: PayloadIdentifier.particleField.rawValue, // 100
            p2: 0x00,
            payload: atomBytes
        )

        numberOfAtomBytesSent += atomBytes.count
        remainingBytesInAtom = remainingBytesInAtom.removingFirst(atomBytes.count)

        if remainingBytesInAtom.count == 0 {
            print("💡 Expected Hash (verify on Ledger): \(atom.hash())")
        }

        return response
    }

    var result: [Byte]! 
    while numberOfAtomBytesSent < atomByteCount {
        let maybeField = particleFields.first()

        let nextRelevantEnd = maybeField?.startIndexInAtom ?? atomByteCount

        if let particleField = maybeField, particleField.startIndexInAtom == atomByteCount {
            sendToLedger(particleField: particleField)
            sendToLedgerAtomBytes(count: particleField.byte_count)
        } else {
            let ledgerPayloadMaxSize = 255
            result = sendToLedgerAtomBytes(count: min(ledgerPayloadMaxSize, nextRelevantEnd - numberOfAtomBytesSent))
        }
    }
    guard let signatureFromLedger = result else { fatalError("Expected signature from Ledger") }

    return ECDSASignature(bytes: signatureFromLedger)
}

func calculateMetaDataAboutRelevantFieldsIn(upParticles: [UpParticle], in atom: Atom) -> [ParticleFieldMetadata] {
    return upParticles.flatMap { upParticle in
        if let transferrableTokensParticle = upParticle {
            return [
                transferrableTokensParticle.field(type: .address),
                transferrableTokensParticle.field(type: .amount), 
                transferrableTokensParticle.field(type: .serialzier), 
                transferrableTokensParticle.field(type: .tokenDefinitionReference)
            ].map { field in 
                byte_interval_t(ofField: field, in: atom) 
            }
        } else {
            return [
                byte_interval_t(ofField: upParticle.field(type: .serialzier), in: atom) 
            ]
        }
    }
}

func sendToLedger(p1: Int, p2: Int, payload: [Byte]) -> [Byte] { ... }

func sendToLedger(particleField: particle_field_t) {

    sendToLedger(
        p1: PayloadIdentifier.particleField.rawValue, // 101
        p2: particleField.fieldType, // .address: 200, .amount: 201, .serializer: 202,, .tokenDefRef: 203, 
        payload: particleField.rawBytes // 4 bytes
    )
}

```

## Ledger App
```swift
func signAtom(
    p1: Int,
    p2: Int,
    dataBuffer: [Byte]
) {
    var ctx = SignAtomContext()
    
    // Receive and parse inital setup packet
    let (bip32Path, atomSize) = parseBIP32PathAndAtomSize(
        totalNumberOfUpParticles: p1,
        numberOfUpTransferrableTokensParticles: p2,
        data: dataBuffer
    )
    ctx.bip32Path = bip32Path
    ctx.atomSize = atomSize



    // Finished with inital packet, tell host to send atom bytes
    parseAtom(context: ctx) 
    // execution is blocked here until the whole atom is parsed.


    askUserToVerifyHashBeforeSigning()
    // Execution is blocked until user has accepted / rejected hash+sign

    print("~~~ FINISHED PARSING+SIGNING ATOM ~~~")

}

func parseAtom(context ctx: SignAtomContext) {
    while ctx.numberOfBytesReceived < ctx.atomByteCount {
        receivedBytesAndUpdateHashAndDisplay(context: ctx)
    }
}

func receivedBytesAndUpdateHashAndDisplay(context ctx: SignAtomContext) {
    let (p1, p2, dataBuffer) = readBytesFromHostMachine()
    let payloadType = PayloadType(rawValue: p1)
    switch payloadType {
        case .partifleFieldMetaData:
            ctx.particleField = ParticleFieldMetaData(bytes: dataBuffer)

        case .atomBytes:
            ctx.numberOfBytesReceived += dataBuffer.count

            ctx.hasher.update(
                bytes: dataBuffer, 
                finalize: ctx.numberOfBytesReceived == ctx.atomByteCount
            )


        guard let particleField = ctx.particleField else { 
            print("Irrelevant atom bytes, nothing to parse or to do.")
            return 
        }

        let fieldParsingResult = parseFieldFromAtomBytes(particleField, in: dataBuffer)
        switch fieldParsingResult {
            case .finishedParsingTransfer:
                let askUserToConfirmTransfer = !isTransferChangeBackToHerself(ctx.transfer, deriveAddressFrom: ctx.bip32Path)
                if askUserToConfirmTransfer {
                    askUserToConfirmTransferToOtherAddress()
                    // Execution is blocked until user has accepted / rejected
                }
                ctx.transfer = nil
            case .parsedPartOfTransfer:
                print("Finished part of transfer")
                return
            case .nonTransferDataFound:
                if !ctx.userHasAcceptedNonTransferData {

                    askUserToConfirmUserData()
                    // Execution is blocked until user has accepted / rejected

                    // If user rejects, main loop of program exists, so this
                    // line of code ONLY executes is usere accepts.
                    ctx.userHasAcceptedNonTransferData = true
                }
        }
    }
}

func parseFieldFromAtomBytes(
    _ particleField: ParticleField, 
    in dataBuffer: [Byte], 
    context ctx: SignAtomContext
) -> ParseParticleFieldResult {

    assert(dataBuffer.coount == particleField.byteInterval.count)

    let cborParser = CBORParser(bytes: dataBuffer)
    let cborValueType = cborParser.typeOfValue
    let cborValue = cborParser.value
    let cborLength = cborParser.stringLength
    
    let radixValueIdentifier = cborValue.first()
    
    let radixValue = cborValue.suffix(cborLength - 1)

    switch particleField.type {
        case .address:
            assert(ctx.transfer == nil)
            assert(cborValueType == .byteString)

            assert(radixValueIdentifier == .addressByteString)
            
            ctx.transfer = Transfer()
            ctx.transfer.address = Address(byteString: radixValue)

            return .parsedPartOfTransfer
        case .amount:
            assert(ctx.transfer?.address != nil)
            assert(ctx.transfer?.amount == nil)
            assert(cborValueType == .byteString)

            assert(radixValueIdentifier == .amountByteString)
            
            ctx.transfer.amount = UInt256(byteString: radixValue)
            return .parsedPartOfTransfer

        case .serialzier:
            assert(cborValueType == .textString)
            let serializer = parseSerializer(radixValue)

            print("Found particle with serializer: \(serializer)")
            
            let isSerializerForTransferrableTokensParticle =  serializer == "radix.particle.transferrable_tokens"
            
            if isSerializerForTransferrableTokensParticle {
                assert(!ctx.transfer.hasConfirmedSerializer)
                ctx.transfer.hasConfirmedSerializer = true
                return .parsedPartOfTransfer
            } else {
                return .nonTransferDataFound
            }

        case .tokenDefinitionReference:
            assert(ctx.transfer?.address != nil)
            assert(ctx.transfer?.amount != nil)
            assert(ctx.transfer?.hasConfirmedSerializer == true)
            assert(ctx.transfer?.tokenDefinitionReference == nil)

            assert(cborValueType == .byteString)

            ctx.transfer.tokenDefinitionReference = RadixResourceIdentifier(byteString: radixValue)
            return .finishedParsingTransfer
    }
}

func parseBIP32PathAndAtomSize(
    totalNumberOfUpParticles: Int, 
    numberOfUpTransferrableTokensParticles: Int,
    data: [Byte] // ` BIP32(12 bytes) || AtomSize (2 bytes)`
) {
    // ...
}

```

## MetaData

### Creating MetaData

Swift inspired Pseudocode below constructs a `ParticleMetaData` being a struct of 16 bytes with the four fields in order: `address, amount, serializer, tokenDefinitionReference`, we used to use this struct earlier but now we don't. We only send the fields indiviudall and never the `ParticleMetaData` as a whole.

```swift
func byteIntervalOf(field: Field, in particle: UpParticle) -> byte_interval_t {
    particleCBOR := particle.cborHexString()
    fieldCBOR := field.name.cborHexString()

    return byte_interval_t(
        startsAtByte: particleCBOR.indexOf(fieldCBOR),
        byte_count: particleCBOR.length
    )
}

func metaDataOfUpParticle(upParticle: UpParticle, in atom: Atom) -> ParticleMetaData

    intervalOf := lambda(f) -> byteIntervalOf(field: f, in: upParticle)

    if upParticle is TransferrableTokensParticle {
        metaData := ParticleMetaData(
            address: intervalOf(.address),
            amount: intervalOf(.amount),
            serializer: intervalOf(.serializer),
            tokenDefinitionReference: intervalOf(.rri),
    } else {
        metaData := ParticleMetaData(
            address: .zero,
            amount: .zero,
            serializer: intervalOf(.serializer),
            tokenDefinitionReference: .zero,
        )
    }

    atomCBOR := atom.cborHexString()
    particleCBOR := upParticle.cborHexString()
    particleOffsetInAtom := atomCBOR.indexOf(particleCBOR)
    
    return metaData.withOffsetInAtom(particleOffsetInAtom)

func metaDataOfParticlesInAtom(atom: Atom) -> [ParticleMetaData]
    metaDataAboutParticles := []
    forEach upParticle in atom
        metaData := metaDataOfUpParticle(upParticle, in: atom)
        metaDataAboutParticles.append(metaData)
    return metaDataAboutParticles
```

### MetaData Encoding

```swift

// Always encode 4 byte, use BigEndian
func encodeByteInterval(byteInterval: byte_interval_t) -> ByteArray {
    BigEndian2BytesFromInt16(byteInterval.startsAtByte) || BigEndian2BytesFromInt16(byteInterval.byte_count)
}

// Returns 16 BigEndian encoded ByteArray from ParticleMetaData
func encodeParticleMetaData(particleMetaData: ParticleMetaData) -> ByteArray {
    // MUST be in the same order as the fields are encoded to CBOR:
    let fieldsInCorrectAlphabeticalOrder := [
        addressByteInterval,
        amountByteInterval,
        serializerByteInterval,
        tokenDefinitionReferenceByteInterval
    ]
     
    return fieldsInCorrectAlphabeticalOrder
        // convert each `byte_interval_t` into ByteArray, each 4 bytes long
        .map(encodeByteInterval)
        // concat the four ByteArrays together
        .reduce( || ) 
}
```