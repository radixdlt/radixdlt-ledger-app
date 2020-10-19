# Description

Signing a transaction (list of user actions), that is represented by an "Atom" on the Radix ledger, requires metadata about said atom in order for the Ledger to be able to sign it. To understand why one needs to know about Radix's Atom Model and the fact that we only ever have access to `~1.000` bytes of memory on the Ledger Nano S device. In order to parse tokens transfers, if any, found in an Atom, one needs to be able to:
1. [`DSON`](https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding) ([CBOR - Consice Binary Object Representation](http://cbor.io/)) **decode**
2. Know type of particle field before starting to parse it
3. Know location of relevant information (fields) of particle and byte count

Since our CBOR encoding **sorts** key-value pairs of "map" type (CBOR major type 5) in **lexicographical order** and since the key describing the type of particle is "serializer", it comes late in the encoding of said particle. Naive solution would be to put the serializer key-value first by changing it to "!serializer" or similar. However that only solves one problem - identifying the type of the particle. We still have the problem with large particles and the fact that the Ledger app only gets to see 255 bytes of chunk at any time. And any key or value of a field might be split across chunks. So instead of trying to CBOR decode every byte in the Atom we have chosen to use a different solution - we require any wallet interacting with our Ledger Nano S app to provide meta data about all relevant fields inside all particles with spin UP. That way we only need to try to CBOR decode the values found at these locations (byte intervals). And since we know the byte intervals of fields of interest before we recive the (max 255 bytes large) chunks of data, we can also more easily implement logic taking care of edge cases where these relevant bytes are spread across chunks (e.g. by making sure the bytes for a particle field never is split accross multiple chunks/packets).

The particle field meta data consists of a touple (`startsAtByte`, `byteCount`) each consisting of 2 bytes => the byte interval is thus 4 bytes.

These byte intervals points to the following fields within the spun `UP` particle (`address`, `amount`, `serializer`, `tokenDefinitionReference`) - in that order - for being able to parse `TransferableTokensParticles` (TokenTransfers). 

In the case of **non**-`TransferrableTokensParticles` (e.g. `MessageParticle`, `RRIParticle` etc), only the byte interval for `serializer` field is used.

# Pseudocode

## Host machine

```swift
func calculateMetaDataAboutRelevantFieldsIn(upParticles: [UpParticle], in atom: Atom) -> [ParticleFieldMetadata] {
	return upParticles.flatMap { upParticle in
		if let transferrableTokensParticle = upParticle {
			return [
				transferrableTokensParticle.field(type: .address),
				transferrableTokensParticle.field(type: .amount), 
				transferrableTokensParticle.field(type: .serialzier), 
				transferrableTokensParticle.field(type: .tokenDefinitionReference)
			].map { field in 
				ByteInterval(ofField: field, in: atom) 
			}
		} else {
			return [
				ByteInterval(ofField: upParticle.field(type: .serialzier), in: atom) 
			]
		}
	}
}

func sendToLedger(p1: Int, p2: Int, payload: [Byte]) -> [Byte] { ... }

func sendToLedger(particleField: ParticleField) {
	sendToLedger(
		p1: PayloadIdentifier.particleField.rawValue, // 101
		p2: particleField.fieldType, // .address: 200, .amount: 201, .serializer: 202,, .tokenDefRef: 203, 
		payload: particleField.rawBytes // 4 bytes
	)
}

func stream(
	atom: Atom, 
	toLedgerAndSignItWithKeyAtPath bip32Path: BIP32Path
) -> ECDSASignature {

	var particleFields: [ParticleFieldMetadata] = calculateMetaDataAboutRelevantFieldsIn(upParticles: atom.upParticles())

	var remainingBytesInAtom: [Byte] = atom.dsonEncodedData()

	// Send initial "setup" packet
	
	let atomByteCount = remainingBytesInAtom.count
	sendToLedger(
		p1: atom.spunParticles(spin: .up).count,
		p2: atom.transferrableTokensParticles(spin: .up).count,
		payload: bip32Path.data() + atomByteCount.data()
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
			sendToLedgerAtomBytes(count: particleField.byteCount)
		} else {
			let ledgerPayloadMaxSize = 255
			result = sendToLedgerAtomBytes(count: min(ledgerPayloadMaxSize, nextRelevantEnd - numberOfAtomBytesSent))
		}
	}
	guard let signatureFromLedger = result else { fatalError("Expected signature from Ledger") }

	return ECDSASignature(bytes: signatureFromLedger)
}
```

## MetaData

### Creating MetaData

Swift inspired Pseudocode below constructs a `ParticleMetaData` being a struct of 16 bytes with the four fields in order: `address, amount, serializer, tokenDefinitionReference`, we used to use this struct earlier but now we don't. We only send the fields indiviudall and never the `ParticleMetaData` as a whole.

```swift
func byteIntervalOf(field: Field, in particle: UpParticle) -> ByteInterval {
	particleCBOR := particle.cborHexString()
	fieldCBOR := field.name.cborHexString()

	return ByteInterval(
		startsAtByte: particleCBOR.indexOf(fieldCBOR),
		byteCount: particleCBOR.length
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
func encodeByteInterval(byteInterval: ByteInterval) -> ByteArray {
	BigEndian2BytesFromInt16(byteInterval.startsAtByte) || BigEndian2BytesFromInt16(byteInterval.byteCount)
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
    	// convert each `ByteInterval` into ByteArray, each 4 bytes long
    	.map(encodeByteInterval)
	    // concat the four ByteArrays together
    	.reduce( || ) 
}
```