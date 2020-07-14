# Description

Signing a transaction (list of user actions), that is represented by an "Atom" on the Radix ledger, requires metadata about said atom in order for the Ledger to be able to sign it. To understand why one needs to know about Radix's Atom Model and the fact that we only ever have access to `~1.000` bytes of memory on the Ledger Nano S device. In order to parse tokens transfers, if any, found in an Atom, one needs to be able to:
1. DSON (CBOR) decode
2. Know type of particle before starting to parse it
3. Know location of relevant information (fields) of particle and byte count

Since our CBOR encoding **sorts** key-value pairs of "map" type (CBOR major type 5) in **lexicographical order** and since the key describing the type of particle is "serializer", it comes late in the encoding of said particle. Naive solution would be to put the serializer key-value first by changing it to "!serializer" or similar. However that only solves one problem - identifying the type of the particle. We still have the problem with large particles and the fact that the Ledger app only gets to see 255 bytes of chunk at any time. And any key or value of a field might be split across chunks. So instead of trying to CBOR decode every byte in the Atom we have chosen to use a different solution - we require any wallet interacting with our Ledger Nano S app to provide meta data about all relevant fields inside all particles with spin UP. That we we only need to try to CBOR decode the values found at these locations. And since we know the byte intervals of fields of interest before we recive the 255 bytes large chunks of data, we can also more easily implement logic taking care of edge cases where these relevant bytes are spread across chunks.

The meta data consists of four byte intervals, being a touple (`startsAtByte`, `byteCount`) each consisting of 2 bytes => the byte interval is thus 4 bytes. `4*4 bytes => 16` bytes per particle meta data. 

These byte intervals points to the following fields within the spun `UP` particle (`address`, `amount`, `serializer`, `tokenDefinitionReference`) - in that order - for being able to parse `TransferableTokensParticles` (TokenTransfers). 

In the case of **non**-`TransferrableTokensParticles` (e.g. `MessageParticle`, `RRIParticle` etc), you must provide four ZERO bytes for the fields: `address`, `amount`, `tokenDefinition`, but still provide the correct byte interval for `serializer` field. 

BigEndian hex for a  **non**-`TransferrableTokensParticle` could be: `0x0000000000000000dead001700000000`, i.e. all fields are zero except for `serializer` having value `0xdead0018` for a MessageParticle, where `0xdead` = 57005<sub>10</sub> is the location the field `serializer` - measure in number of bytes from start of Atom, and is bound by 65536 (max size of atom). Subsequently `0x0017` = 23<sub>10</sub> is number of characters in the string `"radix.particles.message"` (the serializer value).

# Pseudocode

## Creating MetaData

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

## MetaData Encoding

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