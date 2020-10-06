struct ByteInterval {
	let startsAt: Int
	let byteCount: Int

	var endsWith: Int {
		startsAt + byteCount
	}
}

struct ParticleMetaData {
	let intervalOfParticleItself: ByteInterval
	
	let addressField: ByteInterval?
	let amountField: ByteInterval?
	let serializerField: ByteInterval
	let tokenDefinitionReferenceField: ByteInterval?
}

struct Transfer {
	var address: Any?
	var amount: Any?
	var hasSerializerBeenConfirmed: Bool
	var tokenDefRef: Any?
}

class Context {
	
	public var noReceivedBytes = 0
	public var noCachedBytes = 0
	
	var Transfer: Transfer!
	let hash: Hash
	var particleMetaData: ParticleMetaData?
}

func numberOfOverlappingBytes(_ a: ByteInterval, _ b: ByteInterval) -> Int {
	return max(
		0, min(a.endsWith, b.endsWith) - max(a.startsAt, b.startsAt)
	)
}

enum FieldType {
	case fieldTypeAddress
	case fieldTypeAmount
	case fieldTypeSerializer
	case fieldTypeTokenDefRef
}

func parseField(interval: ByteInterval, fieldType: FieldType) {
	let cborValue = parseCbor(interval)
	switch cborValue {
		case .byteString:

		case .utf8String:
			assert(fieldType == .fieldTypeSerializer)
	}
}

func parseBytesFromHostMachine(ctx: Context) {
	let numberOfNewlyReceivedAtomBytes = receiveBytesFromHostMachine()
	guard numberOfNewlyReceivedAtomBytes > 0 else {
		return // NOT atom bytes
	}	
	ctx.noReceivedBytes += numberOfNewlyReceivedAtomBytes
	updateHash()
	guard let particleMetaData = ctx.particleMetaData else {
		return
	}
	var currentAtomSlice: ByteInterval = .init(
		startsAt: ctx.noReceivedBytes - ctx.noCachedBytes,
		byteCount: ctx.noCachedBytes + numberOfNewlyReceivedAtomBytes
	)
	ctx.noOfCachedBytes = 0 // TOO EARLY ?

	func doesCurrentAtomSliceContainParticlesBytes() -> Bool {
		let overlappingBytes = numberOfOverlappingBytes(
			currentAtomSlice, particleMetaData.intervalOfParticleItself
		)
		return overlappingBytes > 0
	}
	
	func intervalOfNextFieldToParse(inout fieldType: FieldType?) -> ByteInterval? {
		var doneWithAtomSlice = false
		func innerIntervalOfNextFieldToParse(interval: ByteInterval?) -> ByteInterval? {
			guard let interval = interval else { return nil }

			guard currentAtomSlice.endsWith >= interval.endsWith else {
				print("`currentAtomSlice.endsWith < interval.endsWith` => caching bytes!")
				ctx.noCachedBytes = currentAtomSlice.byteCount
				doneWithAtomSlice = true
				return nil
			}

			guard 
				currentAtomSlice.startsAt <= interval.startsAt
			else {
				print("interval not in atom slice, maybe another interval for the same particle? SHOULD WE UPDATE currentAtomSlice.startsAt???")
				return nil
			}

			if currentAtomSlice.startsAt != interval.startsAt {
				print("`currentAtomSlice.startsAt != interval.startsAt` => setting `currentAtomSlice.startsAt := interval.startsAt` and decreasing `currentAtomSlice.byteCount`")
				currentAtomSlice.byteCount -= (interval.startsAt - currentAtomSlice.startsAt)
				currentAtomSlice.startsAt = interval.startsAt
			}
		
			assert(currentAtomSlice.byteCount >= interval.byteCount)
			return interval
		}
		fieldType = .fieldTypeAddress
		for interval in [
			particleMetaData.addressField,
			particleMetaData.amountField,
			particleMetaData.serializerField,
			particleMetaData.tokenDefinitionReferenceField
		] { 
			if doneWithAtomSlice {
				break
			}
			if let intervalOfNextField = innerIntervalOfNextFieldToParse(interval) {
				return intervalOfNextField
			} else {
				fieldType += 1
			}
		}
		print("No nextField given currentAtomSlice to parse...")
		fieldType = nil
		return nil
	}
	
	// Parse atom bytes, driven by ParticleFields from ParticleMetaData	
	while doesCurrentAtomSliceContainParticlesBytes() {
		var fieldType: FieldType = .fieldTypeAddress
		guard let nextField = intervalOfNextFieldToParse(&fieldType) else {
			return
		}
		
		parseField(interval: nextField, type: fieldType)
	}
}