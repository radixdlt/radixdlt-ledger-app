
func tryParsingAtomBytesIfNeeded() {
	while !parseAllParticles && hasMetaData {
		guard let field = nextFieldToParse else {
			cacheBytesIfNeeded()
			return
		}
		let parseFieldResult = parseField(field)
		switch parseFieldResult {
			case .partOfTransfer: 
				print("Parsed part of transfer, nothing to do")
			case .nonTransferDataFound:
				numberOfNonTransferParticlesIdentifier++
				if !hasAcceptedNonTransferData {
					hasAcceptedNonTransferData = true
					uiDisplay(
						promptUserToConfirm: .nonTransferData,
						callback: tryParsingAtomBytesIfNeeded
					)
					UX_BLOCK()
				}
				fatalError("NEVER REACHED")
			case .finishedParsingTransfer(let transfer):
				numberOfTransfersIdentified++
				if !transfer.isChangeBackToMe {
					uiDisplay(
						promptUserToConfirm: .transfer,
						callback: tryParsingAtomBytesIfNeeded
					)
					UX_BLOCK()
					fatalError("NEVER REACHED")
				}
			
		}
	}
}

func signAtomMainLoop() {
	while bytesReceived < atomSize {
		let newBytes, payloadType = ioExchange()

		switch payloadType {
			case .atomBytes:
				updateHash(bytes)
				updateAtomBytesWindow(newBytes)
				tryParsingAtomBytesIfNeeded()
			case .metaData:
				parseMetaData(bytes)
		}
	}

	assert(hash.isFinalized)

	if !hasAcceptedHash {
		UX_BLOCK()
		uiDisplay(
			promptUserToConfirm: .hash,
			callback: signAtomMainLoop
		)
		fatalError("NEVER REACHED")
	}

	assert(hashConfirmedAndSignedHash)

	print("DONE")

}