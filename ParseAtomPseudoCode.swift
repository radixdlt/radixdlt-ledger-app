// ====== RESULT =========
/// End result of a fully parsed atom
class Transaction {

	/// This is simply built up by just filtering up TransferrableTokensParticles with spun UP.
	class Transfer {
		let recipient: RadixAddress
		let amount: UInt256
		let token: RRI
	}

	/// Address our YOUR keypair.
	var sender: RadixAddress

	/// SHA2-256 hash of the CBOR bytes of the Atom
	var hashDigest: [Byte]

	/// A list of particle TYPES other than TransferrableTokensParticles found in the Atom - if any.
	var nonTransferrableTokensParticleTypesFoundInAtom: [Particle.Type]

	/// an array of transfers, excluding change back (which is an implementation detail for you as a user)
	var transfers: [Transfer]

}

// =========  PARSER ==========
// assumptions: No atom ca be larger than 65335 bytes


/// 'Global' offset, within the Atom, of some bytes.
/// Size: 4 bytes (2 * UInt16 (2))
struct AtomMemoryOffset {
	let startsAt: UInt16 // 2 bytes
	let byteCount: UInt16
}


/// We ONLY care about Spin UP particles (except for Spin DOWN particles used for hashing of course)
/// 
/// Size: MAX 240 bytes => 60 particles with Spin UP.
struct HostProvidedAtomParsingInstructions {

	/// Offset within Atom and length of a Particle that has `Spin` `Up`. (Ledger needs to trust wallet that this is not a particle with Spin down)
	//. This assumes that the FIRST key-value pair in the Particle is `"!serializer"` followed by the string value,
	/// being either "radix.particles.transferrable_tokens", "radix.particles.fixed_supply_token_definition" etc..
	struct SpunUpParticleLocation {
		/// Offset of Particle in Atom
		let atomMemoryOffset: AtomMemoryOffset
	}

	// This MUST be SORTED on `startsAt`
	let particlesWithSpinUp: [SpunUpParticleLocation]

}


final class SignAtomContext {
	var hasher = SHA256Hasher()
	var bip32Path: [UInt32]! // length 5
	// var atomParseInstructionsByteCount: UInt8!
	var atomByteCount: UInt16!
	var atomByteCountParsed: UInt16 = 0

	// Max 240 bytes, to be send as first chunk. 
	var atomParseInstructions = HostProvidedAtomParsingInstructions()

	var numberOfNonTransferrableTokensParticles = [String: UInt8]()
}

var signAtomContext = SignAtomContext()

final class Parser {

	// Entry point of the signAtom ledger action
	func signAtom(
		p1: UInt8,
		p2: UInt8,
		dataBuffer: [UInt8],
		dataLength: UInt16
	) {

		var dataBufferOffset = 0
		let atomParseInstructionsByteCount = p1

		// Read BIP32 path, three components to read, the components at bip32Path[0] and bip32Path[1] are hardcoded
		let bip32ComponentCountToRead = 3
		for i in 0..<bip32ComponentCountToRead {
			signAtomContext.bip32Path[i+2] = U4LE(dataBuffer, dataBufferOffset) // Read UInt32 (4 bytes)
			dataBufferOffset += 4
		}

		signAtomContext.atomByteCount = U2LE(dataBuffer, dataBufferOffset)
		dataBufferOffset += 2

		// should be max 60 particles
		let particleCount = atomParseInstructionsByteCount / sizeof(AtomMemoryOffset)

		for particleIndex in 0..<particleCount {
			let particleStartsAt: UInt16 = U2LE(dataBuffer, dataBufferOffset)
			dataBufferOffset += 2
			let particleByteCount: UInt16 = U2LE(dataBuffer, dataBufferOffset)
			dataBufferOffset += 2
			let particleAt = AtomMemoryOffset(startsAt: particleStartsAt, byteCount: particleByteCount)

			signAtomContext
				.atomParsingInstructions
				.particlesWithSpinUp
				.append(particleAt) // assumes Host sending the array has SORTED the particles on `startsAt`
		}
		// Finished parsing instructions for atom parsing

		// All meta data for Atom parsing setup => start parsing Atom
		parseAtom()
	}

	func parseAtom() {
		// repeat {
		// 	updateHashAndParseParticles()
		// } while signAtomContext.atomByteCountParsed < signAtomContext.atomByteCount
		while !updateHashAndParseParticles() {
			print("Has parsed: #\(signAtomContext.atomByteCountParsed) bytes")
			print("particles with spin up left: #\(signAtomContext.atomParseInstructions.particlesWithSpinUp.count)")
		}
	}

	// Returns `true` when done parsing the whole Atom, else false
	func updateHashAndParseParticles() -> Bool {
		let bytesLeftToRead = signAtomContext.atomByteCount - signAtomContext.atomByteCountParsed
		let chunkOffset = signAtomContext.atomByteCountParsed

		let numberOfBytesToRead = min(ledgerChunkByteCount, bytesLeftToRead)

		// Tell host computer to continue sending next chunk of bytes
		let chunk = read(byteCount: numberOfBytesToRead)

		// Update Hash
		let finalizeHash = bytesLeftToRead < ledgerChunkByteCount
		signAtomContext
			.hasher
			.update(chunk, shouldFinalize: finalizeHash)

		var chunkByteCountTakingIntoAccountPotentiallyCachedBytesFromLastChunk = numberOfBytesToRead

		// Prepend chunk with cached bytes from last chunk, if any. Must be done AFTER `hasher.update(readChunk)` (of course)
		if let cachedBytesFromLastChunk = signAtomContext.cachedBytesFromLastChunk {
			// Prepend
			chunk = signAtomContext.cachedBytesFromLastChunk + chunk
			// Chunk size
			chunkByteCountTakingIntoAccountPotentiallyCachedBytesFromLastChunk += signAtomContext.cachedBytesFromLastChunk.count
			// Reset state of cached bytes
			signAtomContext.cachedBytesFromLastChunk = nil
		}

		// CONTINUE with parsing of particles... 

		// Might be the case where multiple smaller partciles fit into the current chunk...
		var parsedByteCountInChunk = 0 // TODO use this 
		for particle in signAtomContext.atomParseInstructions.particlesWithSpinUp {
			let particleStartInAtom = particle.startsAt
			let particleEndInAtom = particleStartInAtom + particle.byteCount
			let particleStartInChunk = particleStartInAtom - signAtomContext.atomByteCountParsed 

			let particleBytesPotentiallCutOff = readBytes(
				source: &chunk, 
				offset: particleStartInChunk, 
				count: chunkByteCountTakingIntoAccountPotentiallyCachedBytesFromLastChunk - particleStartInChunk
			)

			if let serializer = parseBytesIntoSerializerValue(bytes: particleBytesPotentiallCutOff) {
				if serializer == "radix.particles.transferrable_tokens" {

					// 
					let chunkContainsWholeParticle: Bool = // TODO calculate this...

					if chunkContainsWholeParticle {
						// easy peasy, parse out: `amount`, `token`, `recipient`, `sender` from TransferrableTokensParticle

						// try continue looking at next particle
					} else {
						// Bah! Sometimes life is not easy... this TransferrableTokensParticle spans across multiple chunks
						// we can check `particle.byteCount`/255 (ledgerChunkByteCount)` to calculate how many chunks
						// and if we are extremely unlucky some of this data might be split across two chunks. Handle that

						// finished looking though all bytes in chunck, but not finished with all particles -> return false
						return false
					}

				} else {
					// Increase counter of non transferrable tokens particle
					numberOfNonTransferrableTokensParticles[serializer] += 1
					// remove particle
					signAtomContext
						.atomParsingInstructions
						.particlesWithSpinUp
						.removeFirst()
			
					signAtomContext.atomByteCountParsed + particle.byteCount

					// try continue looking at next particle
				}

			} else { // Assume we failed to read "serializer" because this chunk does not contain it all. 
				// We need to cache byte
				signAtomContext.cachedBytesFromLastChunk = particleBytesPotentiallCutOff
				signAtomContext.atomByteCountParsed -= particleBytesPotentiallCutOff.count
				
				// finished looking though all bytes in chunck, but not finished with all particles -> return false
				return false
			}
		}

	}

}


































