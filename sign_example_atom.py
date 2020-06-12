#!/usr/bin/env python3

from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from typing import List
import argparse
import struct
import math
import binascii
import json
import hashlib
import glob
import os
from pathlib import Path

CommExceptionUserRejection = 0x6985


STREAM_LEN = 255 # Stream in batches of STREAM_LEN bytes each.

def bip32_path_big_endian_encoded():
	# return b"\x80000002" + struct.pack(">I", 1, 3)
	return bytes.fromhex("800000020000000100000003")


class TestVector(object):
	def __init__(self, j):
		self.__dict__ = json.loads(j)

	def description(self) -> str:
		return self.descriptionOfTest

	def transfers_human_readable(self) -> str:
		return self.transfersHumanReadable

	def addresses(self) -> List[str]:
		return self.atomDescription['allAddresses']

	# The private key for BIP32 path: <44'/536'/2'/1/3>
	# using mnemonic: <equip will roof matter pink blind book anxiety banner elbow sun young>
	def alice_private_key(self) -> str:
		return self.expected['privateKeyAlice']

	# ByteInterval of the following fields in the following order:
	# [
	# 	  addressByteInterval,
	# 	  amountByteInterval,
	# 	  serializerByteInterval,
	# 	  tokenDefinitionReferenceByteInterval
	# ]
	def particle_meta_data(self) -> bytearray:
		return bytearray.fromhex(self.atomDescription['particleSpinUpMetaDataHex'])

	def cbor_encoded_hex(self) -> str:
		return self.atomDescription['cborEncodedHex']

	def atom_cbor_encoded(self) -> bytearray:
		return bytearray.fromhex(self.cbor_encoded_hex())

	def atom_byte_count(self) -> int:
		return len(self.cbor_encoded_hex())/2

	def expected_hash_hex(self) -> str:
		return self.expected['shaSha256HashOfAtomCborHex']

	def expected_signature_rs_hex(self) -> str:
		return self.expected['signatureRSOfAtomHashHex']

	def expected_signature_DER_hex(self) -> str:
		return self.expected['signatureDEROfAtomHashHex']

	def up_particles_dict(self):
		non_filtered_up_particle_count_dict = self.atomDescription['upParticles']
		return { key:value for (key,value) in non_filtered_up_particle_count_dict.items() if value > 0 }

	def number_of_up_particles(self) -> int:
		return self.up_particles_dict()['totalCount']

	def number_of_transferrable_tokens_particles_with_spin_up(self) -> int:
		return self.up_particles_dict().get('transferrableTokensParticles', 0)

	def contains_non_transfer_data(self) -> bool:
		return (self.number_of_up_particles() - self.number_of_transferrable_tokens_particles_with_spin_up()) > 0

	def apdu_prefix(self) -> bytearray:
		# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
		CLA = bytes.fromhex("AA")
		INS = b"\x02" # `02` is command "SIGN_ATOM"
		P1 = struct.pack(">B", self.number_of_up_particles())
		P2 = b"\x00"

		return CLA + INS + P1 + P2

	def particle_group_count(self) -> int:
		return self.atomDescription['particleGroupCount']


def send_large_atom_to_ledger_in_many_chunks(vector: TestVector) -> bool:
	"""
	Returns true if user did sign the atom and if the signature matches the expected one specified
	in the TestVector 'vector'
	"""
	
	letDongleOutputDebugPrintStatements = False
	dongle = getDongle(debug=letDongleOutputDebugPrintStatements)

	transfers_string_if_any = ""
	if vector.transfers_human_readable() != "":
		transfers_string_if_any = "Transfers: {}".format(vector.transfers_human_readable())

	print(
		"""
🚀 Streaming Atom from vector to Ledger:
'{}'
Atom byte count: #{}bytes
Particle groups: #{}
Particles with spin UP: #{}
Contains non transfer data: {}
{}
		""".format(
			vector.description(), 
			vector.atom_byte_count(),
			vector.particle_group_count(),
			vector.up_particles_dict(),
			vector.contains_non_transfer_data(),
			transfers_string_if_any
		)
	)

	bip_32_path_bytes = bip32_path_big_endian_encoded()
	particles_meta_data_bytes = vector.particle_meta_data()
	atom_bytes = vector.atom_cbor_encoded()

	hasher = hashlib.sha256()
	hasher.update(atom_bytes)
	first_digest = hasher.digest()
	hasher = hashlib.sha256()
	hasher.update(first_digest)
	hash_of_atom = hasher.hexdigest()

	if hash_of_atom != vector.expected_hash_hex():
		print("\n ☢️ Hash mismatch ☢️\n")
		print(f"Expected hash: {vector.expected_hash_hex()}") 
		print(f"But calculated hash: {hash_of_atom}")


	atom_byte_count = len(atom_bytes)
	assert(atom_byte_count == vector.atom_byte_count())

	atom_byte_count_encoded = struct.pack(">h", atom_byte_count) # `>` means big endian, `h` means `short` -> 2 bytes

	prefix = vector.apdu_prefix()

	payload = bip_32_path_bytes + atom_byte_count_encoded + particles_meta_data_bytes

	print("Sending payload: " + payload.hex())


	L_c = bytes([len(payload)])
	apdu = prefix + L_c + payload

	result = dongle.exchange(apdu)

	count_bytes_sent_to_ledger = 0

	chunk_index = 0
	number_of_chunks_to_send = int(math.ceil(atom_byte_count / STREAM_LEN))
	print(f"Atom will be sent in #chunks: {number_of_chunks_to_send}")

	atom_bytes_chunked = atom_bytes.copy()

	# Keep streaming data into the device till we run out of it.
	while count_bytes_sent_to_ledger < atom_byte_count:
		number_of_bytes_left_to_send = atom_byte_count - count_bytes_sent_to_ledger

		chunk = bytearray(0)
		if number_of_bytes_left_to_send > STREAM_LEN:
			chunk = atom_bytes_chunked[0:STREAM_LEN]
			atom_bytes_chunked = atom_bytes_chunked[STREAM_LEN:]
		else:
			chunk = atom_bytes_chunked
			atom_bytes_chunked = bytearray(0)

		chunk_size = len(chunk)
		print(f"Chunk {chunk_index+1}: [{count_bytes_sent_to_ledger}-{count_bytes_sent_to_ledger+chunk_size}]")
		L_c = bytes([chunk_size])
		count_bytes_sent_to_ledger += chunk_size
		apdu = prefix + L_c + chunk
		if (chunk_index+1) == number_of_chunks_to_send:
			print(f"🔮 Finished streaming all chunks to the ledger.\n💡 Expected Hash: {vector.expected_hash_hex()}\nWaiting for your to press the Ledger's buttons...")

		try:
			result = dongle.exchange(apdu)
		except CommException as commException:
			if commException.sw == CommExceptionUserRejection:
				print("🙅🏿‍♀️ You rejected the atom...Aborting vector.")
				dongle.close()
				return False
			else:
				raise commException # unknown error, interrupt exection and propage the error.
		chunk_index += 1


	signature_from_ledger_device_raw = result.hex()
	signature_from_ledger_device = signature_from_ledger_device_raw[2:]
	expected_signature_hex = vector.expected_signature_rs_hex()

	if expected_signature_hex == signature_from_ledger_device:
		print(f"\n✅ Awesome! Signature from ledger matches that from Swift library ✅\nSignature: {signature_from_ledger_device}")
	else:
		print("\n ☢️ Signature mismatch ☢️\n")
		print(f"Expected signature: {expected_signature_hex}") 
		print(f"But got signature from ledger: {signature_from_ledger_device}")
		return False

	print("⭐️ DONE! ⭐️")
	dongle.close()
	return True


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Stream CBOR encoded atom to Ledger for signing.")
	
	parser.add_argument(
		'--inputAtomVector', 
		'-i', 
		default='./vectors/02.json',
		type=str, 
		help='Path to JSON file containing test vector with CBOR encoded Atom, the particle meta data, description of atom contents and expected hash and signature.\n\nDefaults to %(default)',
		metavar='FILE'
	)

	parser.add_argument('--all', action='store_true')


	args = parser.parse_args()
	if args.all:
		print("🚀 Testing all test vectors...")

		source_file_dir = Path(__file__).parent.absolute()
		vectors_dir = source_file_dir.joinpath("vectors").joinpath("working")

		for vector_file_path in vectors_dir.rglob("*.json"):   
			with open(vector_file_path) as json_file:
				print(f"Found test vector in file: {json_file.name}")
				vector = TestVector(json_file.read())
				did_sign_and_signature_matches = send_large_atom_to_ledger_in_many_chunks(vector=vector)
				if not did_sign_and_signature_matches:
					print("\n🛑 Interrupting testing of all vectors since you rejected the last atom, or signature did not match the expected one?\bBye bye!")
					break

	else:
		json_file_path = args.inputAtomVector

		with open(json_file_path) as json_file:
			vector = TestVector(json_file.read())
			send_large_atom_to_ledger_in_many_chunks(vector=vector)
