#!/usr/bin/env python3
from ledgerblue.comm import getDongle
from ledgerblue.commException import CommException
from typing import List
import argparse
from enum import Enum
import struct
import math
import binascii
import json
import hashlib
import glob
import os
import time
from pathlib import Path

CommExceptionUserRejection = 0x6985


STREAM_LEN = 255 # Stream in batches of STREAM_LEN bytes each.

def bip32_path_big_endian_encoded():
	# return b"\x80000002" + struct.pack(">I", 1, 3)
	return bytes.fromhex("800000020000000100000003")


def __chunks(lst, n):
	"""Yield successive n-sized chunks from lst."""
	for i in range(0, len(lst), n):
		yield lst[i:i + n]


def chunks(lst, n):
	return list(__chunks(lst, n))

class ByteInterval(object):
	def __init__(self, bytes: bytearray):

		assert len(bytes) == 4
		def nextInt16() -> int:
			nonlocal bytes
			two_bytes = bytes[0:2]
			integer = struct.unpack('>h', two_bytes)[0]
			bytes = bytes[2:]
			return integer

		self.startsAtByte = nextInt16()
		self.byteCount = nextInt16()
		assert len(bytes) == 0

	def __repr__(self):
		return f"@{self.startsAtByte}#{self.byteCount}"


class ParticleMetaData(object):
	def __init__(self, bytes: bytearray):
		assert len(bytes) == 20
		bytes_copy = bytes.copy()

		def nextInterval() -> ByteInterval:
			nonlocal bytes
			interval = ByteInterval(bytes[0:4])
			bytes = bytes[4:]
			return interval

		self.particleItself = nextInterval()
		self.addressByteInterval = nextInterval()
		self.amountByteInterval = nextInterval()
		self.serializerByteInterval = nextInterval()
		self.tokenDefinitionReferenceByteInterval = nextInterval()
		assert len(bytes) == 0
		self.bytes = bytes_copy
		assert len(self.bytes) == 20

	def __repr__(self):
		return f"⚛{self.particleItself}: ({self.addressByteInterval}, {self.amountByteInterval}, {self.serializerByteInterval}, {self.tokenDefinitionReferenceByteInterval})\nraw: {self.bytes.hex()}\n"

	def start_index_in_atom(self) -> int:
		return self.particleItself.startsAtByte

	def end_index_in_atom(self) -> int:
		return self.start_index_in_atom() + self.particleItself.byteCount

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

	# [ByteInterval][
	#     particleItself,
	# 	  addressByteInterval,
	# 	  amountByteInterval,
	# 	  serializerByteInterval,
	# 	  tokenDefinitionReferenceByteInterval
	# ]
	def __particle_meta_data(self) -> bytearray:
		return bytearray.fromhex(self.atomDescription['particleSpinUpMetaDataHex'])

	def particle_meta_data_list(self) -> List[ParticleMetaData]:
		particle_meta_data_list_ = chunks(self.__particle_meta_data(), 20)
		assert len(particle_meta_data_list_) == self.total_number_of_up_particles()
		return list(map(lambda b: ParticleMetaData(b), particle_meta_data_list_))

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

	def total_number_of_up_particles(self) -> int:
		return self.up_particles_dict()['totalCount']

	def number_of_transferrable_tokens_particles_with_spin_up(self) -> int:
		return self.up_particles_dict().get('transferrableTokensParticles', 0)

	def contains_non_transfer_data(self) -> bool:
		return (self.total_number_of_up_particles() - self.number_of_transferrable_tokens_particles_with_spin_up()) > 0

	def apdu_prefix_initial_payload(self, skipConfirmation: bool) -> bytearray:
		# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
		CLA = bytes.fromhex("AA")
		INS = b"\x02" # `02` is command "SIGN_ATOM"
		P1 = struct.pack(">B", self.total_number_of_up_particles())
		P2 = struct.pack(">B", self.number_of_transferrable_tokens_particles_with_spin_up())
		if skipConfirmation:
			raise "Not supported."

		return CLA + INS + P1 + P2

	def particle_group_count(self) -> int:
		return self.atomDescription['particleGroupCount']



def apdu_prefix_particle_metadata(is_particle_meta_data: bool) -> bytearray:
		CLA = bytes.fromhex("AA")
		INS = b"\x02" # `02` is command "SIGN_ATOM"
		flag = 3 if is_particle_meta_data else 4
		P1 = struct.pack(">B", flag)
		P2 = b"\x00"
		return CLA + INS + P1 + P2

def send_large_atom_to_ledger_in_many_chunks(vector: TestVector, skipConfirmation: bool) -> bool:
	"""
	Returns true if user did sign the atom and if the signature matches the expected one specified
	in the TestVector 'vector'
	"""

	letDongleOutputDebugPrintStatements = False
	dongle = getDongle(debug=letDongleOutputDebugPrintStatements)

	print(
		"""
🚀 Streaming Atom from vector to Ledger:
Atom byte count: #{}bytes
Particle groups: #{}
Particles with spin UP: #{}
Contains non transfer data: {}
		""".format(
			vector.atom_byte_count(),
			vector.particle_group_count(),
			vector.up_particles_dict(),
			vector.contains_non_transfer_data()
		)
	)

	bip_32_path_bytes = bip32_path_big_endian_encoded()
	# particles_meta_data_bytes = vector.particle_meta_data()
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

	prefix = vector.apdu_prefix_initial_payload(skipConfirmation=skipConfirmation)

	payload = bip_32_path_bytes + atom_byte_count_encoded

	print("Sending payload: " + payload.hex())


	L_c = bytes([len(payload)])
	apdu = prefix + L_c + payload

	result = dongle.exchange(apdu)

	print(f"got result back from Ledger for intial payload={result}")

	count_bytes_sent_to_ledger = 0

	# chunk_index = 0
	# number_of_chunks_to_send = int(math.ceil(atom_byte_count / STREAM_LEN))
	# print(f"Atom will be sent in #chunks: {number_of_chunks_to_send}")

	atom_bytes_chunked = atom_bytes.copy()

	particleMetaDataList = vector.particle_meta_data_list()
	particleMetaDataSize = len(particleMetaDataList)
	particleMetaDataSent = 0

	def sendToLedger(prefix: bytearray, payload: bytearray) -> bool:
		nonlocal result
		payload_size = len(payload)
		L_c = bytes([payload_size])
		apdu = prefix + L_c + payload
		try:
			result = dongle.exchange(apdu)
			return True # success
		except CommException as commException:
			if commException.sw == CommExceptionUserRejection:
				print("🙅🏿‍♀️ You rejected the atom...Aborting vector.")
				dongle.close()
				return False # fail
			else:
				raise commException # unknown error, interrupt exection and propage the error.


	def sendToLedgerParticleMetaData(particleMetaData: ParticleMetaData):
		print(f"Sending particle metadata to Ledger: {particleMetaData}")

		particle_start = particleMetaData.start_index_in_atom()
		if count_bytes_sent_to_ledger > particle_start:
			raise RuntimeError("FATAL ERROR! Flawed logic in this Python script. Sending ParticleMetaData which 'startsAt={particle_start}', however we have already sent #{count_bytes_sent_to_ledger} bytes to the Ledger. Thus the Ledger has missed some relevant bytes for parsing.")

		print(f"#{count_bytes_sent_to_ledger} sent to Ledger, sending MetaData about particle starting at: {particle_start}")

		success = sendToLedger(
			prefix=apdu_prefix_particle_metadata(True),
			payload=particleMetaData.bytes
		)
		if not success:
			raise RuntimeError("Failed sending meta data to Ledger")


	def sendToLedgerAtomBytes(atomBytes: bytearray):
		byteCount = len(atomBytes)
		w_sta = count_bytes_sent_to_ledger
		w_end = w_sta + byteCount
		print(f"Sending atom bytes to ledger - window [{w_sta}-{w_end}] (#{byteCount}), bytes:\n")
		print(atomBytes.hex())
		success = sendToLedger(
			prefix=apdu_prefix_particle_metadata(False),
			payload=atomBytes
		)

		if not success:
			raise RuntimeError("Failed sending atom bytes to Ledger")
	
	# Keep streaming data into the device till we run out of it.
	while count_bytes_sent_to_ledger < atom_byte_count:
		print(f"len(particleMetaDataList)={len(particleMetaDataList)}")
		nextRelevantEnd = atom_byte_count if len(particleMetaDataList) == 0 else particleMetaDataList[0].start_index_in_atom()
		nextParticleMetaData = particleMetaDataList[0] if len(particleMetaDataList) else None


		if not nextParticleMetaData is None and count_bytes_sent_to_ledger == nextParticleMetaData.start_index_in_atom():
			sendToLedgerParticleMetaData(nextParticleMetaData)
			particleMetaDataSent += 1
			particleMetaDataList.pop(0)
			print(f"Finished sending ParticleMetaData: {particleMetaDataSent}/{particleMetaDataSize}")
		else:
			count = min(STREAM_LEN, nextRelevantEnd - count_bytes_sent_to_ledger)
			chunk = atom_bytes_chunked[0:count]
			atom_bytes_chunked = atom_bytes_chunked[count:]
			sendToLedgerAtomBytes(chunk)
			count_bytes_sent_to_ledger += count

		print(f"result: {result.hex()}")
	

	print(f"🔮 Finished streaming all chunks to the ledger.\n💡 Expected Hash: {vector.expected_hash_hex()}\nWaiting for your to press the Ledger's buttons...")

	signature_from_ledger_device = result.hex()
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
	seconds_to_sleep = 5
	print(f"(sleeping {seconds_to_sleep} seconds)\n")
	time.sleep(seconds_to_sleep)
	return True

scenario_A_vector_name = 'no_data_single_transfer_small_amount_no_change'
scenario_B_vector_name = 'data_single_transfer_small_amount_no_change'
scenario_C_vector_name = 'data_multiple_transfers_small_amounts_with_change_unique'
scenario_D_vector_name = 'data_no_transfer_message_action'

class Scenario(Enum):
	A = 'A'
	B = 'B'
	C = 'C'
	D = 'D'

	def vector_name(self) -> str:
		if self == Scenario.A:
			return scenario_A_vector_name
		elif self == Scenario.B: 
			return scenario_B_vector_name
		elif self == Scenario.C: 
			return scenario_C_vector_name
		elif self == Scenario.D:
			return scenario_D_vector_name
		else:
			raise "Invalid case" 


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Stream CBOR encoded atom to Ledger for signing.")
	
	# parser.add_argument(
	# 	'--inputAtomVector', 
	# 	'-i', 
	# 	default='./vectors/sign_atom/huge_atom.json',
	# 	type=str, 
	# 	help='Path to JSON file containing test vector with CBOR encoded Atom, the particle meta data, description of atom contents and expected hash and signature.\n\nDefaults to %(default)',
	# 	metavar='FILE'
	# )

	# parser.add_argument(
	# 	'--scenario', 
	# 	'-s', 
	# 	default='A',
	# 	type=str, 
	# 	help='test scenario\nDefaults to %(default)',
	# 	metavar='FILE'
	# )

	parser.add_argument('--scenario', '-s', type=Scenario, choices=Scenario)

	# # parser.add_argument('--skipConfirmation', action='store_true')

	parser.add_argument('--all', action='store_true')


	args = parser.parse_args()
	skipConfirmation = False #args.skipConfirmation
	# print(f"skipConfirmation: {skipConfirmation}")
	if args.all:
		print("🚀 Testing all test vectors...")

		source_file_dir = Path(__file__).parent.absolute()
		vectors_dir = source_file_dir.joinpath("vectors", "sign_atom")

		for vector_file_path in vectors_dir.rglob("*.json"):   
			with open(vector_file_path) as json_file:
				print(f"Found test vector in file: {json_file.name}")
				vector = TestVector(json_file.read())
				did_sign_and_signature_matches = send_large_atom_to_ledger_in_many_chunks(vector=vector, skipConfirmation=skipConfirmation)
				if not did_sign_and_signature_matches:
					print("\n🛑 Interrupting testing of all vectors since you rejected the last atom, or signature did not match the expected one?\bBye bye!")
					break

	elif args.scenario:
		scenario = args.scenario
		vector_name = scenario.vector_name() + ".json"
		source_file_dir = Path(__file__).parent.absolute()
		vectors_dir = source_file_dir.joinpath("vectors", "sign_atom")
		json_file_path = vectors_dir.joinpath(vector_name)
		print(f"Running scenario={scenario}, vector named: {vector_name}, json_file_path: {json_file_path}")

		with open(json_file_path) as json_file:
			vector = TestVector(json_file.read())
			send_large_atom_to_ledger_in_many_chunks(vector=vector, skipConfirmation=skipConfirmation)
	else:
		raise RuntimeError("Invalid args={args}") 
