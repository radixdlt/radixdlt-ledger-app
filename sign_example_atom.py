#!/usr/bin/env python3
from ledgerblue.comm import getDongle, Dongle
from ledgerblue.commException import CommException
from typing import List, Tuple, Optional
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

	def end_index(self) -> int:
		return self.startsAtByte + self.byteCount

	def __repr__(self):
		if self.byteCount == 0:
			assert self.startsAtByte == 0
			return "<EMPTY>"
		return f"[{self.startsAtByte}-{self.end_index()}] (#{self.byteCount} bytes)"


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

	def __repr__(self) -> str:
		return """
  ⚛ Particle in atom {}, fields: (
    address: 	{},
    amount: 	{},
    serializer:	{},
    tokenDefRef:{}
  )
""".format(
		self.particleItself,
		self.addressByteInterval,
		self.amountByteInterval,
		self.serializerByteInterval,
		self.tokenDefinitionReferenceByteInterval
	)

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
		atom_bytes = bytearray.fromhex(self.cbor_encoded_hex())
		assert(len(atom_bytes) == self.atom_byte_count())
		return atom_bytes

	def atom_byte_count(self) -> int:
		return int(len(self.cbor_encoded_hex())/2)

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

	def apdu_prefix_initial_payload(self) -> bytearray:
		# https://en.wikipedia.org/wiki/Smart_card_application_protocol_data_unit
		CLA = bytes.fromhex("AA")
		INS = b"\x02" # `02` is command "SIGN_ATOM"
		P1 = struct.pack(">B", self.total_number_of_up_particles())
		P2 = struct.pack(">B", self.number_of_transferrable_tokens_particles_with_spin_up())
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

def sendToLedger(dongle: Dongle, prefix: bytearray, payload: bytearray) -> Tuple[bool, bytearray]:
	payload_size = len(payload)
	L_c = bytes([payload_size])
	apdu = prefix + L_c + payload
	try:
		result = dongle.exchange(apdu)
		return [True, result]
	except CommException as commException:
		if commException.sw == CommExceptionUserRejection:
			print("🙅🏿‍♀️ You rejected the atom...Aborting vector.")
			dongle.close()
			return [False, b''] # fail
		else:
			raise commException # unknown error, interrupt exection and propage the error.

class StreamVector(object):
	def __init__(self, vector: TestVector, allow_debug_prints_by_this_program: bool=True, allow_debug_prints_from_ledger: bool=False):
		self.vector = vector
		self.dongle = getDongle(debug=allow_debug_prints_from_ledger)
		self.allow_debug_prints_by_this_program = allow_debug_prints_by_this_program
		self.remaining_atom_bytes = vector.atom_cbor_encoded().copy()
		self.count_bytes_sent_to_ledger = 0
		self.list_of_particle_meta_data = vector.particle_meta_data_list()
		self.number_of_metadata_to_send = vector.total_number_of_up_particles()

	def atom_size_in_bytes(self) -> int:
		return self.vector.atom_byte_count()

	def print_vector(self) -> None:
		vector = self.vector
		print( # looks like it is badly formatted, but in fact this results in correct output in terminal.
			"""
\n\n\n\n\n\n\n
🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀
🚀                                🚀  
🚀  Streaming Atom to Ledger:     🚀	
🚀  # Bytes in Atom: 	{}	  🚀
🚀  # ParticleGroups:	{}	  🚀
🚀  # UpParticles: 	{}	  🚀
🚀                                🚀  
🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀🚀
			""".format(
				vector.atom_byte_count(),
				vector.particle_group_count(),
				vector.total_number_of_up_particles(),
			)
		)

	def number_of_particle_metadata_left_to_send_to_ledger(self) -> int:
		return int(len(self.list_of_particle_meta_data))

	def number_of_particle_metadata_sent_to_ledger(self) -> int:
		return self.number_of_metadata_to_send - self.number_of_particle_metadata_left_to_send_to_ledger()

	def sendToLedgerParticleMetaData(self, payload: ParticleMetaData) -> Tuple[bool, bytearray]:
		particle_meta_data = payload
	
		if self.allow_debug_prints_by_this_program:
			print(f"\nSending meta data about particle ({self.number_of_particle_metadata_sent_to_ledger() + 1}/{self.number_of_metadata_to_send}) to Ledger: {	particle_meta_data}")
	
		return sendToLedger(
			dongle=self.dongle,
			prefix=apdu_prefix_particle_metadata(True),
			payload=particle_meta_data.bytes
		)
	
	
	def sendToLedgerAtomBytes(self, payload: bytearray) -> Tuple[bool, bytearray]:
		atom_bytes = payload
		if self.allow_debug_prints_by_this_program:
			size_of_payload = len(atom_bytes)
			index_of_last_byte_being_sent = self.count_bytes_sent_to_ledger + size_of_payload
			print(f"Sending atom (size={self.atom_size_in_bytes()}) byte window to ledger: [{self.count_bytes_sent_to_ledger}-{	index_of_last_byte_being_sent}] (#{size_of_payload})")

		return sendToLedger(
			dongle=self.dongle,
			prefix=apdu_prefix_particle_metadata(False),
			payload=atom_bytes
		)

	def send_initial_setup_payload_to_ledger(self):
		(success, _) = sendToLedger(
			self.dongle,
			prefix=vector.apdu_prefix_initial_payload(), 
			payload=bip32_path_big_endian_encoded() + struct.pack(">h", self.atom_size_in_bytes())
		)

		if not success:
			raise "Failed to send initial setup payload"

	def next_particle_metadata_or_none(self) -> Optional[ParticleMetaData]:
		if self.number_of_particle_metadata_left_to_send_to_ledger() == 0:
			return None
		else:
			return self.list_of_particle_meta_data[0]


	def stream_all_bytes_except_last_one___MEGA_UGLY_HACK___to_ledger(self) -> None:
		
		
		# Keep streaming data into the device till we run out of it.
		while self.count_bytes_sent_to_ledger < self.atom_size_in_bytes() - 1:

			next_particle_metadata = self.next_particle_metadata_or_none()

			should_send_metadata = not next_particle_metadata is None and self.count_bytes_sent_to_ledger == next_particle_metadata.start_index_in_atom()


			if should_send_metadata:
				
				self.sendToLedgerParticleMetaData(
					payload=next_particle_metadata
				)

				self.list_of_particle_meta_data.pop(0)

			else:
				next_relevant_end = None
				if not next_particle_metadata is None:
					next_relevant_end = next_particle_metadata.start_index_in_atom()
				else:
					# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
					# !!!!!🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉!!!!!
					# !!!!!🐉🐉  BEWARE HERE BE DRAGONS  🐉🐉!!!!!
					# !!!!!🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉!!!!!
					# !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
	
					# This is the UGLIEST HACK in history of man
					# we stop streaming up until the last byte of 
					# the atom. We save that last byte until later
					# in order to workaround tricky internal state
					# of ledger device relating to 'io_exchange'
					# and blocking UX. Which is why we subtract `1`
					size_of_atom___MEGA_UGLY_HACK___minus_one = self.atom_size_in_bytes() - 1
					next_relevant_end = size_of_atom___MEGA_UGLY_HACK___minus_one

				number_of_atom_bytes_to_send = min(STREAM_LEN, next_relevant_end - self.count_bytes_sent_to_ledger)

				self.sendToLedgerAtomBytes(
					payload=self.remaining_atom_bytes[0:number_of_atom_bytes_to_send], 
				)

				self.remaining_atom_bytes = self.remaining_atom_bytes[number_of_atom_bytes_to_send:]
				self.count_bytes_sent_to_ledger += number_of_atom_bytes_to_send

			if self.allow_debug_prints_by_this_program:
				percent = int(100 * self.count_bytes_sent_to_ledger/self.atom_size_in_bytes())
				print(f"Sent %{percent} of all atom bytes and metadata about #{self.number_of_particle_metadata_sent_to_ledger()}/{self.number_of_metadata_to_send} particles.")

		print( # looks like it is badly formatted, but in fact this results in correct output in terminal.
			"""
🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮
🔮                                          🔮
🔮    FINISHED STREAMING ALL ATOM BYTES     🔮
🔮 	   _except_ for the FINAL byte      🔮
🔮         to the ledger device.            🔮
🔮                                          🔮
🔮 Due to internal state of ledger it was   🔮
🔮 easiest to send the last byte separatly. 🔮
🔮                                          🔮
🔮  🤷‍♂️🤷‍♂️🤷‍♂️ SORRY! 🤷‍♂️🤷‍♂️🤷‍♂️              🔮
🔮                                          🔮
🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮🔮
			"""
		)


	def send_last_atom_byte____MEGA_UGLY_HACK___to_ledger_and_return_signature_produced_by_ledger(self) -> Tuple[bool, bytearray]:

		assert len(self.remaining_atom_bytes) == 1
		assert self.count_bytes_sent_to_ledger == self.atom_size_in_bytes() - 1
		assert self.remaining_atom_bytes[0] == 0xFF

		print( # looks like it is badly formatted, but in fact this results in correct output in terminal.
			"""
🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉
🐉                                🐉
🐉 !!! BEWARE HERE BE DRAGONS !!! 🐉
🐉 Sending the last byte (=0xFF)  🐉
🐉 in the atom alone. The whole   🐉
🐉 solution depends on this.      🐉
🐉 (So sorry, please excuse me.)  🐉
🐉                                🐉
🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉🐉
			"""
		)

		print(f"\n💡 Expected Hash (verify on Ledger): {vector.expected_hash_hex()}\n")

		return sendToLedger(
			self.dongle,
			prefix=apdu_prefix_particle_metadata(False),
			payload=self.remaining_atom_bytes
		)


	def assert_correct_signature(self, signature_from_ledger: bytearray) -> bool:
		expected_signature_hex = self.vector.expected_signature_rs_hex()

		if expected_signature_hex == signature_from_ledger:
			print(f"\n✅ Awesome! Signature from ledger matches that from Swift library ✅\nSignature: {signature_from_ledger}")
			return True
		else:
			print("\n ☢️ Signature mismatch ☢️\n")
			print(f"Expected signature: {expected_signature_hex}") 
			print(f"But got signature from ledger: {signature_from_ledger}")
			return False


	def start(self) -> bool:
		"""
		Returns true if user did sign the atom and if the signature matches the expected one specified
		in the TestVector 'vector'
		"""
		self.print_vector()
		self.send_initial_setup_payload_to_ledger()
		self.stream_all_bytes_except_last_one___MEGA_UGLY_HACK___to_ledger()
		(success, signature_from_ledger_bytes) = self.send_last_atom_byte____MEGA_UGLY_HACK___to_ledger_and_return_signature_produced_by_ledger()
		if not success:
			print("Failed to get signature from ledger")
			return False

		self.dongle.close()

		if not self.assert_correct_signature(signature_from_ledger_bytes.hex()):
			return False

		print("⭐️ DONE! ⭐️")
		return True




def main_args_parser() -> argparse.ArgumentParser:
	parser = argparse.ArgumentParser(description="Stream CBOR encoded atom to Ledger for signing.")
	
	parser.add_argument(
		'--inputAtomVector', 
		'-i', 
		default='./vectors/sign_atom/huge_atom.json',
		type=str, 
		help='Path to JSON file containing test vector with CBOR encoded Atom, the particle meta data, description of atom contents and expected hash and signature.\n\nDefaults to %(default)',
		metavar='FILE'
	)
	parser.add_argument('--all', action='store_true')
	return parser




if __name__ == "__main__":
	parser = main_args_parser()
	args = parser.parse_args()
	if args.all:
		print("🥁 Testing all test vectors...")

		source_file_dir = Path(__file__).parent.absolute()
		vectors_dir = source_file_dir.joinpath("vectors", "sign_atom")

		for vector_file_path in vectors_dir.rglob("*.json"):   
			with open(vector_file_path) as json_file:
				print(f"Found test vector in file: {json_file.name}")
				vector = TestVector(json_file.read())
				stream_test = StreamVector(vector=vector)
				did_sign_and_signature_matches = stream_test.start()
				if not did_sign_and_signature_matches:
					print("\n🛑 Interrupting testing of all vectors since you rejected the last atom, or signature did not match the expected one?\bBye bye!")
					break

	else:
		json_file_path = args.inputAtomVector

		with open(json_file_path) as json_file:
			vector = TestVector(json_file.read())
			stream_test = StreamVector(vector=vector)
			did_sign_and_signature_matches = stream_test.start()
