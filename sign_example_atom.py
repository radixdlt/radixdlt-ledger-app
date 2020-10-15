#!/usr/bin/env python3
from ledgerblue.comm import getDongle, Dongle
from ledgerblue.commException import CommException
from typing import List, Tuple, Optional
import argparse
from enum import Enum, unique
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


MAX_SIZE_PAYLOAD = 255 # Stream in batches of MAX_SIZE_PAYLOAD bytes each.

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
		self.bytes = bytes.copy()
		assert len(bytes) == 4
		def nextInt16() -> int:
			nonlocal bytes
			two_bytes = bytes[0:2]
			integer = struct.unpack('>h', two_bytes)[0]
			bytes = bytes[2:]
			return int(integer)

		self.startsAtByte = nextInt16()
		self.byteCount = nextInt16()
		assert len(bytes) == 0
		assert len(self.bytes) == 4

	def end_index(self) -> int:
		return self.startsAtByte + self.byteCount

	def __repr__(self):
		if self.byteCount == 0:
			assert self.startsAtByte == 0
			return "<EMPTY>"
		return f"[{self.startsAtByte}-{self.end_index()}] (#{self.byteCount} bytes)"

@unique
class ParticleFieldType(Enum)
	ADDRESS = 200# "address"
	AMOUNT = 201 #"amount"
	SERIALIZER = 202 # "serializer"
	TOKEN_DEFINITION_REFERENCE = 203 #"tokenDefinitionReference"

	def integer_identifier(self) -> int:
		return self.value

class ParticleField(object):
	def __init__(self, byte_interval: ByteInterval, field_type: ParticleFieldType):
		self.byte_interval = byte_interval

		assert self.byte_interval.byteCount <= MAX_SIZE_PAYLOAD
		self.field_type = field_type

	def start_index_in_atom(self) -> int:
		assert !self.has_been_sent_to_ledger
		return self.byte_interval.startsAtByte

	def is_empty(self) -> bool:
		return self.byte_interval.byteCount == 0

	def is_non_empty(self) -> bool:
		return not self.is_empty()


class ParticleMetaData(object):
	def __init__(self, bytes: bytearray):
		assert len(bytes) == 20

		def nextInterval() -> ByteInterval:
			nonlocal bytes
			interval = ByteInterval(bytes[0:4])
			bytes = bytes[4:]
			return interval

		self.particle_itself_intervals = nextInterval() # not used
		self.address_field = ParticleField(byte_interval: nextInterval(), field_type: ParticleFieldType.ADDRESS)

		self.amount_field = ParticleField(byte_interval: nextInterval(), field_type: ParticleFieldType.AMOUNT)
		self.serializer_field = ParticleField(byte_interval: nextInterval(), field_type: ParticleFieldType.SERIALIZER)
		self.token_definition_reference_field = ParticleField(byte_interval: nextInterval(), field_type: ParticleFieldType.TOKEN_DEFINITION_REFERENCE)
		assert len(bytes) == 0

	def __repr__(self) -> str:
		return """
  ⚛ Particle(
    address: 	{},
    amount: 	{},
    serializer:	{},
    tokenDefRef:{}
  )
""".format(
		self.address_field.byte_interval,
		self.amount_field.byte_interval,
		self.serializer_field.byte_interval,
		self.token_definition_reference_field.byte_interval
	)

	def all_particle_fields(self) -> List[ParticleField]:
		return [self.address_field, self.amount_field, self.serializer_field, self.token_definition_reference_field]

	def non_empty_particle_fields(self) -> List[ParticleField]:
		return list(map(lambda f: f.is_non_empty(), self.all_particle_fields()))

	def next_particle_field_or_none(self) -> Optional[ParticleField]:
		fields = self.particle_fields_not_yet_sent_to_ledger()
		return fields[0] if len(fields) > 0 else None

	def start_index_in_atom(self) -> int:
		return self.particleItself.startsAtByte

	def end_index_of_particle_itself_in_atom(self) -> int:
		return self.particleItself.end_index()

	def end_index_of_last_relevant_field_in_atom(self) -> int:
		if self.is_transferrable_tokens_particle():
			return self.tokenDefinitionReferenceByteInterval.end_index()
		else:
			return self.serializerByteInterval.end_index()

	def is_transferrable_tokens_particle(self) -> bool:
		is_ttp = self.addressByteInterval.byteCount > 0 or self.amountByteInterval.byteCount > 0 or self.tokenDefinitionReferenceByteInterval.byteCount > 0
		if is_ttp:
			assert self.addressByteInterval.byteCount > 0 and self.amountByteInterval.byteCount > 0 and self.tokenDefinitionReferenceByteInterval.byteCount > 0
		return is_ttp

class Transfer(object):
	def __init__(self, dict):
		self.address = dict['recipient'] # string
		self.amount = int(dict['amount'])
		self.is_transfer_change_back_to_sender = bool(dict['isChangeBackToUserHerself'])
		self.token_definition_reference = dict['tokenDefinitionReference'] # string


	def __repr__(self) -> str:
		return """
Transfer(
    address: 	{},
    amount: 	{},
    tokenDefRef:{}
)
""".format(
		self.address,
		self.amount,
		self.token_definition_reference
	)

class TestVector(object):
	def __init__(self, j):
		self.__dict__ = json.loads(j)

	def description(self) -> str:
		return self.descriptionOfTest

	def get_list_of_transfers(self) -> List[Transfer]:
		transfers_list = self.transfers
		transfers = list(map(lambda t: Transfer(t), transfers_list))
		assert len(transfers) == self.number_of_transferrable_tokens_particles_with_spin_up()
		return transfers

	def addresses(self) -> List[str]:
		return self.atomDescription['allAddresses']

	# The private key for BIP32 path: <44'/536'/2'/1/3>
	# using mnemonic: <equip will roof matter pink blind book anxiety banner elbow sun young>
	def alice_private_key(self) -> str:
		return self.expected['privateKeyAlice']

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

class PayloadIdentifier(Enum):
	ATOM_BYTES = 100
	PARTICLE_FIELD = 101

def apdu_prefix_helper(payload_identifier: PayloadIdentifier, particle_field_type: Optional[ParticleFieldType]=None) -> bytearray:
	CLA = bytes.fromhex("AA")
	INS = b"\x02" # `02` is command "SIGN_ATOM"
	P1 = struct.pack(">B", payload_identifier.value)
	P2 = b"\x00"
	if particle_field_type is not None:
		assert isinstance(particle_field_type, ParticleFieldType), 'Argument of wrong type!' 
		P2 = struct.pack(">B", particle_field_type.value)
	return CLA + INS + P1 + P2

def apdu_prefix_particle_field(particle_field: ParticleField) -> bytearray:
	return apdu_prefix_helper(
		payload_identifier=PayloadIdentifier.PARTICLE_FIELD, 
		particle_field_type=particle_field.field_type
	)

def apdu_prefix_atom_bytes() -> bytearray:
	return apdu_prefix_helper(payload_identifier=PayloadIdentifier.ATOM_BYTES)

def send_to_ledger(dongle: Dongle, prefix: bytearray, payload: bytearray) -> Tuple[bool, bytearray]:
	payload_size = len(payload)
	assert payload_size <= MAX_SIZE_PAYLOAD
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

	# class State(object):
	# 	def __init__(self):
	# 		self.type_of_last_field_sent_to_ledger = None # Optional[ParticleFieldType]

	def __init__(self, vector: TestVector, allow_debug_prints_by_this_program: bool=True, allow_debug_prints_from_ledger: bool=False):
		self.vector = vector
		self.dongle = getDongle(debug=allow_debug_prints_from_ledger)
		self.allow_debug_prints_by_this_program = allow_debug_prints_by_this_program
		self.remaining_atom_bytes = vector.atom_cbor_encoded().copy()
		self.count_bytes_sent_to_ledger = 0
		self.relevant_particle_fields_to_send_to_ledger = list(reduce(lambda pmd: pmd.non_empty_particle_fields(), vector.particle_meta_data_list()))
	
		last_field
		for field in self.relevant_particle_fields_to_send_to_ledger:
			assert isinstance(particle_fieldfield_type, ParticleField), "Wrong type, expected 'ParticleField'"
			assert field.byte_interval.byteCount > 0, "Expected field to be non empty"
			if last_field is not None:
				assert last_field.byte_interval.startsAtByte < field.byte_interval.startsAtByte, "Expected strictly increasing order of fields"
			last_field = field

		self.transfers_not_yet_identified = vector.get_list_of_transfers()

		self.last_particle_field_sent_to_ledger = None
		# self.state = State()


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

	def send_to_ledger_particle_field(self, particle_field: ParticleField) -> Tuple[bool, bytearray]:
	
		if self.allow_debug_prints_by_this_program:
			print(f"\nSending metadata about particle field to Ledger: {particle_field}")
	
		return send_to_ledger(
			dongle=self.dongle,
			prefix=apdu_prefix_particle_field(particle_field),
			payload=particle_field.bytes
		)
	
	
	def send_to_ledger_atom_bytes(self, payload: bytearray) -> Tuple[bool, bytearray]:
		atom_bytes = payload
		if self.allow_debug_prints_by_this_program:
			size_of_payload = len(atom_bytes)
			index_of_last_byte_being_sent = self.count_bytes_sent_to_ledger + size_of_payload
			print(f"Sending atom (size={self.atom_size_in_bytes()}) byte window to ledger: [{self.count_bytes_sent_to_ledger}-{	index_of_last_byte_being_sent}] (#{size_of_payload})")

		return send_to_ledger(
			dongle=self.dongle,
			prefix=apdu_prefix_atom_bytes(),
			payload=atom_bytes
		)

	def send_initial_setup_payload_to_ledger(self):
		(success, _) = send_to_ledger(
			self.dongle,
			prefix=vector.apdu_prefix_initial_payload(), 
			payload=bip32_path_big_endian_encoded() + struct.pack(">h", self.atom_size_in_bytes())
		)

		if not success:
			raise "Failed to send initial setup payload"

	# def next_particle_metadata_or_none(self) -> Optional[ParticleMetaData]:
	# 	if self.number_of_particle_metadata_left_to_send_to_ledger() == 0:
	# 		return None
	# 	else:
	# 		return self.list_of_particle_meta_data[0]

	def next_relevant_particle_field_or_none(self) -> Optional[ParticleField]:
		return self.relevant_particle_fields_to_send_to_ledger.pop(0)


	def stream_all_bytes_except_last_one___MEGA_UGLY_HACK___to_ledger(self) -> None:
		
		
		# Keep streaming data into the device till we run out of it.
		while self.count_bytes_sent_to_ledger < self.atom_size_in_bytes() - 1:
			next_particle_field = self.next_relevant_particle_field_or_none()
			should_send_particle_field_metadata = False
			if not next_particle_field is None:
			 	if self.count_bytes_sent_to_ledger == next_particle_field.start_index_in_atom()

			if should_send_particle_field_metadata:
				self.send_to_ledger_particle_field(
					payload=next_particle_field
				)
				self.last_particle_field_sent_to_ledger = next_particle_field

			else:
				next_relevant_end = None
				if not next_particle_field is None:
					# Send "non particle field bytes" up until start of next relevant field
					next_relevant_end = next_particle_field.start_index_in_atom()
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

				number_of_atom_bytes_to_send = min(MAX_SIZE_PAYLOAD, next_relevant_end - self.count_bytes_sent_to_ledger)

				# Debug print transfer at the right moment in time
				if self.last_particle_field_sent_to_ledger is not None:
					if self.last_particle_field_sent_to_ledger.end_index() <= (self.count_bytes_sent_to_ledger + number_of_atom_bytes_to_send):
						if self.last_particle_field_sent_to_ledger.field_type == ParticleField.TOKEN_DEFINITION_REFERENCE:
							transfer = self.transfers_not_yet_identified.pop(0)
							if not transfer.is_transfer_change_back_to_sender:
								print(f"Verify that transfer identified by ledger matches this:\n{transfer}\n")
						self.last_particle_field_sent_to_ledger = None	

				self.send_to_ledger_atom_bytes(
					payload=self.remaining_atom_bytes[0:number_of_atom_bytes_to_send], 
				)

				self.remaining_atom_bytes = self.remaining_atom_bytes[number_of_atom_bytes_to_send:]
				self.count_bytes_sent_to_ledger += number_of_atom_bytes_to_send

			if self.allow_debug_prints_by_this_program:
				percent = int(100 * self.count_bytes_sent_to_ledger/self.atom_size_in_bytes())
				print(f"Sent %{percent} of all atom bytes")

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

		return send_to_ledger(
			self.dongle,
			prefix=apdu_prefix_particle_metadata(False),
			payload=self.remaining_atom_bytes
		)


	def assert_correct_signature(self, signature_from_ledger: bytearray) -> bool:
		expected_signature_hex = self.vector.expected_signature_rs_hex()

		if expected_signature_hex == signature_from_ledger:
			print(f"✅ Awesome! Signature from ledger matches that from Swift library ✅\nSignature: {signature_from_ledger}\n")
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

		print( # looks like it is badly formatted, but in fact this results in correct output in terminal.
			"""
⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️
⭐️              ⭐️
⭐️     DONE     ⭐️
⭐️              ⭐️
⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️⭐️
\n\n
			"""
		)
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
				print(f"\n\n🗂 🗂 🗂\nFound test vector in file: {json_file.name}\ntesting it by streaming it to the ledger...\n📒 📒 📒\n")
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
