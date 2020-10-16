#!/usr/bin/env python3
from ledgerblue.comm import getDongle, Dongle
from ledgerblue.commException import CommException
from typing import List, Tuple, Optional
import argparse
from enum import Enum, unique
import struct
import math
import base58
import binascii
import json
import hashlib
import glob
import os
from cbor2 import loads
from functools import reduce
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

		self.starts_at_byte = nextInt16()
		self.byte_count = nextInt16()
		assert len(bytes) == 0
		assert len(self.bytes) == 4

	def end_index(self) -> int:
		return self.starts_at_byte + self.byte_count

	def __repr__(self):
		if self.byte_count == 0:
			assert self.starts_at_byte == 0
			return "<EMPTY>"
		return f"[{self.starts_at_byte}-{self.end_index()}] (#{self.byte_count} bytes)"

@unique
class ParticleFieldType(Enum):
	ADDRESS = 200# "address"
	AMOUNT = 201 #"amount"
	SERIALIZER = 202 # "serializer"
	TOKEN_DEFINITION_REFERENCE = 203 #"tokenDefinitionReference"

	def integer_identifier(self) -> int:
		return self.value

	def __repr__(self):
		if self == ParticleFieldType.ADDRESS:
			return "Address"
		elif self == ParticleFieldType.AMOUNT:
			return "Amount"
		elif self == ParticleFieldType.SERIALIZER:
			return "Serializer"
		elif self == ParticleFieldType.TOKEN_DEFINITION_REFERENCE:
			return "TokenDefinitionReference"
		else:
			raise "Unknown field"

class ParticleField(object):
	def __init__(self, byte_interval: ByteInterval, field_type: ParticleFieldType):
		self.byte_interval = byte_interval

		assert self.byte_interval.byte_count <= MAX_SIZE_PAYLOAD
		self.field_type = field_type
		self.bytes = byte_interval.bytes

	def start_index_in_atom(self) -> int:
		return self.byte_interval.starts_at_byte

	def is_empty(self) -> bool:
		return self.atom_byte_count() == 0

	def is_non_empty(self) -> bool:
		return not self.is_empty()

	def atom_byte_count(self) -> int:
		return self.byte_interval.byte_count

	def __repr__(self):
		return "Field({}: {})".format(self.field_type, self.byte_interval)


class ParticleMetaData(object):
	def __init__(self, bytes: bytearray):
		assert len(bytes) == 20

		def nextInterval() -> ByteInterval:
			nonlocal bytes
			interval = ByteInterval(bytes[0:4])
			bytes = bytes[4:]
			return interval

		self.particle_itself_intervals = nextInterval() # not used
		self.address_field = ParticleField(byte_interval=nextInterval(), field_type=ParticleFieldType.ADDRESS)
		self.amount_field = ParticleField(byte_interval=nextInterval(), field_type=ParticleFieldType.AMOUNT)
		self.serializer_field = ParticleField(byte_interval=nextInterval(), field_type=ParticleFieldType.SERIALIZER)
		self.token_definition_reference_field = ParticleField(byte_interval=nextInterval(), field_type=ParticleFieldType.TOKEN_DEFINITION_REFERENCE)
		assert len(bytes) == 0

	def all_particle_fields(self) -> List[ParticleField]:
		return [self.address_field, self.amount_field, self.serializer_field, self.token_definition_reference_field]

	def non_empty_particle_fields(self) -> List[ParticleField]:
		return list(filter(lambda f: f.is_non_empty(), self.all_particle_fields()))

	def next_particle_field_or_none(self) -> Optional[ParticleField]:
		fields = self.particle_fields_not_yet_sent_to_ledger()
		return fields[0] if len(fields) > 0 else None

	def start_index_in_atom(self) -> int:
		return self.particleItself.starts_at_byte

	def end_index_of_particle_itself_in_atom(self) -> int:
		return self.particleItself.end_index()

	def end_index_of_last_relevant_field_in_atom(self) -> int:
		if self.is_transferrable_tokens_particle():
			return self.tokenDefinitionReferenceByteInterval.end_index()
		else:
			return self.serializerByteInterval.end_index()

	def is_transferrable_tokens_particle(self) -> bool:
		is_ttp = self.addressByteInterval.byte_count > 0 or self.amountByteInterval.byte_count > 0 or self.tokenDefinitionReferenceByteInterval.byte_count > 0
		if is_ttp:
			assert self.addressByteInterval.byte_count > 0 and self.amountByteInterval.byte_count > 0 and self.tokenDefinitionReferenceByteInterval.byte_count > 0
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

def flatten(itr):
	t = tuple()
	for e in itr:
		try:
			t += flatten(e)
		except:
			t += (e,)
	return t

# Please see column "Additional info" in table "CBOR Major types": https://radixdlt.atlassian.net/wiki/spaces/AM/pages/56557727/DSON+Encoding
class CBORByteStringType(Enum):
	ADDRESS = 0x04

	# Used for `amount` (uint256)
	AMOUNT = 0x05

	# Used for `token_definition_reference` (rri)
	TOKEN_DEFINITION_REFERENCE = 0x06

	def __repr__(self):
		if self == CBORByteStringType.ADDRESS:
			return "Address"
		elif self == CBORByteStringType.AMOUNT:
			return "UInt256 (Amount)"
		elif self == CBORByteStringType.TOKEN_DEFINITION_REFERENCE:
			return "RRI"
		else:
			raise "Unknown field"


def cbor_decode_bytes(particle_field: ParticleField, atom_bytes: bytearray):
	# print(f"\nCBOR decoding particle field={particle_field}, from bytes: {atom_bytes.hex()}\n")
	assert particle_field.atom_byte_count() == len(atom_bytes)
	decoded = loads(atom_bytes)
	if particle_field.field_type != ParticleFieldType.SERIALIZER:
		cbor_byte_prefix = decoded[0]
		decoded = decoded[1:]
		cbor_byte_string_type = CBORByteStringType(cbor_byte_prefix)

		if particle_field.field_type == ParticleFieldType.ADDRESS:
			assert cbor_byte_string_type == CBORByteStringType.ADDRESS, "Expected `cbor_byte_prefix == CBORByteStringType.ADDRESS`"
			decoded = str(base58.b58encode(decoded), "utf-8")
		elif particle_field.field_type == ParticleFieldType.AMOUNT:
			assert cbor_byte_string_type == CBORByteStringType.AMOUNT, "Expected `cbor_byte_prefix == CBORByteStringType.AMOUNT`"
			decoded = int(decoded.hex(), 16)
		elif particle_field.field_type == ParticleFieldType.TOKEN_DEFINITION_REFERENCE:
			assert cbor_byte_string_type == CBORByteStringType.TOKEN_DEFINITION_REFERENCE, "Expected `cbor_byte_prefix == CBORByteStringType.TOKEN_DEFINITION_REFERENCE`"
			decoded = str(decoded)
		else:
			raise "Unsupported case...."
	else:
		assert isinstance(decoded, str), "Expected string"

	# print(f"🧩 CBOR decoded result='{decoded}'")

	return decoded

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

		rel_fields = []
		particle_metadata_list = vector.particle_meta_data_list()
		for pmd in particle_metadata_list:
			rel_fields.extend(pmd.non_empty_particle_fields())
		self.relevant_particle_fields_to_send_to_ledger = rel_fields

		# print(f"\n\n🌱🌱🌱🌱🌱🌱🌱🌱🌱🌱\nThese are the expected fields to send to Ledger:\n\n")
		# for field in self.relevant_particle_fields_to_send_to_ledger:
		# 	print(f"{field}\n\n")
		# print("\n\n\n🌱🌱🌱🌱🌱🌱🌱🌱🌱🌱🌱\n")

		last_field = None
		for field in self.relevant_particle_fields_to_send_to_ledger:
			assert isinstance(field, ParticleField), "Wrong type, expected 'ParticleField'"
			assert field.byte_interval.byte_count > 0, "Expected field to be non empty"
			if last_field is not None:
				assert last_field.byte_interval.starts_at_byte < field.byte_interval.starts_at_byte, "Expected strictly increasing order of fields"
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

	def send_to_ledger_atom_bytes(self, atom_bytes: bytearray) -> Tuple[bool, bytearray]:
		byte_count = len(atom_bytes)
		if self.allow_debug_prints_by_this_program:
			index_of_last_byte_being_sent = self.count_bytes_sent_to_ledger + byte_count
			print(f"Sending atom (size={self.atom_size_in_bytes()}) byte window to ledger: [{self.count_bytes_sent_to_ledger}-{	index_of_last_byte_being_sent}] (#{byte_count})")


		if (self.count_bytes_sent_to_ledger + byte_count) == self.atom_size_in_bytes():
					print(f"\n💡 Expected Hash (verify on Ledger): {vector.expected_hash_hex()}\n")

		result = send_to_ledger(
			dongle=self.dongle,
			prefix=apdu_prefix_atom_bytes(),
			payload=atom_bytes
		)

		self.remaining_atom_bytes = self.remaining_atom_bytes[byte_count:]
		self.count_bytes_sent_to_ledger += byte_count

		return result

	def send_to_ledger_atom_bytes_count(self, byte_count: int) -> Tuple[bool, bytearray]:
		atom_bytes = self.remaining_atom_bytes[0:byte_count]
		return self.send_to_ledger_atom_bytes(atom_bytes)

	def send_initial_setup_payload_to_ledger(self):
		(success, _) = send_to_ledger(
			self.dongle,
			prefix=vector.apdu_prefix_initial_payload(), 
			payload=bip32_path_big_endian_encoded() + struct.pack(">h", self.atom_size_in_bytes())
		)

		if not success:
			raise "Failed to send initial setup payload"


	def stream_atom_to_ledger(self) -> None:
		result = None # Tuple[bool, bytearray] 
		
		# Keep streaming data into the device till we run out of it.
		while self.count_bytes_sent_to_ledger < self.atom_size_in_bytes():
			next_particle_field = self.relevant_particle_fields_to_send_to_ledger[0] if len(self.relevant_particle_fields_to_send_to_ledger) > 0 else None
			should_send_particle_field_metadata = False
			next_relevant_end = self.atom_size_in_bytes()
			if not next_particle_field is None:
				next_relevant_end = next_particle_field.start_index_in_atom()
				if self.count_bytes_sent_to_ledger == next_particle_field.start_index_in_atom():
					should_send_particle_field_metadata = True

			if should_send_particle_field_metadata:

				self.send_to_ledger_particle_field(next_particle_field)


				self.relevant_particle_fields_to_send_to_ledger.pop(0)
				self.last_particle_field_sent_to_ledger = next_particle_field

				particle_field_atom_byte_count = next_particle_field.byte_interval.byte_count

				particle_field_atom_bytes = self.remaining_atom_bytes[0:particle_field_atom_byte_count]
				decoded_atom_bytes = cbor_decode_bytes(next_particle_field, particle_field_atom_bytes)

				if next_particle_field.field_type == ParticleFieldType.TOKEN_DEFINITION_REFERENCE:
					transfer = self.transfers_not_yet_identified.pop(0)
					if not transfer.is_transfer_change_back_to_sender:
						print(f"  --> Verify that transfer identified by ledger matches this:\n{transfer}\n")
				elif next_particle_field.field_type == ParticleFieldType.SERIALIZER:
					serializer = decoded_atom_bytes 
					if not serializer == "radix.particle.transferrable_tokens_particle":
						print("  --> Found non transferrable tokens particle with serializer: '{serializer}', confirm on Ledger device?")	
				self.send_to_ledger_atom_bytes(particle_field_atom_bytes)

			else:
				number_of_atom_bytes_to_send = min(MAX_SIZE_PAYLOAD, next_relevant_end - self.count_bytes_sent_to_ledger)
				result = self.send_to_ledger_atom_bytes_count(number_of_atom_bytes_to_send)

			if self.allow_debug_prints_by_this_program:
				percent = int(100 * self.count_bytes_sent_to_ledger/self.atom_size_in_bytes())
				print(f"Sent %{percent} of all atom bytes")

		return result

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
		(success, signature_from_ledger_bytes) = self.stream_atom_to_ledger()
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
		default='./vectors/sign_atom/data_multiple_transfers_small_amounts_with_change_unique.json',
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
