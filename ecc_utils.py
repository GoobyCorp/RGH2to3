#!/usr/bin/env python3

from enum import Enum
from io import BytesIO
from typing import Union
from argparse import ArgumentParser
from struct import pack, unpack_from

class BLOCK_TYPE(Enum):
	SMALL = 0x0
	BIG_ON_SMALL = 0x1
	BIG = 0x02
	UNKNOWN = 0x03

def get_block_type(page_20_spare_data: Union[bytes, bytearray]) -> BLOCK_TYPE:
	if page_20_spare_data[0] == 0xFF:
		# print("Detected 256/512MB Big Block Flash")
		return BLOCK_TYPE.BIG
	elif page_20_spare_data[5] == 0xFF:
		if page_20_spare_data[:2] == b"\x01\x00":
			# print("Detected 16/64MB Small Block Flash")
			return BLOCK_TYPE.SMALL
		elif page_20_spare_data[:2] == b"\x00\x01":
			# 3print("Detected 16/64MB Big on Small Flash")
			return BLOCK_TYPE.BIG_ON_SMALL
		else:
			# print("Can't detect flash type")
			return BLOCK_TYPE.UNKNOWN
	else:
		# print("Can't detect flash type")
		return BLOCK_TYPE.UNKNOWN

def calcecc(data: Union[bytes, bytearray]) -> bytes:
	assert len(data) == 0x210
	val = 0
	for i in range(0x1066):
		if not i & 31:
			v = ~unpack_from("<I", data, i // 8)[0]
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	val = ~val
	return data[:-4] + pack("<I", ((val << 6) & 0xFFFFFFFF) ^ (data[-4] & 0x3F))

def addecc(data: Union[bytes, bytearray], block: int = 0, block_type: BLOCK_TYPE = BLOCK_TYPE.BIG_ON_SMALL):
	with BytesIO(data) as rbio, BytesIO() as wbio:
		while rbio.tell() < len(data):
			d = rbio.read(0x200)

			if block_type == BLOCK_TYPE.BIG_ON_SMALL:
				d += pack("<BI3B8x", 0, block // 32, 0xFF, 0, 0)
			elif block_type == BLOCK_TYPE.BIG:
				d += pack("<BI3B8x", 0xFF, block // 256, 0, 0, 0)
			elif block_type == BLOCK_TYPE.SMALL:
				d += pack("<I4B8x", block // 32, 0, 0xFF, 0, 0)
			else:
				raise ValueError("Block type not supported")
			d = calcecc(d)
			block += 1
			wbio.write(d)
		return wbio.getvalue()

def unecc(image: Union[bytes, bytearray]) -> bytes:
	with BytesIO(image) as rbio, BytesIO() as wbio:
		for i in range(len(image) // 528):
			wbio.write(rbio.read(512))
			rbio.seek(16, 1)  # skip 16 bytes
		return wbio.getvalue()

def verify(data: Union[bytes, bytearray], page: int = 0, off_8: Union[bytes, bytearray] = b"\x00" * 2):
	block_type = get_block_type(page_20_spare_data=data[0x4400:0x4410])
	if block_type == BLOCK_TYPE.UNKNOWN:
		print("aborting...")
		return
	with BytesIO(data) as rbio:
		while rbio.tell() < len(data):
			d = rbio.read(0x200)
			file_ecc = rbio.read(0x10)
			if block_type == BLOCK_TYPE.BIG_ON_SMALL:
				block_num = page // 32
				fs_seq_0 = file_ecc[0]
				fs_seq_1 = file_ecc[3]
				fs_seq_2 = file_ecc[4]
				fs_seq_3 = file_ecc[6]
				fs_size_1 = file_ecc[7]
				fs_size_0 = file_ecc[8]
				fs_page_count = file_ecc[9]
				fs_unused_1 = b"\x00\x00"
				fs_block_type = file_ecc[12] & 0x3f
				ecc_2_1_0 = b"\x00\x00\x00"
				d += pack("<BH7B2sB3s", fs_seq_0, block_num, fs_seq_1, fs_seq_2, 0xFF, fs_seq_3, fs_size_1, fs_size_0, fs_page_count, fs_unused_1, fs_block_type, ecc_2_1_0)
			elif block_type == BLOCK_TYPE.BIG:
				block_num = page // 256
				fs_seq_2 = file_ecc[3]
				fs_seq_1 = file_ecc[4]
				fs_seq_0 = file_ecc[5]
				fs_unused_1 = 0x00
				fs_size_1 = file_ecc[7]
				fs_size_0 = file_ecc[8]
				fs_page_count = file_ecc[9]
				fs_unused_2 = b"\x00\x00"
				fs_block_type = file_ecc[12] & 0x3f
				ecc_2_1_0 = b"\x00\x00\x00"
				d += pack("<BH7B2sB3s", 0xFF, block_num, fs_seq_2, fs_seq_1, fs_seq_0, fs_unused_1, fs_size_1, fs_size_0, fs_page_count, fs_unused_2, fs_block_type, ecc_2_1_0)
			elif block_type == BLOCK_TYPE.SMALL:
				block_num = page // 32
				fs_seq_0 = file_ecc[2]
				fs_seq_1 = file_ecc[3]
				fs_seq_2 = file_ecc[4]
				fs_seq_3 = file_ecc[6]
				fs_size_1 = file_ecc[7]
				fs_size_0 = file_ecc[8]
				fs_page_count = file_ecc[9]
				fs_unused_1 = b"\x00\x00"
				fs_block_type = file_ecc[12] & 0x3f
				ecc_2_1_0 = b"\x00\x00\x00"
				d += pack("<H8B2sB3s", block_num, fs_seq_0, fs_seq_1, fs_seq_2, 0xFF, fs_seq_3, fs_size_1, fs_size_0, fs_page_count, fs_unused_1, fs_block_type, ecc_2_1_0)
			else:
				raise ValueError("Block type not supported")
			d = calcecc(d)
			calc_ecc = d[0x200:]
			if file_ecc[:12] == b"\x00" * 12:
				print(f"Page 0x{page:02X} is bad")
			elif calc_ecc != file_ecc and file_ecc[:12] != b"\xff" * 12:
				print(f"ECC mismatch on page 0x{page:02X} (0x{(page + 1) * 0x210 - 0x10:02X})")
				print(f"File: {file_ecc.hex()} Calculated: {calc_ecc.hex()}")
			page += 1

def main() -> None:
	parser = ArgumentParser(description="", add_help=False)
	parser.add_argument("-u", "--unecc", action="store_true", help="UnECC an image")
	parser.add_argument("-e", "--ecc", action="store_true", help="ECC an image")
	parser.add_argument("-v", "--verify", action="store_true", help="Verify an image")
	parser.add_argument("infile", type=str, help="The image to work with")
	args = parser.parse_args()

	with open(args.infile, "rb") as f:
		image = f.read()

	if args.unecc:
		image = unecc(image)
		with open(args.infile + ".unecc", "wb") as f:
			f.write(image)
	elif args.ecc:
		image = addecc(image)
		with open(args.infile + ".ecc", "wb") as f:
			f.write(image)
	elif args.verify:
		verify(image)
	else:
		help()
		return

if __name__ == "__main__":
	main()