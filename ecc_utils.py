#!/usr/bin/env python3

__authors__ = ["DrSchottky", "GoobyCorp"]
__version__ = "1.0.0.0"

from enum import Enum
from io import BytesIO
from typing import Union
from struct import pack, unpack, pack_into
from argparse import ArgumentParser, FileType

class BLOCK_TYPE(Enum):
	SMALL = 0x0
	BIG_ON_SMALL = 0x1
	BIG = 0x02

def calcecc(data: Union[bytes, bytearray]) -> bytes:
	if type(data) != bytearray:
		data = bytearray(data)

	assert len(data) == 0x210
	val = 0
	for i in range(0x1066):
		if not i & 31:
			v = ~unpack("<I", data[i // 8:(i // 8) + 4])[0]
		val ^= v & 1
		v >>= 1
		if val & 1:
			val ^= 0x6954559
		val >>= 1
	val = ~val
	pack_into("<I", data, len(data) - 4, (val << 6) & 0xFFFFFFFF)
	return data

def addecc(data: Union[bytes, bytearray], block_type: BLOCK_TYPE = BLOCK_TYPE.BIG_ON_SMALL):
	with BytesIO(data) as rbio, BytesIO() as wbio:
		block = 0
		while rbio.tell() < len(data):
			d = bytearray(528)
			t = rbio.read(512)
			d[:len(t)] = t

			if block_type == BLOCK_TYPE.BIG_ON_SMALL:
				pack_into("<BI3B8x", d, 512, 0, block // 32, 0xFF, 0, 0)
			elif block_type == BLOCK_TYPE.BIG:
				pack_into("<BI3B8x", d, 512, 0xFF, block // 256, 0, 0, 0)
			elif block_type == BLOCK_TYPE.SMALL:
				pack_into("<I4B8x", d, 512, block // 32, 0, 0xFF, 0, 0)
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

def verify(data: Union[bytes, bytearray], block: int = 0, off_8: Union[bytes, bytearray] = b"\x00" * 4):
	while len(data):
		d = (data[:0x200] + b"\x00" * 0x200)[:0x200]
		d += pack("<L4B4s4s", block // 32, 0, 0xFF, 0, 0, off_8, b"\x00" * 4)
		d = calcecc(d)
		calc_ecc = d[0x200:0x210]
		file_ecc = data[0x200:0x210]
		if calc_ecc != file_ecc:
			print(f"ECC mismatch on page 0x{block:02X} (0x{(block + 1) * 0x210 - 0x10:02X})")
			print(file_ecc)
			print(calc_ecc)
		block += 1
		data = data[0x210:]

def lowercase_type(s: str) -> str:
	return s.lower()

def main() -> None:
	parser = ArgumentParser(description="A script to ECC or UNECC an image")
	parser.add_argument("mode", type=lowercase_type, choices=["unecc", "ecc", "verify"], help="The mode of operation")
	parser.add_argument("infile", type=FileType("rb"), help="The image to work with")
	args = parser.parse_args()

	image = args.infile.read()
	args.infile.close()

	if args.mode == "ecc":
		image = addecc(image)
		with open(args.infile.name + ".ecc", "wb") as f:
			f.write(image)
	elif args.mode == "unecc":
		image = unecc(image)
		with open(args.infile.name + ".unecc", "wb") as f:
			f.write(image)
	elif args.mode == "verify":
		verify(image)
	else:
		help()
		return

if __name__ == "__main__":
	main()