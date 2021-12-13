#!/usr/bin/env python3

__authors__ = ["DrSchottky", "GoobyCorp"]
__version__ = "1.0.0.0"

import re
import hmac
from typing import Union
from hashlib import sha1
from os.path import isfile
from struct import unpack_from
from argparse import ArgumentParser, FileType, ArgumentTypeError

# rc4.py
from rc4 import RC4
# ecc_utils.py
from ecc_utils import BLOCK_TYPE, addecc, unecc

_1BL_KEY = bytes.fromhex("DD88AD0C9ED669E7B56794FB68563EFA")

CPUKEY_EXP = re.compile(r"^([0-9a-fA-F]{32})$")

def decrypt_cba(cba: Union[bytes, bytearray]) -> bytes:
	key = hmac.new(_1BL_KEY, cba[0x10:0x20], sha1).digest()[:0x10]
	cba = cba[:0x10] + key + RC4(key).crypt(cba[0x20:])
	return cba

def decrypt_cbb(cbb: Union[bytes, bytearray], cba_key: Union[bytes, bytearray], cpukey: Union[bytes, bytearray]) -> bytes:
	h = hmac.new(cba_key, digestmod=sha1)
	h.update(cbb[0x10:0x20])
	h.update(cpukey)
	key = h.digest()[:0x10]
	cbb = cbb[:0x10] + key + RC4(key).crypt(cbb[0x20:])
	return cbb

def cpukey_type(key: str) -> bytes:
	matches = CPUKEY_EXP.match(key)
	if matches:
		return bytes.fromhex(key)
	raise ArgumentTypeError("CPU key isn't a 32 character hex string")

def main() -> None:
	parser = ArgumentParser(description=f"RGH2 to RGH3 by DrSchottky v{__version__}")
	parser.add_argument("eccfile", type=FileType("rb"), help="The ECC file to apply")
	parser.add_argument("infile", type=FileType("rb"), help="The flash image to convert to RGH3")
	parser.add_argument("outfile", type=FileType("wb"), help="The flash image to output to")
	parser.add_argument("-k", "--cpukey", type=cpukey_type, help="The CPU key for the given flash image")
	args = parser.parse_args()

	if args.cpukey:
		cpukey = args.cpukey
	elif isfile("cpukey.bin"):
		with open("cpukey.bin", "rb") as f:
			cpukey = f.read()[:0x10]  # first 16 bytes
	elif isfile("cpukey.txt"):
		with open("cpukey.txt", "r") as f:
			cpukey = bytes.fromhex(f.read().strip()[:0x20])  # first 32 characters
	else:
		print("No CPU key found, aborting...")
		return

	print("Loading ECC...")
	ecc = args.eccfile.read()
	args.eccfile.close()

	if len(ecc) == 1351680:
		print("ECC contains spare data")
		ecc = unecc(ecc)
	elif len(ecc) == 1310720:
		print("ECC does not contain spare data")
	else:
		print("Unexpected ECC length, aborting...")
		return

	print("\nExtracting RGH3 SMC...")
	(rgh3_smc_len, rgh3_smc_start) = unpack_from(">2I", ecc, 0x78)
	rgh3_smc = ecc[rgh3_smc_start:rgh3_smc_len + rgh3_smc_start]
	(loader_start,) = unpack_from(">I", ecc, 8)

	print("\nExtracting RGH3 Bootloaders...")
	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack_from(">2sH3I", ecc, loader_start)
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	rgh3_cba = ecc[loader_start:loader_start + loader_size]
	loader_start += loader_size

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack_from(">2sH3I", ecc, loader_start)
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	rgh3_payload = ecc[loader_start:loader_start + loader_size]

	# with open("extracted/rgh3_smc.bin", "wb") as f:
	# 	f.write(rgh3_smc)

	# with open("extracted/rgh3_cba.bin", "wb") as f:
	# 	f.write(rgh3_cba)

	# with open("extracted/rgh3_payload.bin", "wb") as f:
	# 	f.write(rgh3_payload)

	if not rgh3_payload or not rgh3_cba:
		print("\nMissing ECC bootloaders, aborting...")
		return

	print("\nLoading FB...")
	fb = args.infile.read()
	args.infile.close()
	fb_with_ecc = False

	if len(fb) == 17301504 or len(fb) == 69206016:
		print("FB image contains spare data")
		xell_start = 0x73800
		patchable_fb = fb[:xell_start]
		patchable_fb = unecc(patchable_fb)
		fb_with_ecc = True
	elif len(fb) == 50331648:
		print("FB image does not contain spare data")
		xell_start = 0x70000
		patchable_fb = fb[:xell_start]
	else:
		print("Unexpected FB image length, aborting...")
		return

	if fb_with_ecc:
		spare_sample = fb[0x4400:0x4410]
		if spare_sample[0] == 0xFF:
			print("Detected 256/512MB Big Block Flash")
			block_type = BLOCK_TYPE.BIG
		elif spare_sample[5] == 0xFF:
			if spare_sample[:2] == b"\x01\x00":
				print("Detected 16/64MB Small Block Flash")
				block_type = BLOCK_TYPE.SMALL
			elif spare_sample[:2] == b"\x00\x01":
				print("Detected 16/64MB Big on Small Flash")
				block_type = BLOCK_TYPE.BIG_ON_SMALL
			else:
				print("Can't detect flash type, aborting...")
				return
		else:
			print("Can't detect flash type, aborting...")
			return
	else:
		print("Detected 4GB Flash")

	if fb[xell_start:xell_start + 0x10] != bytes.fromhex("48000020480000EC4800000048000000"):
		print("XeLL header not found, aborting...")
		return

	print("\nPatching SMC...")
	patchable_fb = patchable_fb[:rgh3_smc_start] + rgh3_smc + patchable_fb[rgh3_smc_start + rgh3_smc_len:]

	print("\nExtracting FB bootloaders...")

	(loader_start,) = unpack_from(">I", patchable_fb, 8)

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack_from(">2sH3I", patchable_fb, loader_start)
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	fb_cba = patchable_fb[loader_start:loader_start + loader_size]
	fb_cba_start = loader_start
	loader_start += loader_size

	(loader_name, loader_ver, loader_flags, loader_ep, loader_size) = unpack_from(">2sH3I", patchable_fb, loader_start)
	print(f"Found {loader_name.decode()} {loader_ver} with size 0x{loader_size:08X} at 0x{loader_start:08X}")
	fb_cbb = patchable_fb[loader_start:loader_start + loader_size]
	fb_cbb_start = loader_start

	print("\nDecrypting CB...")
	fb_cba = decrypt_cba(fb_cba)
	fb_cbb = decrypt_cbb(fb_cbb, fb_cba[0x10:0x20], cpukey)
	if fb_cbb[0x392:0x39A] not in [b"XBOX_ROM", b"\x00" * 8]:
		print("CB_B decryption error (wrong CPU key?), aborting...")
		return

	print("\nPatching CB...")
	original_size = len(patchable_fb)
	new_cbb = rgh3_payload + fb_cbb
	patchable_fb = patchable_fb[:fb_cba_start] + rgh3_cba + new_cbb + patchable_fb[fb_cbb_start + len(fb_cbb):]
	new_size = len(patchable_fb)
	print(f"I had to remove 0x{new_size - original_size:02X} bytes after CE to make it fit.")
	patchable_fb = patchable_fb[:original_size]

	print("\nMerging image...")
	if fb_with_ecc:
		patchable_fb = addecc(patchable_fb, block_type)
	fb = patchable_fb + fb[len(patchable_fb):]

	args.outfile.write(fb)
	args.outfile.close()

	print("\nDone!")

if __name__ == "__main__":
	main()