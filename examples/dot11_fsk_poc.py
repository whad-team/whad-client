from whad.ble.utils .phy import frequency_to_channel, dewhitening
from whad.helpers import bytes_to_bits, bits_to_bytes, swap_bits
from mirage.libs.mosart_utils.scapy_mosart_layers import *
from multiprocessing import Process

def scrambling(data):
    return bytes([0x5a ^ i for i in data])

def count_valid_utf8(packet):
    count = 0
    for i in packet:
        try:
            test = bytes([i]).decode("utf-8")
            count += 1
        except:
            pass
    return count

def _initial(c):
	crc = 0
	c = c << 8
	for j in range(8):
		if (crc ^ c) & 0x8000:
			crc = (crc << 1) ^ 0x1021
		else:
			crc = crc << 1
		c = c << 1
	return crc


_tab = [_initial(i) for i in range(256)]


def _update_crc(crc, c):
	cc = 0xFF & c

	tmp = (crc >> 8) ^ cc
	crc = (crc << 8) ^ _tab[tmp & 0xFF]
	crc = crc & 0xFFFF

	return crc


def crc(data):
	'''
	This function returns the CRC of a Mosart payload.
	:param data: bytes of the payload
	:type data: bytes
	'''
	crc = 0
	for c in data:
		crc = _update_crc(crc, c)
	return crc

empty = 24
def check(packet):
    best_candidate = None
    best_candidate_count = 0

    for offset in range(0,empty):
        for value in range(0, (2**empty) - 1):
            binary_value = "{:024b}".format(value)
            raw = bytes([swap_bits(i) for i in bits_to_bytes(binary_value[:offset] + bytes_to_bits(packet) + binary_value[offset:])])
            whitened = dewhitening(15*b"\x00" + raw, 7)[15:]

            current_count = count_valid_utf8(whitened)
            if current_count > best_candidate_count:
                best_candidate_count = current_count
                best_candidate = whitened
                print(best_candidate, current_count)
                print("".join(["\\x" + "{:02x}".format(i) for i in best_candidate]))
packet = bytes.fromhex("aaeee44e492cdb4a6a0aff")
check(packet)
