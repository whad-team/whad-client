from whad.ble.utils .phy import frequency_to_channel, dewhitening
from whad.helpers import bytes_to_bits, bits_to_bytes, swap_bits
from mirage.libs.mosart_utils.scapy_mosart_layers import *
from threading import Thread
def scrambling(data):
    return bytes([0x5a ^ i for i in data])


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

def check(packet):
    for offset in range(0,16):
        for value in range(0, (2**16) - 1):
            binary_value = "{:016b}".format(value)
            raw = bytes([swap_bits(i) for i in bits_to_bytes(binary_value[:offset] + bytes_to_bits(packet) + binary_value[offset:])])
            whitened = dewhitening(15*b"\x00" + raw, 7)[15:]
            try:
                print(whitened.decode("utf-8"))
            except UnicodeDecodeError:
                pass

threads = []
for i in range((2**4) - 1):
    packet = bytes.fromhex("aaaaeee44e492cdb4a6a0aff")
    packet = Mosart_Hdr(scrambling(packet)[:-3])
    packet.seq_num = i
    packet = bytes(packet)
    postamble = bytes.fromhex("{:02x}".format(crc(scrambling(packet)[6:-3]))) + b"\xa5"
    packet += postamble
    process = Thread(target=check, args=[packet])
    process.start()
    threads.append(process)

for process in threads:
    process.join()
