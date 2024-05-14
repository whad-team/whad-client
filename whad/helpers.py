from pkgutil import iter_modules
from scapy.fields import StrField
from scapy.packet import Packet_metaclass
import whad

"""
def message_filter(category, message):
    return lambda x: x.WhichOneof('msg') == category and getattr(x, category).WhichOneof('msg')==message
"""

def message_filter(message_class):
    return lambda x: isinstance(x, message_class)

def is_message_type(message, category, message_type):
    if message.WhichOneof('msg') == category:
        return (hasattr(message, category) and getattr(message, category).WhichOneof('msg') == message_type)
    else:
        return False

def bd_addr_to_bytes(bd_addr):
    """
    Convert BD address to bytes
    """
    if not isinstance(bd_addr,str):
        return None

    # Clean BD address
    bd_addr_b = []
    bd_addr = bd_addr.replace(':','').lower()
    if len(bd_addr) == 12:
        for i in range(6):
            bd_addr_b.append(int(bd_addr[i*2:(i+1)*2], 16))
        return bytes(bd_addr_b[::-1])
    else:
        return None

def asciiz(s):
    """Convert a bytes buffer into ascii
    """
    if not isinstance(s,bytes):
        return None

    out=''
    for c in s:
        if s!=0:
            out += chr(c)
    return out

def swap_bits(value):
    """
    Swap the bits of a byte or a sequence of bytes.
    """
    if isinstance(value, int):
        return (value * 0x0202020202 & 0x010884422010) % 1023
    elif isinstance(value,bytes):
        return bytes([(i * 0x0202020202 & 0x010884422010) % 1023 for i in value])
    else:
        return None

def bytes_to_bits(data):
	'''
	This function converts bytes to the corresponding bits sequence (as string).

	:param data: bytes to convert
	:return: corresponding bits sequence

	:Example:
		>>> bytes_to_bits(b"\x01\x02\x03\xFF")
		'00000001000000100000001111111111'
		>>> bytes_to_bits(b"ABC")
		'010000010100001001000011'
	'''
	return "".join(["{:08b}".format(i) for i in bytes(data)])

def bits_to_bytes(bits):
	'''
	This function converts a sequence of bits (as string) to the corresponding bytes.

	:param bits: string indicating a sequence of bits (e.g. "10110011")
	:return: corresponding bytes

	:Example:
		>>> bits_to_bytes('00000001000000100000001111111111')
		b'\x01\x02\x03\xff'
		>>> bits_to_bytes('010000010100001001000011')
		b'ABC'
	'''
	return bytes([int(j+((8-len(j))*"0"),2) for j in [bits[i:i + 8] for i in range(0, len(bits), 8)]])

def bitwise_xor(a,b):
	'''
	This function returns the result of a bitwise XOR operation applied to two sequences of bits (a and b);

	:param a: string indicating a sequence of bits (e.g. "10101010")
	:param b: string indicating a sequence of bits (e.g. "10101010")
	:return: result of the XOR operation

	:Example:
		>>> bitwise_xor('11001111','10101010')
		'01100101'
		>>> bitwise_xor('11111111','00101010')
		'11010101'
		>>> bitwise_xor('11111111','11001100')
		'00110011'
	'''
	if len(a) != len(b):
		return None
	result = ""
	for i in range(len(a)):
		valA = a[i] == "1"
		valB = b[i] == "1"
		result += "1" if valA ^ valB else "0"
	return result

def list_domains():
    '''
    Returns a list of implemented domains.
    '''
    domains = []
    for submodule in iter_modules(whad.__path__):
        try:
            candidate = __import__("whad.{}.connector".format(submodule.name))
            domains.append(submodule.name)
        except ModuleNotFoundError:
            pass
    return domains

def scapy_packet_to_pattern(packet, selected_fields=None, selected_layers=None):
    '''
    This function converts a scapy packet into a pattern, a mask and an offset.
    '''

    # Format arguments to be iterable
    if isinstance(selected_fields, str):
        selected_fields = (selected_fields,)

    if isinstance(selected_layers, Packet_metaclass):
        selected_layers = (selected_layers, )
    # convert packet to bitstring
    pattern = bytes_to_bits(bytes(packet))
    mask = ""
    offset = 0

    # iterate over layers and fields to keep those selected
    for layer in packet.layers():
        use_layer = False

        if selected_layers is None and selected_fields is None:
            use_layer = True
        elif selected_layers is not None and layer in selected_layers:
            use_layer = True
        for field in layer.fields_desc:
            field_size = int(field.sz*8) if not isinstance(getattr(packet, field.name), bytes) else len(getattr(packet, field.name))*8
            if use_layer:
                mask += "1" * field_size
            else:
                if selected_fields is None:
                    mask += "0" * field_size
                elif field.name in selected_fields:
                    mask += "1" * field_size
                else:
                    mask += "0" * field_size

    # Convert bitstrings to bytes
    pattern = bits_to_bytes(pattern)
    mask = bits_to_bytes(mask)

    # Crop leading zero bytes and adjust offset
    for i in range(len(mask)):
        if mask[i] == 0:
            offset += 1
        else:
            break
    pattern = pattern[offset:]
    mask = mask[offset:]

    # Crop ending zero bytes and adjust size
    size = len(mask) - 1
    while size > 0 and mask[size] == 0:
        mask = mask[:-1]
        pattern = pattern[:-1]
        size-=1
    return (pattern, mask, offset)
