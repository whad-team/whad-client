def message_filter(category, message):
    return lambda x: x.WhichOneof('msg') == category and getattr(x, category).WhichOneof('msg')==message

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
