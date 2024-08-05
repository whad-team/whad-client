from scapy.packet import Packet, bind_layers
from scapy.fields import StrField, StrFixedLenField, XByteField, \
    FieldLenField, BitField, BitEnumField, XShortField, StrLenField
from scapy.config import conf
from struct import pack, unpack

from whad.helpers import bits_to_bytes, bytes_to_bits, bitwise_xor

USER_DLT = 148

def crc_update(crc, value, bits):
    """Update CRC with the provided bits.

    Implementation taken from Bastille's nRF Research firmware
    (https://github.com/BastilleResearch/nrf-research-firmware/)
    """
    crc = crc ^ (value << 8)
    while bits>0:
        bits -= 1
        if (crc & 0x8000) == 0x8000:
            crc = (crc << 1) ^ 0x1021
        else:
            crc = crc << 1
    crc = crc & 0xFFFF
    return crc


def compute_crc(packet) -> bytes:
    """Compute ESB packet CRC bytes (16-bit)

    :param packet: ESB packet with an extra null byte
    :type packet: :class:`whad.scapy.layers.esb.ESB_Hdr`
    :return: CRC encoded as a byte array
    :rtype: bytes
    """
    # CRC initial value is 0xFFFF
    crc = 0xFFFF

    # Loop on all packet bytes except the last one
    for x in packet[:-1]:
        crc = crc_update(crc, x, 8)

    # Include the last bit stored in the extra byte
    crc = crc_update(crc, packet[-1], 1)

    # Return the encoded CRC (big-endian)
    return pack('>H', crc)


# Field representing a ShockBurst address
class SBAddressField(StrLenField):
    def __init__(self, name, default, length_from):
        StrLenField.__init__(self, name, default,length_from=length_from)

    def i2h(self,pkt,x):
        return ":".join(["{:02x}".format(i) for i in x])

    def i2repr(self,pkt,x):
        return self.i2h(pkt, x)

    def any2i(self,pkt,x):
        if isinstance(x,str):
            x = bytes.fromhex(x.replace(":",""))
        return x

class ESB_Hdr(Packet):
    ESB_PREAMBLE_SIZE = 8
    ESB_PCF_SIZE = 9
    ESB_CRC_SIZE = 16
    ESB_PAYLEN_SIZE = 6

    name = "Enhanced ShockBurst packet"
    fields_desc = [
            XByteField("preamble",0xAA),
            FieldLenField("address_length", None, length_of="address"),
            SBAddressField("address",b"\0\0\0\0\0",length_from = lambda pkt:pkt.address_length),
            BitField("payload_length", None, 6),
            BitField("pid",None,2),
            BitField("no_ack", 0,1),
            BitField("padding",0,6),
            BitEnumField("valid_crc",0,1,{0:"no",1:"yes"}),
            XShortField("crc",None)
    ]


    def post_build(self, p, pay):
        """Effectively build the ESB packet based on its properties.
        """
        # Extract preamble
        preamble = p[0]

        # extract address and address length
        address_len = unpack('>H', p[1:3])[0]
        address = p[3:3+address_len]

        # Compute PCF field (9 bits)
        pcf = (p[3+address_len]<<1) | (p[3+address_len+1]&0x80)>>7

        # Update payload length if required
        if self.payload_length is None:
            payload_length = len(pay)
            pcf = (pcf & 0x7) | (payload_length << 3)

        # Build payload bytes
        carry = pcf&1
        out = []
        for x in pay:
            out.append((x>>1) | (carry << 7))
            carry = x&1
        out.append(carry<<7)

        # Compute CRC
        frame = address + bytes([pcf>>1]) + bytes(out)
        if self.crc is None:
            crc = compute_crc(frame)#pack('>H', compute_crc_value(frame))
        else:
            crc = p[-2:]

        # Append the packet CRC
        out[-1] |= crc[0]>>1
        out.append((crc[1]>>1) | (crc[0]&1)<<7)
        out.append((crc[1]&1)<<7)


        # Build the final frame
        return bytes([preamble]) + address + bytes([pcf>>1]) + bytes(out)

    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def pre_dissect(self,s):
        """Pre-dissect an ESB frame to guess the address and payload sizes.
        """
        if s[0] not in [0xAA, 0x55]: # Dirty patch if no preamble is included
            s = b"\xAA"+s
        bitstring = bytes_to_bits(s)
        crc = None
        crc_found = False
        i = ESB_Hdr.ESB_PREAMBLE_SIZE+1
        # We try to guess the packet size by looking for a valid CRC
        while i < len(bitstring) - 16:
            if bytes_to_bits(compute_crc(bits_to_bytes(bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:i]))) == bitstring[i:i+ESB_Hdr.ESB_CRC_SIZE]:
                crc_found = True
                break
            i += 1

        # We try to guess the address size by checking if :
        # ESB_PREAMBLE_SIZE + 8*addr_size + ESB_PCF_SIZE + payload_size = 8*packet_size - ESB_CRC_SIZE
        addr_len_found = False
        for addr_length in range(3,6):
            payLen = bits_to_bytes("00"+bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PAYLEN_SIZE])[0]
            if ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE+payLen*8 == i:
                addr_len_found = True
                break


        preamble = bitstring[:ESB_Hdr.ESB_PREAMBLE_SIZE]
        if crc_found and addr_len_found:
            # No problem, we know that the packet is valid
            address = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8]
            validCrc = "1" if crc_found else "0"
        else:
            # Our assumption is : addrLen = 5, invalid CRC
            addr_length = 5
            address = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8]
            validCrc = "0"

        pcf = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE]
        payload_length = bits_to_bytes("00"+pcf[:6])[0]
        payload = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE+payload_length*8]
        crc = bitstring[ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE+payload_length*8:ESB_Hdr.ESB_PREAMBLE_SIZE+addr_length*8+ESB_Hdr.ESB_PCF_SIZE+payload_length*8+ESB_Hdr.ESB_CRC_SIZE]

        padding = "0"*6

        #print("pl",bits_to_bytes(preamble + bytes_to_bits(bytes([0,addr_length])) + address + pcf + padding + validCrc + crc + payload).hex())
        return bits_to_bytes(preamble + bytes_to_bits(bytes([0,addr_length])) + address + pcf + padding + validCrc + crc + payload)


class ESB_Payload_Hdr(Packet):
    """ESB payload header
    """
    name = "ESB Payload"
    fields_desc = []

class ESB_Ping_Request(Packet):
    """ESB Ping request.

    Ping request is identified by a payload of [0x0F, 0x0F, 0x0F, 0x0F].
    """
    name = "ESB Ping Request"
    fields_desc = [StrFixedLenField('ping_payload', '\x0f\x0f\x0f\x0f', length=4)]

class ESB_Ack_Response(Packet):
    """ESB Ack response layer.
    """
    name = "ESB Ack Response"
    fields_desc = [StrField('ack_payload', '')]


class ESB_Pseudo_Packet(Packet):
    """ESB pseudo-packet layer.
    """
    name = "ESB Pseudo packet"
    fields_desc = []

def guess_payload_class_esb(self, payload):
    """Guess payload content based on payload size and content.
    """
    if b"\x0f\x0f\x0f\x0f" == payload[:4]:
        return ESB_Ping_Request
    elif len(payload) == 0 or self.underlayer is not None and self.underlayer.no_ack == 1:
        return ESB_Ack_Response
    else:
        return Packet.guess_payload_class(self, payload)

ESB_Payload_Hdr.guess_payload_class = guess_payload_class_esb

bind_layers(ESB_Hdr,ESB_Payload_Hdr)
conf.l2types.register(USER_DLT, ESB_Hdr)
conf.l2types.register(USER_DLT, ESB_Pseudo_Packet)
