from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import Field, ByteEnumField, StrLenField, IntField, XShortField, LEShortField, \
    FieldLenField, StrLenField, ConditionalField, PacketField, XLongField, XIntField,  XLEIntField, \
    XLEShortField, BitEnumField, BitField, ByteField, ShortField, XShortField, PacketListField
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data
from scapy.config import conf
from scapy.utils import rdpcap
from math import ceil
from struct import pack, unpack

class FiveBytesField(ByteField):
    def __init__(self, name, default):
        # type: (str, Optional[int]) -> None
        Field.__init__(self, name, default, ">Q")

    def addfield(self, pkt, s, val):
        # type: (Packet, bytes, Optional[int]) -> bytes
        return s + pack(self.fmt, self.i2m(pkt, val))[-5:]

    def getfield(self, pkt, s):
        # type: (Optional[Packet], bytes) -> Tuple[bytes, int]
        return s[5:], self.m2i(pkt, unpack(self.fmt, b"\x00"*3 + s[:5])[0])  # noqa: E501


class WirelessHart_DataLink_Hdr(Packet):
    name = "Wireless Hart Data Link header"
    fields_desc = [
        BitField("reserved", None, 2), 
        BitEnumField("priority", None, 2, {0 : "alarm", 1:"normal", 2:"process_data", 3 : "command"}), 
        BitEnumField("network_key_use", None, 1, {0 : "no", 1:"yes"}), 
        BitEnumField("pdu_type", None, 3, {0 : "acknowledgment", 1:"advertisement", 2:"keep-alive", 3:"disconnect", 7 : "data"}), 
        XIntField("mic", None),
    ]
    
    def pre_dissect(self,s):
        return s[0:1] + s[-4:] + s[1:-4]

    
    def post_build(self,p,pay):
            return p[0:1] + p[5:] + pay + p[1:5]
    
    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

class Link(Packet):
    name = "Wireless Hart Link"
    fields_desc = [
        ShortField("link_join_slot", None),
        BitField("link_reserved", 0, 1), 
        BitEnumField("link_use_for_transmission", 0, 1, {0:"denied", 1:"allowed"}), 
        BitField("link_channel_offset", 0, 6)
    ]
     
    def extract_padding(self, s):
        return b'', s
   
    
class Superframe(Packet):
    name = "Wireless Hart Superframe"
    fields_desc = [
        ByteField("superframe_id", None), 
        ShortField("superframe_number_of_slots", None), 
        FieldLenField("superframe_number_of_links", None, fmt="B", length_of="superframe_links"), 
        PacketListField("superframe_links",[], Link, length_from=lambda p:3 * p.superframe_number_of_links)#, length_from=lambda p:p.number_of_links),

    ]
    
    def extract_padding(self, s):
        return b'', s

class WirelessHart_DataLink_Advertisement_Hdr(Packet):
    name = "Wireless Hart Data Link Advertisement header"
    fields_desc = [
        FiveBytesField("asn", 0),
        BitEnumField("security_level_supported",0,4,{0 : "session_keyed", 1 : "join_keyed", 2 : "reserved", 3: "reserved"}), 
        BitField("join_priority",0,4), 
        FieldLenField("channel_count", None, fmt="B", length_of="channel_map"),
        StrLenField("channel_map", None, length_from = lambda p: ceil(p.channel_count / 8)),
        XShortField("graph_id", None), 
        FieldLenField("number_of_superframes", None, fmt="B", count_of="superframes"),
        PacketListField("superframes",[], Superframe, count_from=lambda p:p.number_of_superframes)#, length_from=lambda p:p.number_of_superframes),

    ]

bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_Advertisement_Hdr, pdu_type=1)

old_guess_payload_class = Dot15d4Data.guess_payload_class

def new_guess_payload_class(self, payload):
    if conf.dot15d4_protocol == "wirelesshart":
        return WirelessHart_DataLink_Hdr
    else:
        return old_guess_payload_class(self, payload)

Dot15d4Data.guess_payload_class = new_guess_payload_class


conf.dot15d4_protocol = "wirelesshart"


pkts = rdpcap("whad/ressources/pcaps/wireless_hart_capture_channel_11_41424344414243444142434441424344.pcapng")
for pkt in pkts:
    dot15d4_bytes = bytes(pkt)[44:]
    dot15d4_pkt = Dot15d4FCS(dot15d4_bytes)
    dot15d4_pkt.show()
    print(dot15d4_bytes.hex())
    print(bytes(dot15d4_pkt).hex())
    
'''       
from Cryptodome.Cipher import AES
    
# good crypto !
# non encrypted payload, AES-CCM*

data = bytes.fromhex("4188e0cd04ffff01003100000204e0110fff7f000003000400010042420101000100530404008006000e4a00154a00174a004b4a00524a006e4a")

print(data)
nonce  = bytes.fromhex("00000204e0") + 6*b"\x00"+ bytes.fromhex("0001")

cipher = AES.new(b'www.hartcomm.org', AES.MODE_CCM, nonce=nonce, mac_len=4)
cipher.update(data) # not encrypted but authenticated : full DLPDU (from 0x41 to the end of payload - just before MIC and empty encryption data)
X1= cipher.encrypt(b"")
tag = cipher.digest()
print(X1.hex(), tag.hex())
'''