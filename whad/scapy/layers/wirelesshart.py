from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import Field, ByteEnumField, StrLenField, IntField, XShortField, LEShortField, \
    FieldLenField, StrLenField, ConditionalField, PacketField, XByteField, XIntField,  SignedShortField, \
    XLEShortField, BitEnumField, BitField, ByteField, ShortField, XShortField, PacketListField, FieldListField
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data, MultipleTypeField
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
        PacketListField("superframe_links",[], Link, length_from=lambda p:3 * p.superframe_number_of_links)

    ]
    
    def extract_padding(self, s):
        return b'', s

class WirelessHart_DataLink_Advertisement(Packet):
    name = "Wireless Hart Data Link Advertisement DLPDU"
    fields_desc = [
        FiveBytesField("asn", 0),
        BitEnumField("security_level_supported",0,4,{0 : "session_keyed", 1 : "join_keyed", 2 : "reserved", 3: "reserved"}), 
        BitField("join_priority",0,4), 
        FieldLenField("channel_count", None, fmt="B", length_of="channel_map"),
        StrLenField("channel_map", None, length_from = lambda p: ceil(p.channel_count / 8)),
        XShortField("graph_id", None), 
        FieldLenField("number_of_superframes", None, fmt="B", count_of="superframes"),
        PacketListField("superframes",[], Superframe, count_from=lambda p:p.number_of_superframes)

    ]

class WirelessHart_DataLink_Acknowledgement(Packet):
    name = "Wireless Hart Data Link Acknowledgement DLPDU"
    fields_desc = [
        ByteEnumField("response_code", None, 
            {   
                0 : "success",
                61 : "error_no_buffers_available",
                62 : "error_no_alarm_event_buffers_available",
                63 : "error_priority_too_low"
            }
        ), 
        SignedShortField("time_adjustment", None)
        
    ]

class WirelessHart_DataLink_KeepAlive(Packet):
    name = "Wireless Hart Data Link Keep Alive DLPDU"
    fields_desc = [] # empty payload

class WirelessHartAddressField(Field):
    __slots__ = ["adjust", "length_of"]

    def __init__(self, name, default, length_of=None, fmt="<H", adjust=None):
        Field.__init__(self, name, default, fmt)
        self.length_of = length_of
        if adjust is not None:
            self.adjust = adjust
        else:
            self.adjust = lambda pkt, x: self.lengthFromAddrMode(pkt, x)

    def i2repr(self, pkt, x):
        """Convert internal value to a nice representation"""
        if len(hex(self.i2m(pkt, x))) < 7:  # short address
            return hex(self.i2m(pkt, x))
        else:  # long address
            x = "%016x" % self.i2m(pkt, x)
            return ":".join(["%s%s" % (x[i], x[i + 1]) for i in range(0, len(x), 2)])  # noqa: E501

    def addfield(self, pkt, s, val):
        """Add an internal value to a string"""
        if self.adjust(pkt, self.length_of) == 2:
            return s + pack(self.fmt[0] + "H", val)
        elif self.adjust(pkt, self.length_of) == 8:
            return s + pack(self.fmt[0] + "Q", val)
        else:
            return s

    def getfield(self, pkt, s):
        if self.adjust(pkt, self.length_of) == 2:
            return s[2:], self.m2i(pkt, unpack(self.fmt[0] + "H", s[:2])[0])  # noqa: E501
        elif self.adjust(pkt, self.length_of) == 8:
            return s[8:], self.m2i(pkt, unpack(self.fmt[0] + "Q", s[:8])[0])  # noqa: E501
        else:
            raise Exception('impossible case')

    def lengthFromAddrMode(self, pkt, x):
        addrmode = 0
        pkttop = pkt
        if pkttop is None:
            print("No underlayer to guess address mode")
            return 0
        while True:
            try:
                print(pkttop.getfieldval(x))
                addrmode = pkttop.getfieldval(x)
                break
            except Exception:
                if pkttop.underlayer is None:
                    break
                pkttop = pkttop.underlayer
        
        if addrmode == 0:
            return 2
        elif addrmode == 1:
            return 8
        return 0


class WirelessHart_Network_Hdr(Packet):
    name = "Wireless Hart Network Layer header"
    fields_desc = [
        BitEnumField("nwk_dest_addr_length", None, 1, {0 : "short", 1 : "long"}), 
        BitEnumField("nwk_src_addr_length", None, 1, {0 : "short", 1 : "long"}), 
        BitField("reserved", 0, 3), 
        BitEnumField("proxy_route", None, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("second_src_route_segment", None, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("first_src_route_segment", None, 1, {0 : "no", 1 : "yes"}), 
        ByteField("ttl", None), 
        XShortField("asn_snippet", None), # least two significant bits of ASN : latency count
        XShortField("graph_id", None),
        WirelessHartAddressField("nwk_dest_addr", 0x0, length_of="nwk_dest_addr_length"),
        WirelessHartAddressField("nwk_src_addr", 0x0, length_of="nwk_src_addr_length"),  
        ConditionalField(
            WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2),
            lambda pkt: pkt.proxy_route  == 1
        ),
          ConditionalField(
            FieldListField("first_route_segment",[],WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2), count_from=lambda p : 4),
            lambda pkt:pkt.getfieldval("first_src_route_segment") == 1
        ),
          ConditionalField(
            FieldListField("second_route_segment",[],WirelessHartAddressField("parent_proxy_addr", None, adjust = lambda pkt, x : 2), count_from=lambda p : 4),
            lambda pkt:pkt.getfieldval("second_src_route_segment") == 1
        ),
        
    ]

class WirelessHart_Network_Security_SubLayer_Hdr(Packet):
    name = "Wireless Hart Network Security sub-layer header"
    fields_desc = [
        BitField("reserved", 0, 4), 
        BitEnumField("security_types", 0, 4,{0: 'session_keyed', 1: 'join_keyed', 2: 'reserved', 3: 'reserved', 4: 'reserved', 5: 'reserved', 6: 'reserved', 7: 'reserved', 8: 'reserved', 9: 'reserved', 10: 'reserved', 11: 'reserved', 12: 'reserved', 13: 'reserved', 14: 'reserved'}), 
        MultipleTypeField(
            [
                (XByteField("counter", None), lambda p:p.security_types == 0),
            ],
            XIntField("counter", None)
        ),
]
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_Acknowledgement, pdu_type=0)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_Advertisement, pdu_type=1)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_DataLink_KeepAlive, pdu_type=2)
bind_layers(WirelessHart_DataLink_Hdr, WirelessHart_Network_Hdr, pdu_type=7)

bind_layers(WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr)

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
    if WirelessHart_DataLink_Advertisement not in dot15d4_pkt:
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