from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import ByteEnumField, StrLenField, LEIntField, XShortField, LEShortField, \
    FieldLenField, StrFixedLenField, ConditionalField, PacketField, XLongField, XIntField,  XLEIntField, \
    XLEShortField, BitEnumField, BitField, ByteField, FieldListField, StrField, XByteField, LEShortField
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data
from scapy.config import conf
from scapy.utils import rdpcap


class WirelessHart_DataLink_Hdr(Packet):
    name = "Wireless Hart Data Link header"
    fields_desc = [
        BitField("reserved", None, 2), 
        BitEnumField("priority", None, 2, {0 : "alarm", 1:"normal", 2:"process_data", 3 : "command"}), 
        BitEnumField("network_key_use", None, 1, {0 : "no", 1:"yes"}), 
        BitEnumField("pdu_type", None, 3, {0 : "acknowledgment", 1:"advertisement", 2:"keep-alive", 3:"disconnect", 7 : "data"}), 
        XIntField("mic", None), 
        StrField("nl_data", None)
    ]
    
    def pre_dissect(self,s):
        return s[0:1] + s[-4:] + s[1:-4]

    '''
    def post_build(self,p,pay):
        if self.security_enabled == 1:
            mic = self.mic
            return p[:1] + p[5:] + pay + p[1:5]
        else:
            return p + pay

    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s
    ''' 

old_guess_payload_class = Dot15d4Data.guess_payload_class

def new_guess_payload_class(self, payload):
    if conf.dot15d4_protocol == "wirelesshart":
        return WirelessHart_DataLink_Hdr
    else:
        return old_guess_payload_class(self, payload)

Dot15d4Data.guess_payload_class = new_guess_payload_class


conf.dot15d4_protocol = "wirelesshart"

from Cryptodome.Cipher import AES


pkts = rdpcap("whad/ressources/pcaps/wireless_hart_capture_channel_11_41424344414243444142434441424344.pcapng")
for pkt in pkts[-2:]:
    dot15d4_pkt = Dot15d4FCS(bytes(pkt)[44:])    
    dot15d4_pkt.show()
    
        
    
# bad crypto...
data = bytes.fromhex("41889ccd04ffff050011000003659c120fff7f00000200040001036e4b010100010070004d9f01cc5485")

print(data)
nonce  = bytes.fromhex("0001") + 6*b"\x00" + bytes.fromhex("000003659c")
print(len(nonce))
for i in range(0,len(data)):
    for j in range(0,len(data)):
        cipher = AES.new(b'www.hartcomm.org', AES.MODE_CCM, nonce=nonce, mac_len=4)
        X1, tag= cipher.encrypt_and_digest(data[i:-j])
        if "cc019f4d" in tag.hex() or "4d9f01cc" in tag.hex():
            print(X1.hex(), tag.hex(), i,j)