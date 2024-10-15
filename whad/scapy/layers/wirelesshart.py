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

        StrField("data", None)
    ]

def new_guess_payload_class(self, payload):
    if conf.dot15d4_protocol == "wirelesshart":
        return WirelessHart_DataLink_Hdr
    else:
        return old_guess_payload_class(self, payload)

Dot15d4Data.guess_payload_class = new_guess_payload_class


conf.dot15d4_protocol = "wirelesshart"

pkts = rdpcap("whad/ressources/pcaps/wireless_hart_capture_channel_11_41424344414243444142434441424344.pcapng")
for pkt in pkts:
    dot15d4_pkt = Dot15d4FCS(bytes(pkt)[44:])
    dot15d4_pkt.show()