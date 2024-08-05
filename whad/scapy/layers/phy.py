from scapy.packet import Packet, bind_layers
from scapy.fields import XStrField, IntField
from scapy.config import conf

class Phy_Packet_Hdr(Packet):
    name = "Physical layer generic packet header"
    fields_desc = [
        IntField("frequency", None),
        IntField("rssi", None)
    ]

class Phy_Packet(Packet):
    name = "Physical layer generic Packet"
    fields_desc = [
        XStrField("data", None)
    ]

bind_layers(Phy_Packet_Hdr, Phy_Packet)
conf.l2types.register(152, Phy_Packet_Hdr)
