from scapy.packet import Packet
from scapy.fields import XStrField


class Phy_Packet(Packet):
    name = "Physical layer generic Packet"
    fields_desc = [
        XStrField("data", None)
    ]
