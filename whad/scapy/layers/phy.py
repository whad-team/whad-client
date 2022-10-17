from scapy.packet import Packet
from scapy.fields import StrField


class Phy_Packet(Packet):
    name = "Physical layer generic Packet"
    fields_desc = [
        StrField("data", None)
    ]
