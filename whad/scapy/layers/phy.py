from scapy.packet import Packet, bind_layers
from scapy.fields import XStrField, IntField, SignedIntField, IntEnumField, FieldLenField, XStrLenField
from scapy.config import conf

MODULATIONS = {
    0 : "ASK",
    1 : "FSK",
    2 : "4FSK",
    3 : "GFSK",
    4 : "MSK",
    5 : "BFSK",
    6 : "QFSK",
    7 : "LoRa"
}
class Phy_Packet_Hdr(Packet):
    name = "Physical layer generic packet header"
    fields_desc = [
        IntField("frequency", None),
        SignedIntField("rssi", None),
        IntField("datarate", None),
        IntField("deviation", None),
        IntEnumField("endianness", None, {0 : "little", 1 : "big"}),
        IntEnumField("modulation", None, MODULATIONS),
        FieldLenField("syncword_length", None, length_of="syncword"),
        XStrLenField("syncword", None, length_from=lambda s: s.syncword_length)
    ]

class Phy_Packet(Packet):
    name = "Physical layer generic Packet"
    fields_desc = [
        XStrField("data", None)
    ]

bind_layers(Phy_Packet_Hdr, Phy_Packet)
conf.l2types.register(152, Phy_Packet_Hdr)
