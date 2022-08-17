from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ByteEnumField, LEShortField, \
    StrLenField, FieldLenField

CCSI_APP = 0x51

GOODFET_REPLIES = {
    0x7F : "init",
    0xFF : "debug_string",
    0xFE : "debug_int32",
    0xFD : "nop"
}

CC_VERSIONS = {
    0x233d : "CC2420"
}

# Scapy packets definitions
class GoodFET_Hdr(Packet):
    name = "GoodFET header"
    fields_desc = [
        ByteField("app", None),
        ByteEnumField("verb", None, GOODFET_REPLIES)
    ]

class GoodFET_Init_Reply(Packet):
    name = "GoodFET Init Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="url", fmt="<H"),
        StrLenField("url", "http://goodfet.sf.net/", length_from=lambda x:x.size)
    ]

class GoodFET_Debug_String_Reply(Packet):
    name = "GoodFET Debug String Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

bind_layers(GoodFET_Hdr, GoodFET_Init_Reply, verb = 0x7F)
bind_layers(GoodFET_Hdr, GoodFET_Debug_String_Reply, verb = 0xFF)
