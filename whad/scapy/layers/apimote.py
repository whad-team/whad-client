from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ByteEnumField, LEShortField, \
    StrField

GOODFET_REPLIES = {
    0x7F : "init",
    0xFF : "debug_string",
    0xFE : "debug_int32",
    0xFD : "nop"
}

# Scapy packets definitions
class GoodFET_Hdr(Packet):
    name = "GoodFET header"
    fields_desc = [
        ByteField("app", None),
        ByteEnumField("verb", None, GOODFET_REPLIES),
        LEShortField("size",None)
    ]

class GoodFET_Init_Reply(Packet):
    name = "GoodFET Init Reply"
    fields_desc = [
        StrField("url", "http://goodfet.sf.net/")
    ]

bind_layers(GoodFET_Hdr, GoodFET_Init_Reply, verb = 0x7F)
