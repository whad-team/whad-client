from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ByteEnumField, LEShortField, \
    StrLenField, FieldLenField

GOODFET_APPS = {
    0x00 : "MONITOR",
    0x51 : "CCSPI"
}

GOODFET_OPCODES = {
    0x00 : "transfer",
    0x02 : "peek",
    0x03 : "poke",
    0x80 : "read_rf_packet",
    0x81 : "send_rf_packet",
    0x84 : "peek_ram",
    0x85 : "poke_ram",
    0x10 : "setup_ccspi",
    0xB1 : "monitor_connected",
    0x7F : "init",
    0xFF : "debug_string",
    0xFE : "debug_int32",
    0xFD : "nop"
}

CC_VERSIONS = {
    0x233d : "CC2420"
}

# Scapy packets definitions
class GoodFET_Command_Hdr(Packet):
    name = "GoodFET Command header"
    fields_desc = [
        ByteEnumField("app", None, GOODFET_APPS),
        ByteEnumField("verb", None, GOODFET_OPCODES)
    ]


class GoodFET_Transfer_Command(Packet):
    name = "GoodFET Transfer Command"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]


class GoodFET_Monitor_Connected_Command(Packet):
    name = "GoodFET Monitor Connected Command"
    fields_desc = [LEShortField("size", 0x0000)]

class GoodFET_Peek_Command(Packet):
    name = "GoodFET Peek Command"
    fields_desc = [
        FieldLenField("size", None, length_of="address", fmt="<H"),
        StrLenField("address", None, length_from=lambda x:x.size)
    ]

class GoodFET_Poke_Command(Packet):
    name = "GoodFET Poke Command"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Peek_RAM_Command(Packet):
    name = "GoodFET Peek RAM Command"
    fields_desc = [
        LEShortField("size", 0x0004),
        LEShortField("address", 0x0000),
        LEShortField("count", 0x0000)
    ]

class GoodFET_Poke_RAM_Command(Packet):
    name = "GoodFET Poke RAM Command"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Send_RF_Packet_Command(Packet):
    name = "GoodFET Send RF Packet Command"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Setup_CCSPI_Command(Packet):
    name = "GoodFET Setup CCSPI Command"
    fields_desc = [LEShortField("size", 0x0000)]

class GoodFET_Read_RF_Packet_Command(Packet):
    name = "GoodFET Read RF Packet Command"
    fields_desc = [
        LEShortField("size", 0x0001),
        ByteField("reserved", 0x00) # ?
    ]

class GoodFET_Reply_Hdr(Packet):
    name = "GoodFET Reply header"
    fields_desc = [
        ByteEnumField("app", None, GOODFET_APPS),
        ByteEnumField("verb", None, GOODFET_OPCODES)
    ]


class GoodFET_Poke_RAM_Reply(Packet):
    name = "GoodFET Poke RAM Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Peek_RAM_Reply(Packet):
    name = "GoodFET Peek RAM Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Peek_Reply(Packet):
    name = "GoodFET Peek Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Init_Reply(Packet):
    name = "GoodFET Init Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="url", fmt="<H"),
        StrLenField("url", "http://goodfet.sf.net/", length_from=lambda x:x.size)
    ]

class GoodFET_Setup_CCSPI_Reply(Packet):
    name = "GoodFET Setup CCSPI Reply"
    fields_desc = [
                LEShortField("size", 0x0001),
    ]

class GoodFET_Poke_Reply(Packet):
    name = "GoodFET Poke Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Transfer_Reply(Packet):
    name = "GoodFET Transfer Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]


class GoodFET_Read_RF_Packet_Reply(Packet):
    name = "GoodFET Read RF Packet Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Send_RF_Packet_Reply(Packet):
    name = "GoodFET Send RF Packet Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

class GoodFET_Debug_String_Reply(Packet):
    name = "GoodFET Debug String Reply"
    fields_desc = [
        FieldLenField("size", None, length_of="data", fmt="<H"),
        StrLenField("data", None, length_from=lambda x:x.size)
    ]

bind_layers(GoodFET_Command_Hdr, GoodFET_Peek_Command, verb = 0x02)
bind_layers(GoodFET_Command_Hdr, GoodFET_Monitor_Connected_Command, verb = 0xB1)
bind_layers(GoodFET_Command_Hdr, GoodFET_Setup_CCSPI_Command, verb = 0x10)
bind_layers(GoodFET_Command_Hdr, GoodFET_Transfer_Command, verb = 0x00)
bind_layers(GoodFET_Command_Hdr, GoodFET_Poke_Command, verb = 0x03)
bind_layers(GoodFET_Command_Hdr, GoodFET_Read_RF_Packet_Command, verb = 0x80)
bind_layers(GoodFET_Command_Hdr, GoodFET_Send_RF_Packet_Command, verb = 0x81)
bind_layers(GoodFET_Command_Hdr, GoodFET_Peek_RAM_Command, verb = 0x84)
bind_layers(GoodFET_Command_Hdr, GoodFET_Poke_RAM_Command, verb = 0x85)

bind_layers(GoodFET_Reply_Hdr, GoodFET_Init_Reply, verb = 0x7F)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Peek_Reply, verb = 0x02)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Poke_Reply, verb = 0x03)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Debug_String_Reply, verb = 0xFF)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Setup_CCSPI_Reply, verb = 0x10)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Transfer_Reply, verb = 0x00)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Read_RF_Packet_Reply, verb = 0x80)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Send_RF_Packet_Reply, verb = 0x81)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Peek_RAM_Reply, verb = 0x84)
bind_layers(GoodFET_Reply_Hdr, GoodFET_Peek_RAM_Reply, verb = 0x85)
