from scapy.packet import Packet, bind_layers
from scapy.config import conf
from scapy.fields import ByteField, ByteEnumField, LEShortEnumField, \
    FieldLenField, PacketListField, LenField, LEThreeBytesField, \
    IEEEFloatField, LEIntField, LEShortField, IEEEDoubleField, StrFixedLenField, Field
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
import struct

class LEIEEEFloatField(Field[int, int]):
    def __init__(self, name, default):
        Field.__init__(self, name, default, "<f")


# Implement https://github.com/jkcko/ieee802.15.4-tap
DLT_IEEE802_15_4_TAP = 283

DOT15D4TAP_VERSIONS = {
    0x00 : "version 1.0"
}

DOT15D4TAP_TYPES = {
    0x00 : "fcs_type",
    0x01 : "receive_signal_strength",
    0x02 : "bit_rate",
    0x03 : "channel_assignment",
    0x04 : "sun_phy_information",
    0x05 : "start_of_frame_timestamp",
    0x06 : "end_of_frame_timestamp",
    0x07 : "absolute_slot_number",
    0x08 : "start_of_slot_timestamp",
    0x09 : "timeslot_length",
    0x0a : "link_quality_indicator",
    0x0b : "channel_center_frequency",
    0x0c : "channel_plan"

}

class Dot15d4TAP_TLV_Hdr(Packet):
    name = "Dot15d4 TAP Type-Length-Value Header"
    fields_desc = [
        LEShortEnumField("type", None, DOT15D4TAP_TYPES),
        LenField("len", None, fmt="<H")
    ]


class Dot15d4TAP_TLV_Element(Packet):
    name = "Dot15d4 TAP Type-Length-Value Element"
    def extract_padding(self, s):
        return b"",s

class  Dot15d4TAP_FCS_Type(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 FCS Type"
    fields_desc = [
        ByteEnumField("fcs_type", 1, {0 : "none", 1: "16-bit CRC", 2: "32-bit CRC"}),
        StrFixedLenField("padding", b"\x00"*3, 3)

    ]

class  Dot15d4TAP_Received_Signal_Strength(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Received Signal Strength"
    fields_desc = [
        LEIEEEFloatField("rss",None),
    ]

class  Dot15d4TAP_Bit_Rate(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Bit Rate"
    fields_desc = [
        LEIntField("bit_rate",None)
    ]

class  Dot15d4TAP_Channel_Assignment(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Channel Assignment"
    fields_desc = [
        LEShortField("channel_number",None),
        ByteField("channel_page", None),
        StrFixedLenField("padding", "\x00", 1),
    ]

class  Dot15d4TAP_SUN_PHY_Information(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 SUN PHY Information"
    fields_desc = [
        ByteField("phy_band", None),
        ByteField("phy_type", None),
        ByteField("phy_mode", None),
        StrFixedLenField("padding", b"\x00"*1, 1)
    ]


class  Dot15d4TAP_Start_Of_Frame_Timestamp(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Start of Frame Timestamp"
    fields_desc = [
        IEEEDoubleField("timestamp", None)
    ]


class  Dot15d4TAP_End_Of_Frame_Timestamp(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 End of Frame Timestamp"
    fields_desc = [
        IEEEDoubleField("timestamp", None)
    ]

class  Dot15d4TAP_Absolute_Slot_Number(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Absolute Slot Number"
    fields_desc = [
        IEEEDoubleField("absolute_slot_number", None)
    ]


class  Dot15d4TAP_Start_Of_Slot_Timestamp(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Start of Slot Timestamp"
    fields_desc = [
        IEEEDoubleField("timestamp", None)
    ]

class  Dot15d4TAP_Timeslot_Length(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Timeslot Length"
    fields_desc = [
        IEEEDoubleField("timeslot_length", None)
    ]


class  Dot15d4TAP_Link_Quality_Indicator(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Link Quality Indicator"
    fields_desc = [
        ByteField("lqi", None),
        StrFixedLenField("padding", b"\x00"*3, 3)
    ]


class  Dot15d4TAP_Channel_Center_Frequency(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Channel Center Frequency"
    fields_desc = [
        LEIEEEFloatField("channel_frequency", None),
    ]


class  Dot15d4TAP_Channel_Plan(Dot15d4TAP_TLV_Element):
    name = "Dot15d4 Channel Plan"
    fields_desc = [
        LEIEEEFloatField("base_channel_frequency", None),
        LEIEEEFloatField("channel_spacing", None),
        LEShortField("number_of_channels", None),
        StrFixedLenField("padding", b"\x00"*2, 2)
    ]


class Dot15d4TAP_Hdr(Packet):
    name = "Dot15d4 TAP Header"
    fields_desc = [
        ByteEnumField("version", 0, DOT15D4TAP_VERSIONS),
        ByteField("reserved", 0),
        FieldLenField("length", None, length_of="data", fmt="<H", adjust=lambda pkt, f:f+4),
        PacketListField("data", [], Dot15d4TAP_TLV_Hdr, length_from=lambda x:x.length-4),
    ]


bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_FCS_Type, type=0x00)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Received_Signal_Strength, type=0x01)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Bit_Rate, type=0x02)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Channel_Assignment, type=0x03)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_SUN_PHY_Information, type=0x04)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Start_Of_Frame_Timestamp, type=0x05)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_End_Of_Frame_Timestamp, type=0x06)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Absolute_Slot_Number, type=0x07)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Start_Of_Slot_Timestamp, type=0x08)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Timeslot_Length, type=0x09)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Link_Quality_Indicator, type=0x0a)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Channel_Center_Frequency, type=0x0b)
bind_layers(Dot15d4TAP_TLV_Hdr, Dot15d4TAP_Channel_Plan, type=0x0c)

bind_layers(Dot15d4TAP_Hdr, Dot15d4)
bind_layers(Dot15d4TAP_Hdr, Dot15d4FCS)
conf.l2types.register(DLT_IEEE802_15_4_TAP, Dot15d4TAP_Hdr)
