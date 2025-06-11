from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, LEIntField, LEShortField, \
    LEX3BytesField, ShortField, SignedByteField, XByteField, XLEIntField
from scapy.layers.bluetooth4LE import BTLE
from whad.ble.utils.phy import FieldsSize
from struct import unpack
# Ubertooth Packet Types
UBERTOOTH_PACKET_TYPES = [
    "BR_PACKET",
    "LE_PACKET",
    "MESSAGE",
    "KEEP_ALIVE",
    "SPECAN",
    "LE_PROMISC",
    "EGO_PACKET"
]

# Scapy packets definitions
class Ubertooth_Hdr(Packet):
    name = "Ubertooth header"
    fields_desc = [
        ByteEnumField("packet_type", 0, UBERTOOTH_PACKET_TYPES),
        ByteField("status", None),
        ByteField("channel", None),
        ByteField("clkn_high",None),
        LEIntField("clk_100ns", None),
        SignedByteField("rssi_max", None),
        SignedByteField("rssi_min", None),
        SignedByteField("rssi_avg", None),
        ByteField("rssi_count", None),
        ShortField("unused",None)
    ]
    def pre_dissect(self,s):
        if s[0] == 0x01:
            size = unpack('B',s[14:][5:6])[0]
            return s[0:14+size+FieldsSize.ACCESS_ADDRESS_SIZE+FieldsSize.HEADER_SIZE+FieldsSize.CRC_SIZE]
        else:
            return s

class BTLE_Promiscuous_Data(Packet):
    name = "BTLE Promiscuous Data"
    fields_desc = [
            ByteEnumField("state",None,{0x00 : "access_address",
                           0x01 : "crc_init",
                           0x02 : "hop_interval",
                           0x03 : "hop_increment"})
            ]

class BTLE_Promiscuous_Access_Address(Packet):
    name = "BTLE Promiscuous Access Address"
    fields_desc = [XLEIntField("access_address",None)]

class BTLE_Promiscuous_CRCInit(Packet):
    name = "BTLE Promiscuous CRCInit"
    fields_desc = [LEX3BytesField("crc_init",None)]

class BTLE_Promiscuous_Hop_Interval(Packet):
    name = "BTLE Promiscuous Hop Interval"
    fields_desc = [LEShortField("hop_interval",None)]

class BTLE_Promiscuous_Hop_Increment(Packet):
    name = "BTLE Promiscuous Hop Increment"
    fields_desc = [XByteField("hop_increment",None)]


bind_layers(Ubertooth_Hdr, BTLE, packet_type=0x01)
bind_layers(Ubertooth_Hdr, BTLE_Promiscuous_Data,packet_type=0x05)
bind_layers(BTLE_Promiscuous_Data, BTLE_Promiscuous_Access_Address, state=0x00)
bind_layers(BTLE_Promiscuous_Data, BTLE_Promiscuous_CRCInit, state=0x01)
bind_layers(BTLE_Promiscuous_Data, BTLE_Promiscuous_Hop_Interval, state=0x02)
bind_layers(BTLE_Promiscuous_Data, BTLE_Promiscuous_Hop_Increment, state=0x03)
