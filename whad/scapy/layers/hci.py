from whad.ble.stack.constants import BT_MANUFACTURERS
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, LEShortEnumField, LEShortField, \
    StrField, StrNullField, LELongField, XByteField
from scapy.layers.bluetooth import HCI_Command_Hdr, HCI_Event_Command_Complete, \
    HCI_Event_LE_Meta, LEMACField
from scapy.layers.bluetooth4LE import BTLEChanMapField

HCI_VERSIONS = LMP_VERSIONS = {
    0x00:   "1.0b",
    0x01:   "1.1",
    0x02:   "1.2",
    0x03:   "2.0",
    0x04:   "2.1",
    0x05:   "3.0",
    0x06:   "4.0",
    0x07:   "4.1",
    0x08:   "4.2",
    0x09:   "5.0",
    0x0a:   "5.1",
    0x0b:   "5.2",
    0x0c:   "5.3",
}

class HCI_Cmd_Read_Local_Version_Information(Packet):
    name = "Read Local Version Information Command"
    fields_desc = []


class HCI_Cmd_Complete_Read_Local_Version_Information(Packet):
    name = "Read Local Version Information Command Complete"
    fields_desc = [
        ByteEnumField("hci_version", None, HCI_VERSIONS),
        LEShortField("hci_subversion", None),
        ByteEnumField("lmp_version", None, LMP_VERSIONS),
        LEShortEnumField("company_identifier", None, BT_MANUFACTURERS),
        LEShortField("lmp_subversion", None),
    ]


class HCI_Cmd_Read_Local_Name(Packet):
    name = "Read Local Name"
    fields_desc = []


class HCI_Cmd_Complete_Read_Local_Name(Packet):
    name = "Read Local Name"
    fields_desc = [
                    StrNullField("local_name", None),
                    StrField("padding",None)
    ]

class HCI_Cmd_LE_Read_Supported_States(Packet):
    name = "LE Read Supported States Command"
    fields_desc = []


class HCI_Cmd_Complete_LE_Read_Supported_States(Packet):
    name = "LE Read Supported States Command Complete"
    fields_desc = [
        LELongField("supported_states", None)
    ]

class HCI_LE_Meta_Enhanced_Connection_Complete(Packet):
    name = "Enhanced Connection Complete"
    fields_desc = [
        ByteEnumField("status", 0, {0: "success"}),
        LEShortField("handle", 0),
        ByteEnumField("role", 0, {0: "master"}),
        ByteEnumField("patype", 0, {0: "public", 1: "random"}),
        LEMACField("paddr", None),
        LEMACField("localresolvprivaddr", None),
        LEMACField("peerresolvprivaddr", None),
        LEShortField("interval", 54),
        LEShortField("latency", 0),
        LEShortField("supervision", 42),
        XByteField("clock_latency", 5),
    ]


# Vendor specific commands - BD address modification
# Manufacturer : Texas Instruments (13)
class HCI_Cmd_TI_Write_BD_Address(Packet):
    name = "TI Write BD Address"
    fields_desc = [
        LEMACField("addr","\x00\x01\x02\x03\x04\x05")
    ]

# Manufacturer : Broadcom (15)
class HCI_Cmd_BCM_Write_BD_Address(Packet):
    name = "BCM Write BD Address"
    fields_desc = [
        LEMACField("addr","\x00\x01\x02\x03\x04\x05")
    ]

# Manufacturer : Zeevo (18)
class HCI_Cmd_Zeevo_Write_BD_Address(Packet):
    name = "Zeevo Write BD Address"
    fields_desc = [
        LEMACField("addr","\x00\x01\x02\x03\x04\x05")
    ]


# Manufacturer : Ericsson (0 / 57)
class HCI_Cmd_Ericsson_Write_BD_Address(Packet):
    name = "Ericsson Write BD Address"
    fields_desc = [
        LEMACField("addr","\x00\x01\x02\x03\x04\x05")
    ]

# Manufacturer : Cambridge Silicon Radios (10)
class HCI_Cmd_CSR_Write_BD_Address(Packet):
    name = "CSR Write BD Address"
    fields_desc = [
        LEMACField("addr","\x00\x01\x02\x03\x04\x05")
    ]

    def post_build(self,p,pay):
        payload = bytearray(b"\xc2\x02\x00\x0c\x00\x11G\x03p\x00\x00\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

        payload[17] = p[2]
        payload[19] = p[0]
        payload[20] = p[1]
        payload[21] = p[3]
        payload[23] = p[4]
        payload[24] = p[5]

        return payload

class HCI_Cmd_CSR_Reset(Packet):
    name = "CSR Write BD Address"
    fields_desc = [
        StrField("bytes",b"\xc2\x02\x00\t\x00\x00\x00\x01@\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
    ]


# Manufacturer : ST (48)
class HCI_Cmd_ST_Write_BD_Address(Packet):
    name = "ST Write BD Address"
    fields_desc = [
        ByteField("user_id", 0xfe),
        ByteField("data_len",0x06),
        LEMACField("addr","\x00\x01\x02\x03\x04\x05"),
        StrField("padding","\x00"*247)
    ]


class HCI_Cmd_LE_Set_Host_Channel_Classification(Packet):
	name = "HCI Command LE Set Host Channel Classification"
	fields_desc = [
		BTLEChanMapField("chM" ,None)
	]


bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Version_Information,                        opcode=0x1001)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Version_Information,    opcode=0x1001)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Read_Local_Name,			                            opcode=0x0c14)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Name,                   opcode=0x0c14)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Supported_States,                              opcode=0x201c)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Read_Supported_States,          opcode=0x201c)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Host_Channel_Classification,                    opcode=0x2014)

bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Enhanced_Connection_Complete,                    event=0xa)


bind_layers(HCI_Command_Hdr, HCI_Cmd_ST_Write_BD_Address,                                   opcode=0xfc22)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Zeevo_Write_BD_Address,                                opcode=0xfc01)
bind_layers(HCI_Command_Hdr, HCI_Cmd_TI_Write_BD_Address,                                   opcode=0xfc06)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Ericsson_Write_BD_Address,                             opcode=0xfc0d)
bind_layers(HCI_Command_Hdr, HCI_Cmd_BCM_Write_BD_Address,                                  opcode=0xfc01)
bind_layers(HCI_Command_Hdr, HCI_Cmd_CSR_Write_BD_Address,                                  opcode=0xfc00)
bind_layers(HCI_Command_Hdr, HCI_Cmd_CSR_Reset,                                             opcode=0xfc00)
