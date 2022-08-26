from whad.ble.stack.constants import BT_MANUFACTURERS
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteEnumField, ByteField, LEShortEnumField, LEShortField, \
    StrField, StrNullField, LELongField
from scapy.layers.bluetooth import HCI_Command_Hdr, HCI_Event_Command_Complete

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


bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Version_Information,                        opcode=0x1001)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Version_Information,    opcode=0x1001)
bind_layers(HCI_Command_Hdr,HCI_Cmd_Read_Local_Name,			                            opcode=0x0c14)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Local_Name,                   opcode=0x0c14)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Supported_States,                              opcode=0x201c)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Read_Supported_States,          opcode=0x201c)
