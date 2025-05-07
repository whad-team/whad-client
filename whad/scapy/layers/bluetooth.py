from scapy.packet import bind_layers, Packet
from scapy.fields import BitField, LEShortField, ByteField, StrFixedLenField
from scapy.layers.bluetooth import SM_Hdr, HCI_Event_LE_Meta, HCI_Command_Hdr, \
    HCI_Event_Command_Complete


class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [
       BitField("authentication", 0, 8)
    ]

bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0b)

class HCI_LE_Meta_Data_Length_Change(Packet):
    name = "Data Length Change"
    fields_desc = [LEShortField("handle", 0),
                   LEShortField("max_tx_octets", 0x001B),
                   LEShortField("max_tx_time", 0x0148),
                   LEShortField("max_rx_octets", 0x001B),
                   LEShortField("max_rx_time", 0x0148)
                   ]
    
class HCI_LE_Set_Data_Length(Packet):
    name = "Set Data Length"
    fields_desc = [LEShortField("handle", 0),
                   LEShortField("tx_octets", 0x001B),
                   LEShortField("tx_time", 0x0148),
                   ]


class HCI_Cmd_LE_Complete_Read_Buffer_Size(Packet):
    name = "LE Read Buffer Size response"
    fields_desc = [LEShortField("acl_pkt_len", 0),
                   ByteField("total_num_acl_pkts", 0)]

class HCI_Cmd_LE_Set_Event_Mask(Packet):
    name = "LE Set Event Mask"
    fields_desc = [StrFixedLenField("mask", b"\x1f\x00\x00\x00\x00\x00\x00\x00", 8)]

class HCI_Cmd_Read_Buffer_Size(Packet):
    name = "Read Buffer Size"


class HCI_Cmd_Complete_Read_Buffer_Size(Packet):
    name = "Read Buffer Size response"
    fields_desc = [LEShortField("acl_pkt_len", 0),
                   ByteField("total_num_acl_pkts", 0)]

# HCI LE events
bind_layers(HCI_Command_Hdr, HCI_LE_Set_Data_Length, ogf=0x08, ocf=0x0022)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Buffer_Size, ogf=0x04, opcode=0x0005)

# HCI LE commands
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Data_Length_Change, event=7)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Event_Mask, opcode=0x2001) # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Read_Buffer_Size, opcode=0x2002)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Buffer_Size, opcode=0x1005)  # noqa: E501