import ctypes
import functools
import socket
import struct
import select
from ctypes import sizeof
from scapy.data import MTU
from scapy.consts import WINDOWS
from scapy.supersocket import SuperSocket
from scapy.packet import bind_layers, Packet
from scapy.fields import BitField, LEShortField
from scapy.error import warning
from scapy.layers.bluetooth import BluetoothUserSocket, BluetoothSocketError, BluetoothCommandError, \
    HCI_Hdr, SM_Hdr, HCI_Event_LE_Meta, HCI_Command_Hdr, HCI_Event_Command_Complete
from scapy.fields import ByteField, ShortField, StrFixedLenField

class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [
       BitField("authentication", 0, 8)
    ]

bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0b)


class sockaddr_hci(ctypes.Structure):
    _fields_ = [
        ("sin_family", ctypes.c_ushort),
        ("hci_dev", ctypes.c_ushort),
        ("hci_channel", ctypes.c_ushort),
    ]

class BluetoothUserSocketFixed(SuperSocket):
    desc = "read/write H4 over a Bluetooth user channel"

    def __init__(self, adapter_index=0):
        if WINDOWS:
            warning("Not available on Windows")
            return
        # s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)  # noqa: E501
        # s.bind((0,1))

        # yeah, if only
        # thanks to Python's weak ass socket and bind implementations, we have
        # to call down into libc with ctypes

        sockaddr_hcip = ctypes.POINTER(sockaddr_hci)
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

        socket_c = libc.socket
        socket_c.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int)
        socket_c.restype = ctypes.c_int

        bind = libc.bind
        bind.argtypes = (ctypes.c_int,
                         ctypes.POINTER(sockaddr_hci),
                         ctypes.c_int)
        bind.restype = ctypes.c_int

        ########
        # actual code

        s = socket_c(31, 3, 1)  # (AF_BLUETOOTH, SOCK_RAW, HCI_CHANNEL_USER)
        if s < 0:
            raise BluetoothSocketError("Unable to open PF_BLUETOOTH socket")
        self.hci_fd = s

        sa = sockaddr_hci()
        sa.sin_family = 31  # AF_BLUETOOTH
        sa.hci_dev = adapter_index  # adapter index
        sa.hci_channel = 1   # HCI_USER_CHANNEL

        r = bind(s, sockaddr_hcip(sa), sizeof(sa))
        if r != 0:
            raise BluetoothSocketError("Unable to bind")

        self.ins = self.outs = socket.fromfd(s, 31, 3, 1)

    def send_command(self, cmd):
        opcode = cmd.opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.type == 0x04 and r.code == 0xe and r.opcode == opcode:
                if r.status != 0:
                    raise BluetoothCommandError("Command %x failed with %x" % (opcode, r.status))  # noqa: E501
                return r

    def recv(self, x=MTU):
        return HCI_Hdr(self.ins.recv(x))

    def readable(self, timeout=0):
        (ins, outs, foo) = select.select([self.ins], [], [], timeout)
        return len(ins) > 0

    def flush(self):
        while self.readable():
            self.recv()

    def close(self):
        if self.closed:
            return

        # Properly close socket so we can free the device
        ctypes.cdll.LoadLibrary("libc.so.6")
        libc = ctypes.CDLL("libc.so.6")

        close = libc.close
        close.restype = ctypes.c_int
        self.closed = True
        if hasattr(self, "outs"):
            if not hasattr(self, "ins") or self.ins != self.outs:
                if self.outs and (WINDOWS or self.outs.fileno() != -1):
                    close(self.outs.fileno())
        if hasattr(self, "ins"):
            if self.ins and (WINDOWS or self.ins.fileno() != -1):
                close(self.ins.fileno())
        close(self.hci_fd)

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
bind_layers(HCI_Command_Hdr, HCI_LE_Set_Data_Length, opcode=0x2022)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Buffer_Size, opcode=0x1005)

# HCI LE commands
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Data_Length_Change, event=7)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Event_Mask, opcode=0x2001) # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Read_Buffer_Size, opcode=0x2002)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Buffer_Size, opcode=0x1005)  # noqa: E501