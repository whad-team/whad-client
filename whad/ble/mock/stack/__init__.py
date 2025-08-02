"""
Bluetooth Low Energy Tiny Stack for unit testing
================================================

This tiny stack implements a basic GATT server and client
with a single emulated GATT profile exposing two services
and a few characteristics.
"""
from typing import Optional, List

from scapy.packet import Packet
from scapy.layers.bluetooth import L2CAP_Hdr

from .l2cap import Llcap
from .server import GattServer
from .client import GattClient

class MalformedPDUError(Exception):
    """Malformed PDU Error."""

class TinyServerStack:
    """Bluetooth Low Energy tiny stack."""

    def __init__(self, conn_handle: int):
        """Initialize BLE stack."""
        self.__conn_handle = conn_handle
        self.__l2cap = Llcap(GattServer, conn_handle)

    def on_pdu(self, packet: Packet) -> Optional[List[Packet]]:
        """Process an incoming BLE PDU and return packets to be sent back.

        :param packet: Incoming BLE packet
        :type packet: scapy.packet.Packet
        """
        # Check packet has an L2CAP header and forward to our L2CAP object
        if L2CAP_Hdr in packet:
            return self.__l2cap.on_pdu(packet[L2CAP_Hdr])
        else:
            # No L2CAP header ? PDU is malformed
            raise MalformedPDUError()

