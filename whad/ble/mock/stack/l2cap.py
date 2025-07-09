"""
Bluetooth Low Energy Tiny Stack - LLCAP
"""
from typing import List

from scapy.packet import Packet, Raw
from scapy.layers.bluetooth import L2CAP_Hdr, ATT_Hdr
from scapy.layers.bluetooth4LE import BTLE_DATA

from .server import GattServer

class Llcap:
    """L2CAP layer"""

    def __init__(self, conn_handle: int):
        """Initialize state."""
        self.__mtu = 23
        self.__conn_handle = conn_handle

        # Fragmentation
        self.__fifo = b""
        self.__exp_length = 0

        # GATT
        self.__gatt = GattServer()

    def on_pdu(self, packet: Packet, fragment: bool = False) -> List[Packet]:
        """Process an L2CAP packet."""
        if fragment:
            # Enqueue the whole L2CAP packet (including header)
            self.__fifo += bytes(packet[L2CAP_Hdr])
        else:
            # Enqueue received bytes into our fifo
            l2cap_data = packet[L2CAP_Hdr]
            self.__fifo = bytes(l2cap_data)

            # Retrieve expected length ( + header size)
            self.__exp_length = l2cap_data.len + 4

        # Check if we received a complete L2CAP frame
        if len(self.__fifo) >= self.__exp_length:
            result = self.on_l2cap(L2CAP_Hdr(self.__fifo[:self.__exp_length]))
            self.__fifo = self.__fifo[self.__exp_length:]
            self.__exp_length = 0
            return result

        # Nothing to do
        return []

    def on_l2cap(self, packet: Packet) -> list[Packet]:
        """Process complete L2CAP packet."""
        packets: list[Packet] = []

        # Check CID
        if packet.cid == 4:
            # Forward to GATT and convert response packets into L2CAP fragments
            for answer in self.__gatt.on_pdu(packet[ATT_Hdr]):
                packets.extend(self.__convert(answer))
        return packets

    def __convert(self, packet: Packet) -> list[Packet]:
        """Convert GATT packet into fragmented L2CAP packets if required."""
        # Create the answer L2CAP packet
        l2cap_pkt = L2CAP_Hdr(cid=4)/packet

        # Fragment it based on MTU
        l2cap_data = bytes(l2cap_pkt)
        nb_fragments = len(l2cap_data)//self.__mtu
        if nb_fragments*self.__mtu < len(l2cap_data):
            nb_fragments += 1

        if nb_fragments > 1:
            # Build BTLE_DATA packets
            packets = []
            for frag_id in range(nb_fragments):
                fragment = l2cap_data[frag_id*self.__mtu:(frag_id+1)*self.__mtu]
                packets.append(BTLE_DATA(LLID=0x02 if frag_id == 0 else 0x01)/Raw(fragment))
            return packets
        else:
            return [BTLE_DATA(LLID=0x02)/l2cap_pkt]

