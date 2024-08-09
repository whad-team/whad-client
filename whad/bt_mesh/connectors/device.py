"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from random import randbytes
from whad.ble.connector import Sniffer
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_NONCONN_IND, EIR_Hdr
from whad.ble import UnsupportedCapability, message_filter, BleDirection
from queue import Queue


from whad.bt_mesh.stack import PBAdvBearerLayer
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU
from whad.bt_mesh.connectors import BTMesh

class Device(BTMesh):
    def __init__(self, device):
        super().__init__(device, stack=PBAdvBearerLayer, options={"role": "device"})

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU

        :param packet: Packet received
        :type packet: Packet
        """
        if packet.haslayer(EIR_PB_ADV_PDU):
            self._stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
