"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from whad.bt_mesh.stack import PBAdvBearerLayer
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU
from whad.bt_mesh.connectors import BTMesh


class Provisionee(BTMesh):
    def __init__(self, device):
        super().__init__(
            device, stack=PBAdvBearerLayer, options={"role": "provisionee"}
        )

        self.is_provisioned = False

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU

        :param packet: Packet received
        :type packet: Packet
        """
        if not self.is_provisioned and packet.haslayer(EIR_PB_ADV_PDU):
            self._stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
