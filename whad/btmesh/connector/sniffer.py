"""
Bluetooth Mesh Sniffer Connector

Basic Bluetooth Mesh Passive Sniffer
"""

from scapy.layers.bluetooth4LE import BTLE_ADV, EIR_Hdr
from whad.btmesh.connector.provisionee import Provisionee
from whad.scapy.layers.btmesh import BTMesh_Obfuscated_Network_PDU


class BTMeshSniffer(Provisionee):
    """
    Connector class for BTMesh sniffing
    """

    def __init__(
        self, device, net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
    ):
        """
        Init the sniffer

        If directly "auto_provision" (with address 0) to passivly listen on network

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :param net_key: net_key of the network we want to listen on, defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        """

        # Address of the node is 0, which does not exist so we do not listen to anything
        super().__init__(device, net_key=net_key, unicast_addr=b"\x00\x00")

        self.sniffing_only = True

        self.profile.auto_provision()

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Logic in subclasses

        :param packet: Packet received
        :type packet: Packet
        """
        # if the packet is not a Network PDU, we display it directly (its a beacon, no crypto)
        if not packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            packet.show()
        else:
            self._main_stack.on_net_pdu_received(
                packet.getlayer(BTMesh_Obfuscated_Network_PDU), packet.metadata.rssi
            )

    def send_raw(packet, channel=37):
        """
        IN sniffing mode, we never send anything

        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """
        pass
