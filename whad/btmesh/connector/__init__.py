"""
Bluetooth Mesh Base connector.
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""

from scapy.layers.bluetooth4LE import (
    BTLE_ADV,
    EIR_Hdr,
)
from whad.ble.connector.base import BLE
from whad.exceptions import UnsupportedCapability
from whad.exceptions import WhadDeviceDisconnected

from scapy.layers.bluetooth4LE import BTLE_ADV, BTLE_ADV_NONCONN_IND
from whad.hub.ble import Direction as BleDirection
'''
class Bearer:
    def __init__(self, connector):
        self.connector = connector

    def start(self):
        pass

    def stop(self):
        pass
'''
class BTMesh(BLE):
    """
    Connector class for Bluetooth Mesh device.
    Should not be used as is, inherited by Provisionee or Provisonner connectors (otherwise not provisioned and no stack instanced !!)

    Allows user code or shell to interact with the network, and also manages callbacks on received messages.
    """

    domain = "btmesh"

    def __init__(
        self,
        device,
    ):
        """
        Creates a BTMesh base connector

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :raises UnsupportedCapability: Device Cannot sniff
        """
        super().__init__(device)
        
        self.is_listening = False

        # Default BD address to facilitate filtering
        self.mesh_bd_address = "AB:CD:EF:AB:CD:EF"

        # We use a random address by default
        super().set_bd_address(self.mesh_bd_address, public=False)


    def on_adv_pdu(self, packet):
        """
        Process a received advertising Mesh packet.
        Adds it to queue
        """
        if not self.bt_mesh_filter(packet, True):
            return
        
        self.process_rx_packets(packet)

    def start_adv_bearer(self):
        """
        Start the adv bearer. 
        """

        if not self.can_scan():
            raise UnsupportedCapability("Scan")

        scan_mode = self.enable_scan_mode(interval=20)
        if not scan_mode:
            return False


        if super().start():
            self.is_listening = True

            return True
        return False


    def send_raw(self, packet, channel=None, repeat=2):
        return self.send_adv_bearer(packet, channel=channel, repeat=repeat)
        
    def send_adv_bearer(self, packet, channel=None, repeat=2):
        """
        Sends the packet through the BLE advertising bearer

        :param packet: Packet to send
        :type packet: Packet (EIR_Element subclass)
        :param channel: [TODO:description], defaults to 37
        :type channel: [TODO:type], optional
        """

        # If channel is None, transmit on every channel 37,38 & 39
        if channel is None:
            channel = 0

        adv_pdu = BTLE_ADV_NONCONN_IND(
                AdvA=self.mesh_bd_address,
                data=packet
        )
        for _ in range(repeat):
            res = self.send_adv_pdu(
                    adv_pdu,
                    channel = channel
            )
        
        return res
    
    def start(self):
        return self.start_adv_bearer()

    def bt_mesh_filter(self, packet, ignore_regular_adv=True):
        """
        Filter out non Mesh advertising packets
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any(
                        [
                            isinstance(i, EIR_Hdr) and i.type in (0x29, 0x2A, 0x2B)
                            for i in packet.data
                        ]
                    )
                    or any(
                        h in [[0x1827], [0x1828]]
                        for h in [
                            i.svc_uuids
                            for i in packet.data
                            if hasattr(i, "svc_uuids") and not ignore_regular_adv
                        ]
                    )
                ):
                    return True

        return False
