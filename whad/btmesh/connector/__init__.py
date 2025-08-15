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

        if not self.can_sniff_advertisements:
            raise UnsupportedCapability("SniffAdvertisements")

    def bt_mesh_filter(self, packet, ignore_regular_adv):
        """
        Filter out non Mesh advertising packets
        """
        if BTLE_ADV in packet:
            if hasattr(packet, "data"):
                if EIR_Hdr in packet and (
                    any([i.type in (0x29, 0x2A, 0x2B) for i in packet.data])
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
