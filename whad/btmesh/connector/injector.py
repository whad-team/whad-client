"""Bluetooth Low Energy packet injection module.

This module provides the :class:`whad.ble.connector.injection.Injector` class
to perform packet injection.
"""

from time import sleep

from whad.btmesh.connector import BTMesh
from whad.exceptions import UnsupportedCapability
from whad.hub.ble import Direction as BleDirection
from whad.btmesh.injecting import InjectionConfiguration
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA
from whad.hub.ble import Direction as BleDirection


class Injector(BTMesh):
    """BTMesh injecion connector."""

    def __init__(self, device):
        super().__init__(device)

        # Check if device accepts injection
        if not self.can_inject():
            raise UnsupportedCapability("Inject")

        self.__configuration = InjectionConfiguration()

    def _enable_configuration(self):
        """Enable configuration for injection."""
        return True

    def configure(self, channel=37):
        """Configure this connector to target an active connection."""
        self.stop()
        self.__configuration.channel = channel
        self._enable_configuration()

    @property
    def configuration(self):
        """Current injection configuration."""
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_configuration()

    def inject(self, packet):
        """Inject packet."""
        access_address = 0x8e89bed6
        if self.__configuration.channel is not None:
            channel = self.__configuration.channel
        if hasattr(packet, "metadata") and hasattr(packet.metadata, "channel"):
            channel = packet.metadata.channel
        else:
            channel = 37 # fallback to channel 37

        return self.send_pdu(packet, access_address=access_address, conn_handle=channel,
                             direction=BleDirection.UNKNOWN)
