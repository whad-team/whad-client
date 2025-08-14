"""Bluetooth Low Energy packet injection module.

This module provides the :class:`whad.ble.connector.injection.Injector` class
to perform packet injection.
"""

from time import sleep

from whad.ble.connector.injector import Injector as BleInjector
from whad.exceptions import UnsupportedCapability
from whad.hub.ble import Direction as BleDirection
from whad.btmesh.injecting import InjectionConfiguration


class Injector(BleInjector):
    """BTMesh injecion connector."""
    domain = 'btmesh'

    def __init__(self, device):
        super().__init__(device)
        self.__connection = None
        self.__synchronized = None

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
        return self.raw_inject(packet)
