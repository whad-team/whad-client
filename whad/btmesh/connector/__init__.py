"""
Bluetooth Mesh Base connector.
================================

Manages basic Tx/Rx. (Based on BLE sniffer because it works)
"""
from whad.ble.connector.base import BLE
from whad.exceptions import UnsupportedCapability, RequiredImplementation, \
    WhadDeviceDisconnected

from whad.hub.ble import Direction as BleDirection

from whad.btmesh.connector.bearer import Bearer, AdvBearer

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
        
        # By default, use the ADV bearer
        self.set_bearer(AdvBearer)
        
        # Configure a default random address 
        self.bearer.configure(bd_address="AA:BB:CC:DD:EE:FF")

    def set_bearer(self, bearer):
        """
        Configure and instantiate the bearer in use by the connector.

        :param bearer: `Bearer` class
        :type bearer: `Bearer`
        """
        self.bearer = bearer(self)
        
    def on_adv_pdu(self, packet):
        """
        Process a received advertising Mesh packet.
        
        
        """
        if self.bearer is not None:
            # Redirect the PDU through the bearer if available
            self.bearer.on_adv_pdu(packet)

    def send(self, packet):
        """
        Send a Mesh PDU through the bearer (if instantiated).

        :param packet: Mesh PDU to transmit
        :type packet: bytes
        """
        if self.bearer is not None:
            return self.bearer.send(packet)

        return False

    def _start(self):
        """
        Performs the initial start command on BLE parent class.
        """
        super().start()


    def _stop(self):
        """
        Performs the initial stop command on BLE parent class.
        """
        super().stop()


    def start(self):
        """
        Start the underlying bearer.
        """
        if self.bearer is not None:
            return self.bearer.start()
        return False

    def stop(self):
        """
        Stop the underlying bearer.
        """
        if self.bearer is not None:
            return self.bearer.stop()
        return False