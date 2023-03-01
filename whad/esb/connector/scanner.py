"""
ESB Scanner connector
=====================

This module provides a scanner connector :class:`whad.esb.connector.scanner.Scanner`
for WHAD ESB devices, allowing to discover available Enhanced ShockBurst devices.

It relies on the use of the WHAD ESB protocol. It puts the hardware adapter in
pseudo-promiscuous sniffing mode and iterates over the channels to discover
Enhanced ShockBurst communications. The packets are then processed to extract
device informations.


This mode is only available with WHAD devices that support promiscuous sniffing.

This connector must be instantiated with a compatible WHAD device, as shown below:

.. code-block:: python

    device = WhadDevice.create('uart0')
    scanner = Scanner(device)

If the underlying device does not support promiscuous sniffing, this connector will raise
an :class:`UnsupportedCapability` exception.

"""
from scapy.packet import Packet
from typing import Iterator
from whad.esb.connector import ESB, message_filter, is_message_type, UnsupportedCapability
from whad.esb.scanning import CommunicatingDevicesDB, CommunicatingDevice

class Scanner(ESB):
    """
    ESB Observer interface for compatible WHAD device.
    """

    def __init__(self, device):
        """Instantiate scanner connector over `device`.

        :param  device: ESB WHAD device instance
        :type   device: :class:`whad.device.WhadDevice`
        """
        super().__init__(device)
        self.__db = CommunicatingDevicesDB()

        # Check device accept sniffing mode
        if not self.can_sniff():
            raise UnsupportedCapability('Sniff')
        else:
            self.stop()
            super().sniff(show_acknowledgements=True, address="FF:FF:FF:FF:FF")

    def start(self):
        """Start the ESB scanner.

        Calling this method resets the discovered devices database and put
        the WHAD device into ESB scanning mode.
        """
        self.__db.reset()
        super().start()

    def sniff(self) -> Iterator[Packet]:
        """
        Listen and yield incoming ESB PDUs.
        """
        while True:
            if self.support_raw_pdu():
                message_type = "raw_pdu"
            else:
                message_type = "pdu"

            message = self.wait_for_message(filter=message_filter('esb', message_type))
            packet = self.translator.from_message(message.esb, message_type)
            yield packet


    def discover_devices(self, minimal_rssi = None, filter_address = None) -> Iterator[CommunicatingDevice]:
        """
        Parse incoming packets and yield discovered devices.

        :param  minimal_rssi:       Minimal RSSI level
        :type   minimal_rssi:       float, optional
        :param  filter_address:     ESB address of a device to discover
        :type   filter_address:     :class:`whad.esb.bdaddr.ESBAddress`, optional
        """
        for packet in self.sniff():
            #print(packet)
            #print(packet.metadata)
            if minimal_rssi is None or packet.metadata.rssi > minimal_rssi:
                device = self.__db.on_device_found(
                    packet.metadata.rssi,
                    packet,
                    filter_addr=filter_address
                )
                if device is not None:
                    yield device
