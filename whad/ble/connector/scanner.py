"""
BLE Scanner connector
=====================

This module provides a scanner connector :class:`whad.ble.connector.scanner.Scanner`
for WHAD BLE devices, allowing to discover available BLE devices.

It implements two different scanning approaches:

* The first one is based on a *normal device scanning* based on WHAD BLE protocol:
  it puts the hardware adapter in device discovery mode and grab each advertisement
  received.

* The second one puts the hardware adapter in *sniffing mode* and sniffs advertisements
  sent on default channels. This mode is only available with WHAD devices that support
  sniffing.

This connector must be instantiated with a compatible WHAD device, as shown below:

.. code-block:: python

    device = WhadDevice.create('uart0')
    scanner = Scanner(device)

If the underlying device does not support scanning, this connector will raise
an :class:`UnsupportedCapability` exception.

"""
from time import time
from typing import Iterator, List

from scapy.packet import Packet
from scapy.layers.bluetooth4LE import BTLE_ADV

from whad.hub.ble import BleAdvPduReceived, BleRawPduReceived
from whad.exceptions import UnsupportedCapability

from .base import BLE
from ..scanning import AdvertisingDevicesDB, AdvertisingDevice

class Scanner(BLE):
    """
    BLE Observer interface for compatible WHAD device.
    """

    domain = 'ble'

    def __init__(self, device):
        """Instantiate scanner connector over `device`.

        :param  device: BLE WHAD device instance
        :type   device: :class:`whad.device.WhadDevice`
        """
        super().__init__(device)
        self.__db = AdvertisingDevicesDB()

        # Check device accept scanning mode
        if not self.can_scan():
            # Does our device accept sniffing mode and is able of sniffing advertising reports ?
            if not self.can_sniff_advertisements():
                raise UnsupportedCapability('Scan')
            # Stop current mode
            self.stop()

            # Set advertisement sniffing
            self.sniff_advertisements()
        else:
            # Stop current mode
            self.stop()

            # Enable active scanning
            self.enable_scan_mode(True)

    def start(self):
        """Start the BLE scanner.

        Calling this method resets the discovered devices database and put
        the WHAD device into BLE scanning mode.
        """
        self.__db.reset()
        super().start()

    def stop(self):
        """Stop scanning.

        Stop scanning for devices, disable scan mode if used.
        """
        # Stop scanning
        super().stop()

        # Disable active scan mode (passive mode by default)
        if self.can_scan():
            self.enable_scan_mode(False)

    def discover_devices(self, minimal_rssi = None, filter_address = None,
                         timeout: float = None) -> Iterator[AdvertisingDevice]:
        """
        Parse incoming advertisements and yield discovered devices.

        :param  minimal_rssi:       Minimal RSSI level
        :type   minimal_rssi:       float, optional
        :param  filter_address:     BD address of a device to discover
        :type   filter_address:     :class:`whad.ble.bdaddr.BDAddress`, optional
        :param  timeout:            Timeout in seconds
        :type   timeout:            float, optional
        """
        start_time = time()
        for advertisement in self.sniff(timeout=timeout):
            if minimal_rssi is None or advertisement.metadata.rssi > minimal_rssi:
                devices = self.__db.on_device_found(
                    advertisement.metadata.rssi,
                    advertisement,
                    filter_addr=filter_address
                )

                for device in devices:
                    yield device

            if (timeout is not None) and (time() - start_time > timeout):
                break

    def sniff(self, messages: List = None, timeout: float = None) -> Iterator[Packet]:
        """
        Listen and yield incoming advertising PDUs.
        """
        if self.support_raw_pdu():
            message_type = BleRawPduReceived
        else:
            message_type = BleAdvPduReceived

        # Loop until timeout reached or stopped
        while True:
            # Switch to sniffing mode
            for message in super().sniff(messages=(message_type), timeout=timeout):
                # Convert message from rebuilt PDU
                packet = message.to_packet()
                if packet is not None:
                    self.monitor_packet_rx(packet)
                    # Force TxAdd value to propagate the address type
                    if isinstance(message, BleAdvPduReceived):
                        if message.addr_type > 0:
                            packet.getlayer(BTLE_ADV).TxAdd = 1
                    yield packet

    def clear(self):
        """
        Clear device database.
        """
        self.__db.reset()
