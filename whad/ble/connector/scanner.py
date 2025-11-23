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
from typing import Iterator, List, Optional

from scapy.packet import Packet
from scapy.layers.bluetooth4LE import BTLE_ADV

from whad.hub.ble import BleAdvPduReceived, BleRawPduReceived
from whad.exceptions import UnsupportedCapability, WhadDeviceNotReady

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

    def start(self) -> bool:
        """Start the BLE scanner.

        Calling this method resets the discovered devices database and put
        the WHAD device into BLE scanning mode.
        """
        self.__db.reset()
        return super().start()

    def stop(self) -> bool:
        """Stop scanning.

        Stop scanning for devices, disable scan mode if used.
        """
        # Stop scanning
        result = super().stop()

        # Disable active scan mode (passive mode by default)
        if self.can_scan():
            self.enable_scan_mode(False)

        # Send result
        return result

    def __enter__(self) -> 'Scanner':
        """Special method used to use this connector as a context manager."""
        # Make sure we are started
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
        return self

    def __exit__(self, exc_type, exc_value, exc_traceback):
        """Special method used to close the connector when a
        context manager is done with it."""
        if self.started:
            if not self.stop():
                raise WhadDeviceNotReady()

    def discover_devices(self, minimal_rssi = None, filter_address = None,
                         timeout: Optional[float] = None, updates: bool = False) -> Iterator[AdvertisingDevice]:
        """
        Parse incoming advertisements and yield discovered devices. If `updates`
        is set to `True`, all discovered devices will be reported with updated
        information.

        :param  minimal_rssi:       Minimal RSSI level
        :type   minimal_rssi:       float, optional
        :param  filter_address:     BD address of a device to discover
        :type   filter_address:     :class:`whad.ble.bdaddr.BDAddress`, optional
        :param  timeout:            Timeout in seconds
        :type   timeout:            float, optional
        :param  updates:            Enable/disable reporting updated information
                                    about already discovered devices
        :type   updates:            bool
        """

        # Start sniffing
        start_time = time()
        for advertisement in self.sniff(timeout=timeout):
            if minimal_rssi is None or advertisement.metadata.rssi > minimal_rssi:
                devices = self.__db.on_device_found(
                    advertisement.metadata.rssi,
                    advertisement,
                    filter_addr=filter_address,
                    updates=updates
                )

                for device in devices:
                    yield device

            if (timeout is not None) and (time() - start_time > timeout):
                break

    def sniff(self, messages: Optional[List] = None, timeout: Optional[float] = None) -> Iterator[Packet]:
        """
        Listen and yield incoming advertising PDUs.
        """
        # Make sure the hardware interface is started
        if not self.started:
            if not self.start():
                raise WhadDeviceNotReady()
            stop_on_exit = True
        else:
            stop_on_exit = False

        # Determine the type of message we are expecting to receive
        if self.support_raw_pdu():
            message_type = BleRawPduReceived
        else:
            message_type = BleAdvPduReceived

        # Loop until timeout reached or stopped
        start_anchor = time()
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

                # Make sure we did not run over a configured timeout, if so
                # exit the main while loop
                if timeout is not None:
                    if (time() - start_anchor) >= timeout:
                        break

        # Stop current mode if we enabled it
        if stop_on_exit:
            if not self.stop():
                raise WhadDeviceNotReady()

    def clear(self):
        """
        Clear device database.
        """
        self.__db.reset()

