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
from scapy.packet import Packet
from typing import Iterator
from whad.hub.ble import BleAdvPduReceived, BleRawPduReceived
from whad.ble.connector import BLE
from whad.ble.scanning import AdvertisingDevicesDB, AdvertisingDevice
from whad.ble import UnsupportedCapability, message_filter, BleAdvType,\
    BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,\
    BTLE_SCAN_RSP, BTLE_ADV

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
            self.stop()
            self.sniff_advertisements()
        else:
            self.stop()
            self.enable_scan_mode(True)

    def start(self):
        """Start the BLE scanner.

        Calling this method resets the discovered devices database and put
        the WHAD device into BLE scanning mode.
        """
        self.__db.reset()
        super().start()


    def discover_devices(self, minimal_rssi = None, filter_address = None) -> Iterator[AdvertisingDevice]:
        """
        Parse incoming advertisements and yield discovered devices.

        :param  minimal_rssi:       Minimal RSSI level
        :type   minimal_rssi:       float, optional
        :param  filter_address:     BD address of a device to discover
        :type   filter_address:     :class:`whad.ble.bdaddr.BDAddress`, optional
        """
        for advertisement in self.sniff():
            if minimal_rssi is None or advertisement.metadata.rssi > minimal_rssi:
                devices = self.__db.on_device_found(
                    advertisement.metadata.rssi,
                    advertisement,
                    filter_addr=filter_address
                )
                for device in devices:
                    if device is not None and device.scanned:
                        yield device


    def sniff(self) -> Iterator[Packet]:
        """
        Listen and yield incoming advertising PDUs.
        """

        while True:
            if self.support_raw_pdu():
                message_type = BleRawPduReceived
            else:
                message_type = BleAdvPduReceived

            message = self.wait_for_message(filter=message_filter(message_type))
            # Convert message from rebuilt PDU
            packet = message.to_packet()
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
