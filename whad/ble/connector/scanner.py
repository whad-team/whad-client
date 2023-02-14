"""
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
from typing import Iterator
from whad.ble.bdaddr import BDAddress
from whad.ble.connector import BLE
from whad.ble.scanning import AdvertisingDevicesDB, AdvertisingDevice
from whad.ble import UnsupportedCapability, message_filter, BleAdvType,\
    BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,\
    BTLE_SCAN_RSP, BTLE_ADV

class Scanner(BLE):
    """
    BLE Observer interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)
        self.__db = AdvertisingDevicesDB()
        # Check device accept scanning mode
        if not self.can_scan():
            raise UnsupportedCapability('Scan')
        else:
            self.stop()
            self.enable_scan_mode(True)

    def start(self):
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
                device = self.__db.on_device_found(
                    advertisement.metadata.rssi,
                    advertisement,
                    filter_addr=filter_address
                )
                if device is not None:
                    yield device

    def sniff(self):
        """
        Listen incoming messages and yield advertisements.
        """

        while True:
            if self.support_raw_pdu():
                message_type = "raw_pdu"
            else:
                message_type = "adv_pdu"

            message = self.wait_for_message(filter=message_filter('ble', message_type))
            # Convert message from rebuilt PDU
            packet = self._build_scapy_packet_from_message(message.ble, message_type)
            # Force TxAdd value to propagate the address type
            if message.ble.adv_pdu.addr_type > 0:
                packet.getlayer(BTLE_ADV).TxAdd = 1
            yield packet
