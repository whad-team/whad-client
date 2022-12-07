
from whad.ble.connector import BLE
from whad.ble.scanning import AdvertisingDevicesDB
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

    def discover_devices(self, minimal_rssi=None, filter_address=None):
        """
        Parse incoming advertisements and return new devices.
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
