
from whad.ble.connector import BLE
from whad.ble import UnsupportedCapability, message_filter, BleAdvType,\
    BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,\
    BTLE_SCAN_RSP, BTLE_ADV
from ...protocol.device_pb2 import BtLE

class Scanner(BLE):
    """
    BLE Observer interface for compatible WHAD device.
    """

    def __init__(self, device):
        super().__init__(device)

        # Check device accept scanning mode
        if not self.can_scan():
            raise UnsupportedCapability('Scan')
        else:
            self.stop()
            self.enable_scan_mode(True)

    def discover_devices(self):
        """
        Listen incoming messages and yield advertisements.
        """

        while True:
            message = self.wait_for_message(filter=message_filter('ble', 'adv_pdu'))
            
            # Convert message from rebuilt PDU
            packet = self._build_scapy_packet_from_message(message.ble, 'adv_pdu')

            # Force TxAdd value to propagate the address type
            if message.ble.adv_pdu.addr_type > 0:
                packet.getlayer(BTLE_ADV).TxAdd = 1
            yield packet
