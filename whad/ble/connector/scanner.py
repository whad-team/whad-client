
from whad.ble.connector import BLE
from whad.ble import UnsupportedCapability, message_filter, BleAdvType,\
    BTLE_ADV_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_NONCONN_IND, BTLE_ADV_SCAN_IND,\
    BTLE_SCAN_RSP

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
        # correlation table
        scapy_corr_adv = {
            BleAdvType.ADV_IND: BTLE_ADV_IND,
            BleAdvType.ADV_NONCONN_IND: BTLE_ADV_NONCONN_IND,
            BleAdvType.ADV_DIRECT_IND: BTLE_ADV_DIRECT_IND,
            BleAdvType.ADV_SCAN_IND: BTLE_ADV_SCAN_IND,
            BleAdvType.ADV_SCAN_RSP: BTLE_SCAN_RSP
        }

        while True:
            message = self.wait_for_message(filter=message_filter('ble', 'adv_pdu'))
            # Convert message from rebuilt PDU
            if message.ble.adv_pdu.adv_type in scapy_corr_adv:
                if message.ble.adv_pdu.adv_type == BleAdvType.ADV_SCAN_RSP:
                    yield (
                        message.ble.adv_pdu.rssi,
                        scapy_corr_adv[message.ble.adv_pdu.adv_type](
                            bytes(message.ble.adv_pdu.bd_address) + bytes(message.ble.adv_pdu.scanrsp_data)
                        )
                    )
                else:
                    yield (
                        message.ble.adv_pdu.rssi,
                        scapy_corr_adv[message.ble.adv_pdu.adv_type](
                            bytes(message.ble.adv_pdu.bd_address) + bytes(message.ble.adv_pdu.scanrsp_data)
                        )
                    )
