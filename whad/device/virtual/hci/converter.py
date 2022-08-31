from scapy.layers.bluetooth import HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, \
    HCI_LE_Meta_Connection_Complete
from scapy.compat import raw
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleAdvType

class HCIConverter:
    """
    This class converts HCI event to WHAD BLE packets and WHAD BLE packets to HCI commands.
    It allows to harmonise the representation of Bluetooth Low Energy traffic, as WHAD expects
    Link Layer-like packets.

    Obviously, some packets can't be converted easily from a representation to the other one without
    losing information or making asumptions. As a result, you should expect some limitations.
    """

    def __init__(self):
        pass

    def process_event(self, event):
        """
        Converts an HCI event to the corresponding Link Layer packet (if possible).
        """
        if HCI_Event_LE_Meta in event:
            if HCI_LE_Meta_Advertising_Reports in event:
                return self.process_advertising_reports(event[HCI_LE_Meta_Advertising_Reports:])
            elif HCI_LE_Meta_Connection_Complete in event:
                return self.process_connection_complete(events[HCI_LE_Meta_Connection_Complete:])


    def process_advertising_reports(self, reports):
        messages = []
        for report in reports.reports:

            msg = Message()
            adv_type = BleAdvType.ADV_UNKNOWN
            if report.type == 0:
                adv_type = BleAdvType.ADV_IND
            elif report.type == 1:
                adv_type = BleAdvType.ADV_DIRECT_IND
            elif report.type == 2:
                adv_type = BleAdvType.ADV_SCAN_IND
            elif report.type == 3:
                adv_type = BleAdvType.ADV_NONCONN_IND
            elif report.type == 4:
                adv_type = BleAdvType.ADV_SCAN_RSP
            msg.ble.adv_pdu.adv_type = adv_type
            if hasattr(report, "rssi"):
                msg.ble.adv_pdu.rssi = report.rssi
            msg.ble.adv_pdu.bd_address = bytes.fromhex(report.addr.replace(":",""))[::-1]

            # Flatten EIR data
            eir_data = b""

            for data in report.data:
                eir_data += raw(data)

            msg.ble.adv_pdu.adv_data = eir_data
            messages.append(msg)
        return messages
