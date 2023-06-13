from scapy.layers.bluetooth import HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, \
    HCI_LE_Meta_Connection_Complete, L2CAP_Hdr, HCI_Hdr, HCI_ACL_Hdr, HCI_Event_Disconnection_Complete
from scapy.layers.bluetooth4LE import BTLE_DATA
from whad.scapy.layers.hci import HCI_LE_Meta_Enhanced_Connection_Complete
from scapy.compat import raw
from whad.exceptions import WhadDeviceUnsupportedOperation
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleAdvType, BleAddrType, BleDirection
from enum import IntEnum

import logging
logger = logging.getLogger(__name__)

class HCIRole(IntEnum):
    NONE = 0
    CENTRAL = 1
    PERIPHERAL = 2

class HCIConverter:
    """
    This class converts HCI event to WHAD BLE packets and WHAD BLE packets to HCI commands.
    It allows to harmonise the representation of Bluetooth Low Energy traffic, as WHAD expects
    Link Layer-like packets.

    Obviously, some packets can't be converted easily from a representation to the other one without
    losing information or making asumptions. As a result, you should expect some limitations.
    """

    def __init__(self, device):
        self.__device = device
        self.role = HCIRole.NONE

    def process_message(self, message):
        ll_packet = BTLE_DATA(message.pdu)

        if L2CAP_Hdr in ll_packet:
            hci_packet = HCI_Hdr() / HCI_ACL_Hdr(handle = message.conn_handle) / ll_packet[L2CAP_Hdr:]
            return [hci_packet]
        elif ll_packet.LLID == 3:
            logger.warning("HCI devices cannot send control PDU.")
            raise WhadDeviceUnsupportedOperation("Device cannot send control PDU, only data PDU.")

    def process_event(self, event):
        """
        Converts an HCI event to the corresponding Link Layer packet (if possible).
        """
        if HCI_Event_LE_Meta in event:
            if HCI_LE_Meta_Advertising_Reports in event:
                return self.process_advertising_reports(event[HCI_LE_Meta_Advertising_Reports:])
            elif HCI_LE_Meta_Connection_Complete in event:
                return self.process_connection_complete(event[HCI_LE_Meta_Connection_Complete:])
            elif HCI_LE_Meta_Enhanced_Connection_Complete in event:
                return self.process_connection_complete(event[HCI_LE_Meta_Enhanced_Connection_Complete:])
                
        elif HCI_ACL_Hdr in event:
            return self.process_acl_data(event[HCI_ACL_Hdr:])
        elif HCI_Event_Disconnection_Complete in event:
            return self.process_disconnection_complete(event[HCI_Event_Disconnection_Complete:])

    def process_acl_data(self, event):
        if event.PB == 2 and L2CAP_Hdr in event:
            msg = Message()
            pdu = BTLE_DATA()/event[L2CAP_Hdr:]

            # If HCI ACL Data PB flag==1 then it is a continued fragment.
            # We make sure BTLE_DATA.LLID is then 0x01 (Continuation
            # of a L2CAP message), our stack will take care of packet reassembly.
            if event.PB == 0x01:
                pdu.LLID = 1

            direction = (BleDirection.SLAVE_TO_MASTER if
                         self.role == HCIRole.CENTRAL else
                         BleDirection.MASTER_TO_SLAVE
            )
            processed = False
            conn_handle = event.handle

            msg.ble.pdu.direction = direction
            msg.ble.pdu.conn_handle = conn_handle
            msg.ble.pdu.pdu = raw(pdu)
            msg.ble.pdu.processed = processed
            return [msg]

        elif event.PB == 1:
            msg = Message()
            pdu = BTLE_DATA()/event[HCI_ACL_Hdr:].payload

            # If HCI ACL Data PB flag==1 then it is a continued fragment.
            # We make sure BTLE_DATA.LLID is then 0x01 (Continuation
            # of a L2CAP message), our stack will take care of packet reassembly.
            pdu.LLID = 1

            direction = (BleDirection.SLAVE_TO_MASTER if
                         self.role == HCIRole.CENTRAL else
                         BleDirection.MASTER_TO_SLAVE
            )
            processed = False
            conn_handle = event.handle

            msg.ble.pdu.direction = direction
            msg.ble.pdu.conn_handle = conn_handle
            msg.ble.pdu.pdu = raw(pdu)
            msg.ble.pdu.processed = processed
            return [msg]

    def process_connection_complete(self, event):
        if event.status == 0x00:

            # Mark device as connected.
            self.__device._connected = True

            # Send BLE connected message to consumer.
            msg = Message()
            handle = event.handle
            if event.role == 0: # master role
                self.role = HCIRole.CENTRAL
                initiator_address = bytes.fromhex(self.__device._bd_address.replace(":",""))[::-1]
                initiator_address_type = self.__device._bd_address_type
                responder_address = bytes.fromhex(event.paddr.replace(":",""))[::-1]
                responder_address_type = BleAddrType.PUBLIC if event.patype == 0 else BleAddrType.RANDOM
            else:
                self.role = HCIRole.PERIPHERAL
                initiator_address = bytes.fromhex(event.paddr.replace(":",""))[::-1]
                initiator_address_type = BleAddrType.PUBLIC if event.patype == 0 else BleAddrType.RANDOM
                responder_address = bytes.fromhex(self.__device._bd_address.replace(":",""))[::-1]
                responder_address_type = self.__device._bd_address_type
            msg.ble.connected.initiator = initiator_address
            msg.ble.connected.init_addr_type = initiator_address_type
            msg.ble.connected.advertiser = responder_address
            msg.ble.connected.adv_addr_type = responder_address_type
            msg.ble.connected.conn_handle = handle
            return [msg]

    def process_disconnection_complete(self, event):
        if event.status == 0x00:
            # Mark device as disconnected
            self.__device._connected = False

            # Send disconnection message to consumer.
            msg = Message()
            handle = event.handle
            reason = event.reason
            msg.ble.disconnected.conn_handle = handle
            msg.ble.disconnected.reason = reason
            return [msg]

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
            msg.ble.adv_pdu.addr_type = BleAddrType.PUBLIC if report.atype == 0 else BleAddrType.RANDOM
            # Flatten EIR data
            eir_data = b""

            for data in report.data:
                eir_data += raw(data)

            msg.ble.adv_pdu.adv_data = eir_data
            messages.append(msg)
        return messages
