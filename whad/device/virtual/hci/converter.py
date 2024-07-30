from scapy.layers.bluetooth import HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, \
    HCI_LE_Meta_Connection_Complete, L2CAP_Hdr, HCI_Hdr, HCI_ACL_Hdr, HCI_Event_Disconnection_Complete, \
    HCI_LE_Meta_Long_Term_Key_Request, HCI_Event_Encryption_Change
from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_CTRL, LL_ENC_REQ, LL_ENC_RSP, LL_START_ENC_RSP, \
    LL_START_ENC_REQ
from whad.scapy.layers.hci import HCI_LE_Meta_Enhanced_Connection_Complete
from scapy.compat import raw
from whad.exceptions import WhadDeviceUnsupportedOperation
from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import BleAdvType, BleAddrType, BleDirection
from whad.hub.ble import BDAddress, AdvType
from struct import pack, unpack
from queue import Queue
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
        self.pending_messages_queue = Queue()
        self.pending_key_request = False
        self.cached_l2cap_payload = b""
        self.cached_l2cap_length = 0
        self.waiting_l2cap_fragments = False

    def process_message(self, message):
        ll_packet = BTLE_DATA(message.pdu)

        if L2CAP_Hdr in ll_packet or self.waiting_l2cap_fragments:

            if not self.waiting_l2cap_fragments and len(raw(ll_packet[L2CAP_Hdr:])) < ll_packet[L2CAP_Hdr:].len:
                self.waiting_l2cap_fragments = True
                self.cached_l2cap_payload = raw(ll_packet[BTLE_DATA:][1:])
                self.cached_l2cap_length = ll_packet[L2CAP_Hdr:].len
                return []
            elif self.waiting_l2cap_fragments:
                self.cached_l2cap_payload += raw(ll_packet[BTLE_DATA:][1:])
                if self.cached_l2cap_length == (len(self.cached_l2cap_payload) - 4):
                    L2CAP_Hdr(self.cached_l2cap_payload).show()
                    hci_packet = HCI_Hdr() / HCI_ACL_Hdr(handle = message.conn_handle) / L2CAP_Hdr(self.cached_l2cap_payload)
                    self.waiting_l2cap_fragments = False
                    return [hci_packet]
                else:
                    return []
            hci_packet = HCI_Hdr() / HCI_ACL_Hdr(handle = message.conn_handle) / ll_packet[L2CAP_Hdr:]
            return [hci_packet]
        elif ll_packet.LLID == 3:
            if LL_ENC_REQ in ll_packet:
                pdu = BTLE_DATA() / BTLE_CTRL() / LL_ENC_RSP(skds=0, ivs=0)

                direction = (BleDirection.SLAVE_TO_MASTER if
                             self.role == HCIRole.CENTRAL else
                             BleDirection.MASTER_TO_SLAVE
                )
                processed = False
                conn_handle = message.conn_handle

                msg = self.__device.hub.ble.create_pdu_received(
                    direction,
                    raw(pdu),
                    conn_handle,
                    processed
                )

                self.add_pending_message(msg)

                msg = Message()
                pdu = BTLE_DATA() / BTLE_CTRL() / LL_START_ENC_REQ()

                direction = (BleDirection.SLAVE_TO_MASTER if
                             self.role == HCIRole.CENTRAL else
                             BleDirection.MASTER_TO_SLAVE
                )
                processed = False
                conn_handle = message.conn_handle

                msg = self.__device.hub.ble.create_pdu_received(
                    direction,
                    raw(pdu),
                    conn_handle,
                    processed
                )

                self.add_pending_message(msg)

                return []
            else:
                #logger.warning("HCI devices cannot send control PDU.")
                raise WhadDeviceUnsupportedOperation("send_pdu", "Device cannot send control PDU, only data PDU.")

    def add_pending_message(self, event):
        self.pending_messages_queue.put(event)

    def get_pending_messages(self):
        events = []
        while not self.pending_messages_queue.empty():
            events.append(self.pending_messages_queue.get())
        return events

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
            elif HCI_LE_Meta_Long_Term_Key_Request in event:
                return self.process_long_term_key_request(event[HCI_LE_Meta_Long_Term_Key_Request:])
        elif HCI_Event_Encryption_Change in event:
            return self.process_encryption_change_event(event[HCI_Event_Encryption_Change:])
        elif HCI_ACL_Hdr in event:
            return self.process_acl_data(event[HCI_ACL_Hdr:])
        elif HCI_Event_Disconnection_Complete in event:
            return self.process_disconnection_complete(event[HCI_Event_Disconnection_Complete:])

    def process_encryption_change_event(self, event):
        pdu = BTLE_DATA()/BTLE_CTRL()/LL_START_ENC_RSP()

        direction = (BleDirection.SLAVE_TO_MASTER if
                     self.role == HCIRole.CENTRAL else
                     BleDirection.MASTER_TO_SLAVE
        )
        processed = False
        conn_handle = event.handle

        msg = self.__device.hub.ble.create_pdu_received(
            direction,
            raw(pdu),
            conn_handle,
            processed
        )

        return [msg]

    def process_long_term_key_request(self, event):

        msg = Message()
        pdu = BTLE_DATA()/BTLE_CTRL()/LL_ENC_REQ(
            rand = unpack('<Q', event.rand)[0],
            ediv = event.ediv,
            # SKD and IV are processed in Link Layer and are not transmitted to Host,
            # so we can't provide the real value. We arbitrarily set them to 0 to allow
            # BLE stack to continue its operations.
            skdm = 0,
            ivm = 0
        )


        direction = (BleDirection.SLAVE_TO_MASTER if
                     self.role == HCIRole.CENTRAL else
                     BleDirection.MASTER_TO_SLAVE
        )
        processed = False
        conn_handle = event.handle

        msg = self.__device.hub.ble.create_pdu_received(
            direction,
            raw(pdu),
            conn_handle,
            processed
        )

        self.pending_key_request = True
        return [msg]

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

            msg = self.__device.hub.ble.create_pdu_received(
                direction,
                raw(pdu),
                conn_handle,
                processed
            )

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

            msg = self.__device.hub.ble.create_pdu_received(
                direction,
                raw(pdu),
                conn_handle,
                processed
            )

            return [msg]

    def process_connection_complete(self, event):
        if event.status == 0x00:

            # Mark device as connected and register handle.
            self.__device._connected = True
            self.__device._active_handles.append(event.handle)

            # Send BLE connected message to consumer.
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
            
            msg = self.__device.hub.ble.create_connected(
                BDAddress(initiator_address, addr_type=initiator_address_type),
                BDAddress(responder_address, addr_type=responder_address_type),
                0, # No access address
                handle
            )

            return [msg]

    def process_disconnection_complete(self, event):
        if event.status == 0x00:
            # Mark device as disconnected and remove handle
            self.__device._connected = False
            self.__device._active_handles.remove(event.handle)

            # Send disconnection message to consumer.
            msg = self.__device.hub.ble.create_disconnected(
                event.reason,
                event.handle
            )

            return [msg]

    def process_advertising_reports(self, reports):
        messages = []
        for report in reports.reports:

            adv_type = AdvType.ADV_UNKNOWN
            if report.type == 0:
                adv_type = AdvType.ADV_IND
            elif report.type == 1:
                adv_type = AdvType.ADV_DIRECT_IND
            elif report.type == 2:
                adv_type = AdvType.ADV_SCAN_IND
            elif report.type == 3:
                adv_type = AdvType.ADV_NONCONN_IND
            elif report.type == 4:
                adv_type = AdvType.ADV_SCAN_RSP

            # Flatten EIR data
            eir_data = b""
            for data in report.data:
                eir_data += raw(data)

            msg = self.__device.hub.ble.create_adv_pdu_received(
                adv_type,
                report.rssi if hasattr(report, "rssi") else 0,
                BDAddress(report.addr, random = not (report.atype == 0)),
                bytes(eir_data)
            )

            messages.append(msg)
        return messages
