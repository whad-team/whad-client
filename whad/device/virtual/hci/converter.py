"""
HCI/WHAD messages converter.
"""
import logging

from struct import unpack
from queue import Queue
from enum import IntEnum
from typing import List

# Scapy
from scapy.layers.bluetooth import HCI_Event_LE_Meta, HCI_LE_Meta_Advertising_Reports, \
    HCI_LE_Meta_Connection_Complete, L2CAP_Hdr, HCI_Hdr, HCI_ACL_Hdr, \
    HCI_Event_Disconnection_Complete, HCI_LE_Meta_Long_Term_Key_Request, \
    HCI_Event_Encryption_Change
from whad.scapy.layers.bluetooth import HCI_LE_Meta_Data_Length_Change
from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_CTRL, LL_ENC_REQ, \
    LL_ENC_RSP, LL_START_ENC_RSP, LL_START_ENC_REQ
from scapy.compat import raw

# Whad
from whad.scapy.layers.hci import HCI_LE_Meta_Enhanced_Connection_Complete
from whad.exceptions import WhadDeviceUnsupportedOperation
from whad.hub.ble import BleAddrType, BleDirection, BDAddress, AdvType, HubMessage

logger = logging.getLogger(__name__)

class HCIRole(IntEnum):
    """HCI role.
    """
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
        self.__locked = False

    def lock(self):
        """Lock the message converter. Messages are then added in a list
        of pending messages and will be processed when converter is unlocked.
        """
        self.__locked = True

    def unlock(self):
        """Unlock converter and trigger pending messages processing.
        """
        self.__locked = False

    def split_l2cap_into_hci(self, l2cap_data: bytes, conn_handle: int):
        """Split L2CAP packet into multiple HCI packets.
        """
        max_acl_len = self.__device.get_max_acl_len()
        nb_hci_packets = len(l2cap_data)//max_acl_len
        if len(l2cap_data)%max_acl_len > 0:
            nb_hci_packets += 1
        hci_packets = []
        for i in range(nb_hci_packets):
            pkt = HCI_Hdr() / HCI_ACL_Hdr(handle = conn_handle, PB=1 if i>0 else 0)
            pkt = pkt / l2cap_data[i*max_acl_len:(i+1)*max_acl_len]
            hci_packets.append(pkt)
        logger.debug("[hci converter] split ACL data into %d chunks (total: %d, acl_len: %d)", nb_hci_packets, len(l2cap_data), max_acl_len)
        return hci_packets

    def process_message(self, message: HubMessage):
        """This function turns a BLE hub message into the corresponding HCI
        packet.

        :param message: Hub message to convert.
        :type message: HubMessage
        """
        ll_packet = BTLE_DATA(message.pdu)

        # L2CAP packet reassembly
        if L2CAP_Hdr in ll_packet or self.waiting_l2cap_fragments:
            if not self.waiting_l2cap_fragments and (
                    (len(raw(ll_packet[L2CAP_Hdr:])) - 4) < ll_packet[L2CAP_Hdr:].len):
                self.waiting_l2cap_fragments = True
                self.cached_l2cap_payload = raw(ll_packet[BTLE_DATA:][1:])
                self.cached_l2cap_length = ll_packet[L2CAP_Hdr:].len

                # No HCI packet to send for now (data queued)
                logger.debug("l2cap is incomplete (%s/%s)",
                             len(self.cached_l2cap_payload)-4,
                             self.cached_l2cap_length)
                return []

            if self.waiting_l2cap_fragments:
                self.cached_l2cap_payload += raw(ll_packet[BTLE_DATA:][1:])
                if self.cached_l2cap_length <= (len(self.cached_l2cap_payload) - 4):
                    if self.cached_l2cap_length < len(self.cached_l2cap_payload) - 4:
                        logger.debug("[hci device][%s] too much data (got %d, expected %d)",
                                     self.__device.interface, len(self.cached_l2cap_payload) - 4,
                                     self.cached_l2cap_length)
                    self.waiting_l2cap_fragments = False
                    logger.debug("[hci device] reassembled l2cap data !")

                    # L2CAP data has been reassembled, then split in respect of
                    # the underlying device max ACL length
                    return self.split_l2cap_into_hci(
                        bytes(L2CAP_Hdr(self.cached_l2cap_payload)),
                        message.conn_handle
                    )

                # No HCI packet for now.
                logger.debug("l2cap is incomplete, more fragments needed (%s/%s).", len(self.cached_l2cap_payload) - 4, self.cached_l2cap_length)
                return []

            # L2CAP packet is complete but must be split
            l2cap_data = bytes(ll_packet[L2CAP_Hdr:])
            if len(l2cap_data) > self.__device.get_max_acl_len():
                return self.split_l2cap_into_hci(l2cap_data, message.conn_handle)

            # No fragmentation, send data as-is.
            hci_packet = HCI_Hdr() / HCI_ACL_Hdr(handle = message.conn_handle)
            hci_packet = hci_packet / ll_packet[L2CAP_Hdr:]
            logger.debug("l2cap does not need frag")
            return [hci_packet]

        if ll_packet.LLID == 3:
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

            #logger.warning("HCI devices cannot send control PDU.")
            raise WhadDeviceUnsupportedOperation(
                "send_pdu", "Device cannot send control PDU, only data PDU."
            )

        # No HCI packet to send
        return []

    def add_pending_message(self, event):
        """Add pending message to queue.

        :param event: Event message to add to queue
        :type event: HubMessage
        """
        self.pending_messages_queue.put(event)

    def get_pending_messages(self) -> List[HubMessage]:
        """Get pending messages.

        :return: List of pending hub messages
        :rtype: list
        """
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

            if HCI_LE_Meta_Connection_Complete in event:
                return self.process_connection_complete(event[HCI_LE_Meta_Connection_Complete:])

            if HCI_LE_Meta_Enhanced_Connection_Complete in event:
                return self.process_connection_complete(
                    event[HCI_LE_Meta_Enhanced_Connection_Complete:]
                )

            if HCI_LE_Meta_Long_Term_Key_Request in event:
                return self.process_long_term_key_request(event[HCI_LE_Meta_Long_Term_Key_Request:])
            
            if HCI_LE_Meta_Data_Length_Change in event:
                # Process a data length change
                length = event[HCI_LE_Meta_Data_Length_Change].max_tx_octets
                logger.debug("[hci][%s] update HCI data length to %d", self.__device.interface, length)
                self.__device._update_max_acl_len(length)


        if HCI_Event_Encryption_Change in event:
            return self.process_encryption_change_event(event[HCI_Event_Encryption_Change:])

        if HCI_ACL_Hdr in event:
            return self.process_acl_data(event[HCI_ACL_Hdr:])

        if HCI_Event_Disconnection_Complete in event:
            return self.process_disconnection_complete(event[HCI_Event_Disconnection_Complete:])

        # Return no messages on unknown events
        return []

    def process_encryption_change_event(self, event) -> List[HubMessage]:
        """Process encryption change.

        :param event: HCI event to process
        :return: list of hub messages
        :rtype: list
        """
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
        """Process long-term key request event.
        """
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
        """Process ACL data event.
        """
        if event.PB == 2 and L2CAP_Hdr in event:
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

            logger.debug("[hci] received PDU from remote device, forwarding to host")
            msg = self.__device.hub.ble.create_pdu_received(
                direction,
                raw(pdu),
                conn_handle,
                processed
            )

            if self.__locked:
                self.add_pending_message(msg)
                return []
            else:
                return [msg]

        if event.PB == 1:
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
            if self.__locked:
                self.add_pending_message(msg)
                return []
            else:
                return [msg]

        # Unsupported event, no messages.
        return []

    def process_connection_complete(self, event):
        """Process connection complete HCI event.
        """
        if event.status == 0x00:

            # Mark device as connected and register handle.
            self.__device.on_connection_created(event.handle)

            # Send BLE connected message to consumer.
            handle = event.handle
            if event.role == 0: # master role
                self.role = HCIRole.CENTRAL
                initiator_address = self.__device._bd_address.value
                initiator_address_type = self.__device._bd_address.type
                responder_address = bytes.fromhex(event.paddr.replace(":",""))[::-1]
                responder_address_type = (
                    BleAddrType.PUBLIC if event.patype == 0 else BleAddrType.RANDOM
                )
            else:
                self.role = HCIRole.PERIPHERAL
                initiator_address = bytes.fromhex(event.paddr.replace(":",""))[::-1]
                initiator_address_type = (
                    BleAddrType.PUBLIC if event.patype == 0 else BleAddrType.RANDOM
                )
                responder_address = self.__device._bd_address.value
                responder_address_type = self.__device._bd_address.type

            msg = self.__device.hub.ble.create_connected(
                BDAddress(initiator_address, addr_type=initiator_address_type),
                BDAddress(responder_address, addr_type=responder_address_type),
                0, # No access address
                handle
            )

            return [msg]
        else:
            logger.debug("[%s] Connection complete event with status 0x%x", self.__device.interface,
                         event.status)
        # Nothing to convert
        return []

    def process_disconnection_complete(self, event):
        """Process HCI disconnection event.
        """
        if event.status == 0x00:
            # Mark device as disconnected and remove handle
            #self.__device._connected = False
            #self.__device._active_handles.remove(event.handle)
            self.__device.on_connection_terminated(event.handle)

            # Send disconnection message to consumer.
            logger.debug("[hci] sending Disconnected message to host")
            msg = self.__device.hub.ble.create_disconnected(
                event.reason,
                event.handle
            )

            return [msg]

    def process_advertising_reports(self, reports):
        """Process HCI advertising reports.
        """
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
                BDAddress(report.addr, random = not report.atype == 0),
                bytes(eir_data)
            )

            messages.append(msg)
        return messages
