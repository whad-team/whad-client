"""
Generic Provisioning Layer
(Network Layer pendant for Provisioning)

Handles the creaton of a Link, acks and fragmentation for the Provisoning Layer
"""

import logging
from queue import Queue
from threading import Thread
from random import uniform

from whad.scapy.layers.btmesh import (
    BTMesh_Generic_Provisioning_Link_Ack,
    BTMesh_Generic_Provisioning_Link_Close,
    BTMesh_Generic_Provisioning_Link_Open,
    BTMesh_Generic_Provisioning_Transaction_Start,
    BTMesh_Generic_Provisioning_Transaction_Ack,
    BTMesh_Generic_Provisioning_Transaction_Continuation,
    BTMesh_Provisioning_Hdr,
)
from whad.common.stack import ContextualLayer, alias, source
from whad.btmesh.stack.gen_prov.message import GenericProvisioningMessage
from whad.btmesh.stack.exceptions import (
    InvalidFrameCheckSequenceError,
)
from scapy.all import raw, Raw
from whad.btmesh.stack.provisioning import (
    ProvisioningLayerProvisionee,
    ProvisioningLayerProvisioner,
)
from time import sleep

from whad.btmesh.stack.gen_prov.constants import CRC_TABLE


logger = logging.getLogger(__name__)


class Transaction(object):
    """
    Represents a transaction (one provisioning packet) currently sent OR received by the Generic Provisioning Layer.
    """

    def __init__(self, transaction_number):
        self.transaction_number = transaction_number
        self.fragments = []


class SendingTransaction(Transaction):
    """
    Transaction object used for the Sender (initiator that sends the Transaction Start)
    Also used to monitor and manage Link Open packets
    """

    def __init__(self, transaction_number, packet, fcs):
        super().__init__(transaction_number)

        raw_packet = raw(packet)

        self.total_length = len(raw_packet)

        # max payload size in start is 20 bytes, 23 in a continuation (adv MTU)
        if self.total_length > 20:
            first_fragment = raw_packet[0:20]
            raw_packet = raw_packet[20:]
            fragments = [raw_packet[i : i + 23] for i in range(0, len(raw_packet), 23)]
            fragments.insert(0, first_fragment)
        else:
            fragments = [raw_packet]

        self.fragments = fragments
        self.total_nb_fragements = len(fragments)
        self.fcs = fcs


class ReceivingTransaction(Transaction):
    """
    Transaction object used for the Receiver of a Transaction (receiving the Transaction Start)
    """

    def __init__(self, transaction_number, total_nb_fragements, expected_fcs):
        super().__init__(transaction_number)
        self.expected_fcs = expected_fcs

        # Last segment index expected
        self.total_nb_fragements = total_nb_fragements

    def add_fragment(self, fragement):
        """
        When transaction in receive mode, add a received fragment
        """
        self.fragments.append(fragement)


@alias("gen_prov")
class GenericProvisioningLayer(ContextualLayer):
    """Generic Provisioning Provisioner/Provisionee base class"""

    def configure(self, options):
        """Configure the Generic Provisioning Layer"""

        self._handlers = {
            BTMesh_Generic_Provisioning_Link_Open: self.on_link_open,
            BTMesh_Generic_Provisioning_Link_Ack: self.on_link_ack,
            BTMesh_Generic_Provisioning_Link_Close: self.on_link_close,
            BTMesh_Generic_Provisioning_Transaction_Start: self.on_transaction_start,
            BTMesh_Generic_Provisioning_Transaction_Ack: self.on_transaction_ack,
            BTMesh_Generic_Provisioning_Transaction_Continuation: self.on_transaction_continuation,
        }

        # Custom handler for packets received from parent layer
        # Should take the message as argument
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

        # True when in the middle of a transaction
        self.state.in_transaction = False

        self.state.current_transaction = None

        self.state.is_link_open = False

        self.state.is_thread_running = False

        # stores the current thread sending fragments (send_packet_thread function)
        self.state.sending_thread = None

        # Transaction number of last received provsioning PDU
        self.state.last_received_transaction_number = -100000000

        # number of retries before we receive an ack for a tx packet (100% arbitrary)
        self.state.tx_packet_attempts = 10

        # Simple FIFO queue for Provisioning messages. Since Provisioning Layer can send  2 packets back to back, need to make sure that all fragments/acks of first packet get there before seinding next one.
        self._queue = Queue()

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Message with class (Scapy packet) specified

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking Packet as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_handler(self, clazz):
        """
        Unregisters a previously registerd custom callback for a message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def send_ack(self, transaction_number):
        """
        Sends one ack to the peer. Is resent when we receive again a packet from a transaction from which we have received all segments
        """
        self.send_to_peer(
            transaction_number, BTMesh_Generic_Provisioning_Transaction_Ack()
        )
        # self.send_to_peer
        #    transaction_number, BTMesh_Generic_Provisioning_Transaction_Ack()
        # )

    def send_packet_thread(self):
        """
        Send each with a random delay between 20 and 50 ms (SPEC)
        Resends the whole transaction if ack not received in 1sec, resends all.
        Starts Ack timer of 30 seconds from the first sending. If no Ack after timer expires, closes the connexion
        """
        i = self.state.tx_packet_attempts
        while i > 0:
            if self.state.is_thread_running:
                transaction_number = self.state.current_transaction.transaction_number
                for index in range(0, len(self.state.current_transaction.fragments)):
                    if index == 0:
                        self.send_to_peer(
                            transaction_number,
                            BTMesh_Generic_Provisioning_Transaction_Start(
                                segment_number=self.state.current_transaction.total_nb_fragements
                                - 1,
                                frame_check_sequence=self.state.current_transaction.fcs,
                                total_length=self.state.current_transaction.total_length,
                            )
                            / Raw(self.state.current_transaction.fragments[index]),
                        )
                    else:
                        self.send_to_peer(
                            transaction_number,
                            BTMesh_Generic_Provisioning_Transaction_Continuation(
                                segment_index=index,
                                generic_provisioning_payload_fragment=self.state.current_transaction.fragments[
                                    index
                                ],
                            ),
                        )

                sleep(0.04)
            sleep(1)
            i -= 1

    def activate_sending_thread(self):
        """
        Activate thread that sends all the fragments (Start and Continuation).
        """
        self.state.sending_thread = Thread(target=self.send_packet_thread, daemon=True)
        self.state.is_thread_running = True
        self.state.sending_thread.start()

    def stop_sending_thread(self):
        """
        Stops the thead sending the packet for the current transaction.
        """
        self.state.is_thread_running = False

    @source("provisioning")
    def on_provisioning_packet(self, packet):
        """
        Handler when receiving a packet from the Provisioning Layer
        """
        # Check if link already open or not
        if not self.state.is_link_open:
            self.open_link()
            self._queue.put(packet)
            return

        # if not in Transaction currently, process direclty
        if self._queue.empty() and not self.state.in_transaction:
            self.process_provisioning_packet(packet)
            return

        # otherwise add to queue
        self._queue.put(packet)

    @source("pb_adv")
    def on_pb_adv_packet(self, message):
        """
        Handler for messages received from the GenericProvisioningLayer
        """
        pkt = message.gen_prov_pkt

        if type(pkt) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(pkt)](message)
            # if custom handler says to return after itself
            if not continue_processing:
                return

        self._handlers[type(pkt)](message)

    def send_to_peer(self, transaction_number, packet):
        """
        Send packet to peer via sublayer

        :param transaction_number: Number of current transaction (can be 0 for some packets)
        :type transaction_number: [TODO:type]
        :param packet: [TODO:description]
        :type packet: [TODO:type]
        """
        message = GenericProvisioningMessage(packet, transaction_number)
        # random delay between 20 and 50 ms
        sleep(uniform(0.01, 0.04))
        self.send("pb_adv", message)

    def send_to_upper_layer(self, packet):
        """
        Transfer packet to the Provisioning Layer

        :param packet: Provisioning packet (no header)
        :type packet: Packet
        """
        self.send("provisioning", packet)

    def check_queue(self):
        """
        Check is Provisioning messages are left to be sent (and we are not in a Transaction). If nothing, we wait for a Transaction Start.
        """
        if self.state.in_transaction:
            return
        if not self._queue.empty():
            self.process_provisioning_packet(self._queue.get_nowait())

    def open_link(self):
        """
        In subclass Provisioner. Open a Link with peer device
        """
        pass

    def close_link(self):
        """
        Closes the link when provisioning is finished or on error in Provisioning layer
        """
        self.send_to_peer(0x00, BTMesh_Generic_Provisioning_Link_Close(reason=0x00))
        self.send_to_peer(0x00, BTMesh_Generic_Provisioning_Link_Close(reason=0x00))
        self.send_to_peer(0x00, BTMesh_Generic_Provisioning_Link_Close(reason=0x00))
        self.state.is_link_open = False

    def on_link_open(self, message):
        """In subclass, provisioner should never receive this"""
        pass

    def on_link_ack(self, message):
        """In subclass, provisionee should never receieve this"""
        pass

    def on_link_close(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Link_Close message
        """
        self.state.is_link_open = False

    def on_transaction_start(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Transaction_Start message
        """
        pkt = message.gen_prov_pkt
        transaction_number = message.transaction_number

        # if we receive a Start from a previous finished Transaction, send ack again
        if transaction_number <= self.state.last_received_transaction_number:
            self.send_ack(transaction_number)
            return

        # ignore packet if already in a transaction otherwise
        if self.state.in_transaction:
            return

        self.state.in_transaction = True

        # Create Transaction object for this transaction
        self.state.current_transaction = ReceivingTransaction(
            transaction_number=transaction_number,
            total_nb_fragements=pkt.segment_number,
            expected_fcs=pkt.frame_check_sequence,
        )

        # only one fragment, send to upper layer and send ack if all good
        if pkt.segment_number == 0:
            try:
                prov_packet = pkt[1]
            except IndexError:
                logger.debug("Missing upper layer in Transaction Start packet")
                return

            # check FCS (we dont use the Hdr)
            fcs = self.compute_fcs(raw(prov_packet))

            if fcs != pkt.frame_check_sequence:
                raise InvalidFrameCheckSequenceError

            # Send ack since only one fragment
            self.state.last_received_transaction_number = (
                self.state.current_transaction.transaction_number
            )
            self.state.in_transaction = False
            self.send_to_upper_layer(prov_packet)
            self.send_ack(transaction_number=transaction_number)

        # if more fragmentx expected, add the first one to the list
        else:
            self.state.current_transaction.add_fragment(pkt.getlayer(Raw).load)

    def on_transaction_continuation(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Transaction_Continuation message
        """
        pkt = message.gen_prov_pkt
        transaction_number = message.transaction_number

        # if we receive a Continuation for an already finished Transaction, send ack again
        if transaction_number <= self.state.last_received_transaction_number:
            self.send_ack(transaction_number)
            return

        # else if we receive in a weird case (no current transaction), we ignore it
        if (
            not self.state.in_transaction
            or self.state.current_transaction.transaction_number != transaction_number
        ):
            return

        # If segment number equal to the one we received before, ignore (its just a resent on some implementations ...)
        if pkt.segment_index < len(self.state.current_transaction.fragments):
            return

        # on wrong segment nb (below the one we have), reset Transaction and wait for resent (in spec)
        if pkt.segment_index != len(self.state.current_transaction.fragments):
            self.state.current_transaction = None
            self.state.in_transaction = False
            logger.debug(
                f"Received Transaction Continuation with wrong segment_index (received: {pkt.segment_index})"
            )
            return

        # Add the received fragment to our Transaction object
        self.state.current_transaction.add_fragment(
            pkt.generic_provisioning_payload_fragment
        )

        # if last segment index, defragment and send to upper layer, and check queue. Send Ack to peer
        if pkt.segment_index == self.state.current_transaction.total_nb_fragements:
            prov_pkt = BTMesh_Provisioning_Hdr(
                b"".join(self.state.current_transaction.fragments)
            )

            # compute fcs to check with the one we received at the start
            fcs = self.compute_fcs(raw(prov_pkt))

            if fcs != self.state.current_transaction.expected_fcs:
                raise InvalidFrameCheckSequenceError

            self.state.in_transaction = False
            self.state.last_received_transaction_number = (
                self.state.current_transaction.transaction_number
            )
            self.send_ack(transaction_number)
            self.send_to_upper_layer(prov_pkt)
            self.check_queue()

    def on_transaction_ack(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Transaction_Ack message
        """
        # Check if ack for the correct transaction
        if (
            not self.state.in_transaction
            or self.state.current_transaction.transaction_number
            != message.transaction_number
        ):
            logger.debug(
                f"Received Ack for wrong transaction. Pkt transaction : {message.transaction_number}"
            )
            return

        self.stop_sending_thread()
        self.state.in_transaction = False
        self.state.last_sent_transaction_number += 1
        self.check_queue()

    def process_provisioning_packet(self, packet):
        """
        Process a Provisioning packet to divide it into fragments, set the expected next packets, and send the first fragment
        """

        # limit size of a fragment is 23 bytes
        self.state.in_transaction = True
        logger.debug(
            "SENDING, Transaction Nb : "
            + hex(self.state.last_sent_transaction_number + 1)
        )

        # compute fcs (dont use the Hdr)
        fcs = self.compute_fcs(raw(packet))

        self.state.current_transaction = SendingTransaction(
            transaction_number=self.state.last_sent_transaction_number + 1,
            packet=packet,
            fcs=fcs,
        )

        # activate sending thread for this packet
        self.activate_sending_thread()

    def compute_fcs(self, data):
        # Initialize FCS to 0xFF
        fcs = 0xFF

        # Iterate over each byte in the data
        for byte in data:
            # Use the current byte to index into the crc_table
            # This effectively does fcs = crc_table[fcs ^ byte]
            fcs = CRC_TABLE[fcs ^ byte]

        # The FCS is the one's complement of the result
        return 0xFF - fcs


class GenericProvisioningLayerProvisioner(GenericProvisioningLayer):
    """
    Subclass of the GenericProvisioningLayer used for Provisioner nodes
    """

    def configure(self, options):
        super().configure(options)

        self.state.last_sent_transaction_number = -1
        self.state.is_link_open_thread_running = False
        # Link Open sending thread
        self.state.link_open_thread = None

        # UUID of peer device, need to be set if not in options
        if "uuid" in options:
            self.state.peer_uuid = options["uuid"]

    def send_link_open_thread(self):
        """
        Function running in a seperate thread to send BTMesh_Generic_Provisioning_Link_Open messages until received
        """
        while self.state.is_link_open_thread_running:
            self.send_to_peer(
                transaction_number=0x00,
                packet=BTMesh_Generic_Provisioning_Link_Open(
                    device_uuid=self.state.peer_uuid
                ),
            )
            sleep(uniform(0.1, 0.2))

    def stop_link_open_thread(self):
        """
        Stops the thead sending the packet for the current transaction.
        """
        self.state.is_link_open_thread_running = False

    def create_sending_thread_link_open(self):
        """
        Activate thread to send Link Open packets
        """
        self.state.is_link_open_thread_running = True
        self.state.link_open_thread = Thread(target=self.send_link_open_thread, daemon=True)
        self.state.link_open_thread.start()

    def on_link_close(self, message):
        super().on_link_close(message)
        logger.debug(
            f"LINK CLOSE, reason : {message.gen_prov_pkt.reason}, peer UUID : {self.state.peer_uuid}"
        )

    def on_link_ack(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Link_Ack messages
        """
        if not self.state.is_link_open:
            self.stop_link_open_thread()
            self.state.is_link_open = True
            self.check_queue()

    def open_link(self):
        """
        Initiates the creation of a Link to the provisionee
        """
        self.state.current_transaction = SendingTransaction(
            transaction_number=0x00,
            packet=BTMesh_Generic_Provisioning_Link_Open(),
            fcs=None,
        )
        self.create_sending_thread_link_open()


class GenericProvisioningLayerProvisionee(GenericProvisioningLayer):
    """Provisionee subclass"""

    def configure(self, options):
        super().configure(options)

        self.state.last_sent_transaction_number = 0x7F

        # Our UUID, need to be set if not in options
        if "uuid" in options:
            self.state.own_uuid = options["uuid"]

    def on_link_open(self, message):
        """
        Handler for BTMesh_Generic_Provisioning_Link_Open message received from the Provisioner
        """
        self.send_to_peer(
            transaction_number=0x00, packet=BTMesh_Generic_Provisioning_Link_Ack()
        )
        self.state.is_link_open = True


GenericProvisioningLayerProvisionee.add(ProvisioningLayerProvisionee)
GenericProvisioningLayerProvisioner.add(ProvisioningLayerProvisioner)
