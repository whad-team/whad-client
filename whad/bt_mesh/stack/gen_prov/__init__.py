"""
Generic Provisioning Layer

Handles the creaton of a Link, acks and fragmentation for the Provisoning Layer
"""

import logging
from queue import Queue

from whad.scapy.layers.bt_mesh import (
    BTMesh_Generic_Provisioning_Link_Ack,
    BTMesh_Generic_Provisioning_Link_Close,
    BTMesh_Generic_Provisioning_Link_Open,
    BTMesh_Generic_Provisioning_Transaction_Start,
    BTMesh_Generic_Provisioning_Transaction_Ack,
    BTMesh_Generic_Provisioning_Transaction_Continuation,
)
from whad.common.stack import ContextualLayer, alias, source
from whad.bt_mesh.stack.gen_prov.message import GenericProvisioningMessage
from whad.bt_mesh.stack.exceptions import (
    InvalidFrameCheckSequenceError,
    UnexepectedGenericProvisioningPacketError,
)
from whad.bt_mesh.utils.assemble_frag import GenericFragmentsAssembler
from scapy.all import raw, Raw
from whad.bt_mesh.stack.provisioning import (
    ProvisioningLayerDevice,
    ProvisioningLayerProvisioner,
)


logger = logging.getLogger(__name__)


class Transaction(object):
    """
    Represents a transaction (one provisioning packet) currently sent OR received by the Generic Provisioning Layer.
    """

    def __init__(self, transaction_number, fragments, total_nb_fragement):
        self.transaction_number = transaction_number
        self.fragments = fragments
        self.total_nb_fragements = total_nb_fragement
        self.next_fragment_number = 0

    def get_next_fragment_to_send(self):
        """
        When transaction in send mode
        """
        self.next_fragment_number += 1
        return self.fragments.pop()

    def add_fragment(self, fragement):
        """
        When transaction in receive mode
        """
        self.fragments.append(fragement)


@alias("gen_prov")
class GenericProvisioningLayer(ContextualLayer):
    """Generic Provisioning Provisioner/Device base class"""

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

        # True when in the middle of a transaction
        self.state.in_transaction = False

        self.state.current_transaction = None

        self.state.is_link_open = False

        self.state.last_packet_sent = None

        self.state.expected_class = None

        # Simple FIFO queue for Provisioning messages. Since Provisioning Layer can send  2 packets back to back, need to make sure that all fragments/acks of first packet get there before seinding next one.
        self._queue = Queue()

    @source("provisioning")
    def on_provisioning_packet(self, packet):
        if self._queue.empty() and not self.state.in_transaction:
            self.process_provisioning_packet(packet)
        else:
            self._queue.put(packet)

    @source("pb_adv")
    def on_pb_adv_packet(self, message: GenericProvisioningMessage):
        pkt = message.gen_prov_pkt
        transaction_number = message.transaction_number
        if isinstance(pkt, BTMesh_Generic_Provisioning_Link_Close):
            self._handlers[BTMesh_Generic_Provisioning_Link_Close](message)
            return

        if self.state.expected_class is not None and not isinstance(
            pkt, self.state.expected_class
        ):
            logger.warning(
                "Unexpected pkt received in Generic Provisoning Layer %s %d"
                % (pkt.__class__.__name__, transaction_number)
            )
            raise UnexepectedGenericProvisioningPacketError(type(pkt))
        if (
            self.state.current_transaction is not None
            and self.state.current_transaction.transaction_number != transaction_number
        ):
            logger.warning(
                "Unexpected transaction number for pkt received in Generic Provisoning Layer %s %d"
                % (pkt.__class__.__name__, transaction_number)
            )
            raise UnexepectedGenericProvisioningPacketError(type(pkt))

        # if we get here, we have the packet we were waiting for
        self._handlers[type(pkt)](message)

    def send_to_peer(self, transaction_number, packet):
        message = GenericProvisioningMessage(packet, transaction_number)
        self.send("pb_adv", message)
        self.state.last_packet_sent = packet

    def send_to_upper_layer(self, packet):
        self.send("provisioning", packet)

    def check_queue(self):
        """Check is Provisioning messages are left to be sent"""
        if not self._queue.empty():
            self.process_provisioning_packet(self._queue.get_nowait())

    def on_link_open(self, message):
        """IN subclass, provisioner should never receive this"""

    def on_link_ack(self, message):
        """IN subclass, device should never receieve this"""
        pass

    def on_link_close(self, message):
        self.state.is_link_open = False

    def on_transaction_start(self, message):
        self.state.in_transaction = True
        pkt = message.gen_prov_pkt
        transaction_number = message.transaction_number

        # only one fragment, send to upper layer
        if pkt.segment_number == 0:
            try:
                prov_packet = pkt[1]
            except IndexError:
                logger.error("Missing upper layer in Transaction Start packet")
                pkt.show2()

            fcs = self.compute_frame_check_sequence(raw(prov_packet))

            if fcs != pkt.frame_check_sequence:
                raise InvalidFrameCheckSequenceError

            self.send_to_peer(
                transaction_number, BTMesh_Generic_Provisioning_Transaction_Ack()
            )
            self.state.in_transaction = False

        else:
            self.state.current_transaction = Transaction(
                transaction_number=transaction_number,
                fragments=[pkt],
                total_nb_fragement=pkt.segment_number,
            )
            self.state.expected_class = (
                BTMesh_Generic_Provisioning_Transaction_Continuation
            )

    def on_transaction_continuation(self, message):
        pkt = message.gen_prov_pkt

        # on wrong segment nb, reset Transaction and wait for resent (in spec)
        if pkt.segment_index != len(self.state.current_transaction.fragments):
            self.state.current_transaction = None
            self.state.expected_class = BTMesh_Generic_Provisioning_Transaction_Start
            logger.warning(
                "Received Transaction Continuation with wrong segment_index (received/expected : %d/%d)"
                % pkt.segment_index,
                len(self.state.current_transaction.fragments),
            )
            return

        self.state.current_transaction.add_fragment(
            pkt.generic_provisioning_payload_fragment
        )

        # if last segment index, defragment and send to upper layer, and check queue
        if pkt.segment_index == self.state.current_transaction.total_nb_fragement:
            assembler = GenericFragmentsAssembler(
                self.state.current_transaction.fragments
            )
            prov_pkt = assembler.reassemble()
            self.send_to_upper_layer(prov_pkt)
            self.check_queue()

    def on_transaction_ack(self, message):
        # check if current transaction is finished
        if len(self.current_transaction.fragments) > 0:
            self.send_next_fragment()

        # if finished, continue with queue if not empty
        self.state.last_sent_transaction_number += 1
        self.state.in_transaction = False
        self.check_queue()

    def process_provisioning_packet(self, packet):
        """
        Process a Provisioning packet to divide it into fragments, set the expected next packets, and send the first fragment
        """
        # limit size of a fragment is 64 bytes
        self.state.in_transaction = False
        raw_packet = raw(packet)
        fragments = [raw_packet[i : i + 64] for i in range(0, len(raw_packet), 64)]

        self.state.current_transaction = Transaction(
            transaction_number=self.state.last_sent_transaction_number + 1,
            fragments=fragments,
            total_nb_fragement=len(fragments),
        )

        # Send the first fragment in a Transaction Start
        fragment = self.state.current_transaction.get_next_fragment_to_send()

        frame_check_sequence = self.compute_frame_check_sequence(raw_packet)

        self.send_to_peer(
            self.state.current_transaction.transaction_number,
            BTMesh_Generic_Provisioning_Transaction_Start(
                segment_number=self.state.current_transaction.total_nb_fragement,
                frame_check_sequence=frame_check_sequence,
            )
            / Raw(bytes.fromhex(fragment)),
        )

        if len(self.state.current_transaction.fragments) == 0:
            self.state.in_transaction = False
        else:
            self.state.expected_class = BTMesh_Generic_Provisioning_Transaction_Ack

    def send_next_fragment(self):
        """
        Send the next fragment in the current transaction
        """
        fragment = self.state.current_transaction.get_next_fragment_to_send()
        self.state.expected_class = BTMesh_Generic_Provisioning_Transaction_Ack
        self.send_to_peer(
            self.state.current_transaction.transaction_number,
            BTMesh_Generic_Provisioning_Transaction_Continuation(
                segment_index=self.state.current_transaction.next_fragment_number,
                generic_provisioning_payload_fragment=fragment,
            ),
        )

    def compute_frame_check_sequence(data):
        fcs = 0xFF
        polynomial = 0x107

        for byte in data:
            fcs ^= byte
            for _ in range(8):
                if fcs & 1:
                    fcs = (fcs >> 1) ^ polynomial
                else:
                    fcs >>= 1

        return fcs & 0xFF


class GenericProvisioningLayerProvisioner(GenericProvisioningLayer):
    """Provisioner subclass UUID of peer device should be in options !"""

    def configure(self, options):
        super().configure(options)

        self.state.expected_class = BTMesh_Generic_Provisioning_Link_Open
        self.state.last_sent_transaction_number = -1

        # send the link open directly

        self.open_link()
        self.send_to_peer(
            transaction_number=0x00,
            packet=BTMesh_Generic_Provisioning_Link_Open(device_uuid=options["uuid"]),
        )

    def on_link_ack(self, message):
        if not self.state.is_link_open:
            self.state.is_link_open = True
            self.check_queue()


class GenericProvisioningLayerDevice(GenericProvisioningLayer):
    """Device (provisionee) subclass"""

    def configure(self, options):
        super().configure(options)

        self.state.expected_class = BTMesh_Generic_Provisioning_Link_Open
        self.state.last_sent_transaction_number = 0x7F

    def on_link_open(self, message):
        self.send_to_peer(
            transaction_number=0x00, packet=BTMesh_Generic_Provisioning_Link_Ack()
        )
        self.state.is_link_open = True
        self.state.expected_class = BTMesh_Generic_Provisioning_Transaction_Start


GenericProvisioningLayerDevice.add(ProvisioningLayerDevice)
GenericProvisioningLayerProvisioner.add(ProvisioningLayerProvisioner)
