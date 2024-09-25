"""
Lower Transport Layer

Handles Segmentation/Reassembly of Upper Transport PDU
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.stack.upper_transport import UpperTransportLayer
from whad.bt_mesh.stack.utils import (
    MeshMessageContext,
    get_address_type,
    UNICAST_ADDR_TYPE,
    VIRTUAL_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    calculate_seq_auth,
)
from queue import Queue
from whad.scapy.layers.bt_mesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Lower_Transport_Segmented_Access_Message,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Segment_Acknoledgment_Message,
    BTMesh_Lower_Transport_Control_Message,
)
from scapy.all import raw, Raw
from whad.bt_mesh.models import GlobalStatesManager
from threading import Thread, Event, Timer
from time import sleep, time
from random import uniform
from copy import copy


logger = logging.getLogger(__name__)


class Transaction:
    def __init__(self, message):
        """
        Initiates a transaction, Rx or Tx

        :param message: The message received or to be sent and its context
        :type message: (Packet, MeshMessageContext)
        """
        self.pkt, self.ctx = message

        self.src_addr_type = get_address_type(self.ctx.src_addr)
        self.dst_addr_type = get_address_type(self.ctx.dest_addr)
        self.is_control_message = not isinstance(
            self.pkt, BTMesh_Upper_Transport_Access_PDU
        )

        # fragments to send or received. Is a dictionary if RxTransaction
        self.fragments = []

        # list of the segment indexes received
        self.acked_segments = []

        # Set to True when the Transaction is finished (all segments received and acked if needed, or all segments sent and acked if needed)
        self.is_transaction_finished = False

        # Event object to stop the timer if acked received to restart transmission/ restart ack sending thread
        self.event = None

        self.global_states_manager = GlobalStatesManager()

        # iv_index used for this PDU
        self.iv_index = self.global_states_manager.iv_index


class TxTransaction(Transaction):
    """
    Initiates a Tx transaction of a PDU to the network Layer
    No control messages for now (exepct use of Ack)
    """

    def __init__(self, message):
        """
        Init the Tx transaction

        :param message: The PDU we want to send received from the Upper Transport Layer and its context
        :type message: (BTMesh_Upper_Transport_Access_PDU, MeshMessageContext)
        """
        super().__init__(message)

        self.sending_thread = None

        raw_pkt = raw(self.pkt)
        if self.is_control_message and (len(raw_pkt) > 11):
            self.fragments = [raw_pkt[i : i + 8] for i in range(0, len(raw_pkt), 8)]
        elif len(raw(self.pkt)) > 15:
            self.fragments = [raw_pkt[i : i + 12] for i in range(0, len(raw_pkt), 12)]
        else:
            self.fragments.append(raw_pkt)

        self.nb_of_segments = len(self.fragments)
        self.last_sent_fragment = -1

        # True for each retransmission if we receive one ack
        self.acked_received = False

        # get the rentransmission interval and counts from the SAR state

        sar_state = self.global_states_manager.get_state("sar_transmitter")
        self.interval_step = sar_state.get_sub_state(
            "sar_segment_interval_step"
        ).get_segment_retransmission_interval()
        self.unicast_retrans_count = sar_state.get_sub_state(
            "sar_unicast_retransmissions_count"
        ).get_value()
        self.unicast_retrans_no_progress_count = sar_state.get_sub_state(
            "sar_unicast_retransmissions_without_progess_count"
        ).get_value()
        self.unicast_retrans_interval_step = sar_state.get_sub_state(
            "sar_unicast_restransmissions_intreval_step"
        ).get_unicast_retransmission_interval_step()
        self.unicast_interval_inc = sar_state.get_sub_state(
            "sar_unicast_retransmissions_interval_increment"
        ).get_unicast_restransmission_interval_increment()
        self.multicast_retrans_count = sar_state.get_sub_state(
            "sar_multicast_retransmissions_count"
        ).get_value()
        self.multicast_retrans_interval_step = sar_state.get_sub_state(
            "sar_multicast_retransmissions_interval_step"
        ).get_multicast_retransmissions_interval()

    def process_ack(self, message):
        """
        Process an ack received from a node to which this transaction is the unicast destination

        :param message: The Lower Transport Layer Ack received and its context
        :type message: (BTMesh_Lower_Transport_Segment_Acknoledgment_Message, MeshMessageContext)
        """
        pkt, ctx = message
        if self.is_transaction_finished:
            return

        # check if the net key used is the same as the one we use
        if ctx.net_key_id != self.ctx.net_key_id:
            logger.error("WRONG KEY ID USED FOR ACKED SEGEMENT MESSAGE")
            return

        # check if seq zero derived ack pdu matches the one stored
        if pkt.seq_zero != self.ctx.seq_auth & 0x1FFF:
            logger.error("WRONG SEQ AUTH VALUE FOR ACKED SEGMENT MESSAGE")
            return

        # reverse conversion : bitfield = sum(1 << num for num in acked_segments)
        acked_segments = [
            i
            for i in range(pkt.acked_segments.bit_length())
            if pkt.acked_segments & (1 << i)
        ].sort()

        # if no acked segment at all, cancel transaction (specification)
        if acked_segments == []:
            self.is_transaction_finished = True
            return

        # check if a new segment has been acked since last transmission.
        if acked_segments != self.acked_segments:
            self.acked_received = True

        self.acked_segments = acked_segments

        # check is all segments have been acked
        if len(acked_segments) == len(self.fragments):
            self.is_transaction_finished = True
            return
        # if segements left to be sent, reset timer
        else:
            self.event.set()


class RxTransaction(Transaction):
    """
    Initiates an Rx transaction for a received PDU from the network layer
    Only segmented messages (unsegmented get sent to upper transport layer directly)
    """

    def __init__(self, first_message):
        """
        Init the Transaction
        The "first_message" is the first one we receive but might not be the first segment though
        No control messages for now

        :param first_message: The message received that initiated the transaction with its context
        :type first_message: (BTMesh_Lower_Transport_Segmented_Access_Message, MeshMessageContext)
        """
        super().__init__(first_message)

        # get the sar states
        sar_state = self.global_states_manager.get_state("sar_receiver")
        self.sar_segment_threshold = sar_state.get_sub_state(
            "sar_segment_threshold"
        ).get_value()
        self.sar_ack_delay_inc = sar_state.get_sub_state(
            "sar_acknowledgment_delay_increment"
        ).get_acknowledgement_increment()
        self.sar_ack_retrans_count = (
            sar_state.get_sub_state(
                "sar_acknowledgment_retransmissions_count"
            ).get_value()
            + 1
        )
        self.sar_discard_timeout = sar_state.get_sub_state(
            "sar_discard_timeout"
        ).get_discard_timeout()
        self.sar_seg_reception_interval = sar_state.get_sub_state(
            "sar_receiver_segment_interval_step"
        ).get_segment_reception_interval()

        # total number of fragments expected
        self.seg_n = self.pkt.last_seg_number

        self.min_ack_delay = self.sar_ack_delay_inc * self.sar_seg_reception_interval

        # main ack sending thread
        self.main_ack_thread = None

        # initial delay before sending the first ack message
        self.initial_ack_delay = (
            min(self.seg_n + 0.5, self.sar_ack_delay_inc)
            * self.sar_seg_reception_interval
        )

        # epoch time of last ack sent
        self.time_last_ack = None

        # add the fragment to the dictionary
        self.fragments = {}
        self.fragments[self.pkt.seg_offset] = self.pkt.getlayer(Raw).load


@alias("lower_transport")
class LowerTransportLayer(Layer):
    def configure(self, options={}):
        """
        LowerTransport Layer.

        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """

        super().configure(options=options)

        # list queue of pending upper_transport layer message waiting to be sent to the network layer
        # keys are the dst_addr and the value are queues for each message where the dst_addr matches
        self.__queues = {}

        # stores one active transaction per src_addr
        self.state.rx_transactions = {}

        # stores one active transaction per dst_src
        self.state.tx_transactions = {}

        # for each src_addr we received a PDU from, we store the last seq_auth value for validation of seq num
        self.state.seq_auth_values = {}

        # stores the current/last seq_auth values for each src addr
        # Used to check if a new message received has a greater seq_auth than the last one
        # keys -> src_addr, values -> seq_auth (Bytes)
        self.state.seq_auth_values = {}

        self.global_states_manager = GlobalStatesManager()

    def send_to_network(self, message):
        """
        Sends the packet and its context to the network layer

        :param message: PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        self.send("network", message)

    def send_to_upper_transport(self, message):
        """
        Sends the packets and its context to the Upper Transport Layer

        :param message: PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        self.send("upper_transport", message)

    @source("network")
    def on_network_layer_message(self, message):
        """
        Handler when the Network layer sends a message with its context

        :param message: The PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message

        # if ack received
        if (
            isinstance(pkt, BTMesh_Lower_Transport_Control_Message)
            and pkt.payload_field.opcode == 0
        ):
            if ctx.src_addr in self.state.tx_transactions.keys():
                self.state.tx_transactions[ctx.src_addr].process_ack((pkt[1], ctx))

        # if access message (segment or not) received
        elif isinstance(pkt, BTMesh_Lower_Transport_Access_Message):
            # set the application_key_id (-1 if device key)
            if pkt.application_key_flag == 0:
                ctx.application_key_id = -1
            else:
                ctx.application_key_id = pkt.application_key_id

            self.dispatch_access_rx_pdu(message)

    def dispatch_access_rx_pdu(self, message):
        """
        Function that checks whether or not a received PDU is valid and how it is processed (new Transaction or not)
        (for now only access messages)

        :param message: PDU and its context
        :type message: (BTMesh_Lower_Transport_Access_Message, MeshMessageContext)
        """
        pkt, ctx = message

        seg = pkt.seg

        # if unsegmented message, just transfer it to upper transport layer (calculate the seq_auth first and check)
        if seg == 0:
            iv_index = self.global_states_manager.iv_index
            ctx.seq_auth = int.from_bytes(
                iv_index + ctx.seq_number.to_bytes(3, "big"), "big"
            )
            ctx.seq_number = ctx.seq_auth & 0xFFFFFF

            # if seq_auth is lower or equal than the stored one, discard
            if (
                ctx.src_addr in self.state.seq_auth_values.keys()
                and ctx.seq_auth <= self.state.seq_auth_values[ctx.src_addr]
            ):
                logger.warn("SEQAUTH VALUE LOWER OR EQUAL THAN STORED ONE")
                return

            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            self.send_to_upper_transport((pkt[1], ctx))

        else:
            pkt = pkt.getlayer(BTMesh_Lower_Transport_Segmented_Access_Message)
            ctx.seq_auth = calculate_seq_auth(
                self.global_states_manager.iv_index, ctx.seq_number, pkt.seq_zero
            )
            ctx.seq_zero = pkt.seq_zero
            ctx.azsmic = pkt.aszmic
            if ctx.src_addr in self.state.seq_auth_values.keys():
                # if segmented packet and lower seq_auth value, disacrd
                if ctx.seq_auth < self.state.seq_auth_values[ctx.src_addr]:
                    logger.warn(
                        "SEGAUTH VALUE LOWER THAN STORED ONE FOR SEGMENT RECEIVED"
                    )
                    return

                # if seq_auth equal, check if a Transaction exists with this seq auth (if it was an unsegmented there was no transaction)
                elif ctx.seq_auth == self.state.seq_auth_values[ctx.src_addr]:
                    if ctx.src_addr in self.state.rx_transactions.keys():
                        self.process_rx_seg_message(
                            self.state.rx_transactions[ctx.src_addr],
                            (
                                pkt,
                                ctx,
                            ),
                        )
                        return
                    else:
                        logger.warn("RECEIVED SEGMENT FOR UNSEGEMENTED SEQAUTH !")
                        return

            # if received seq_auth higher/ not stored seq_auth, start new transaction
            print("NEW TRANSACTION")
            transaction = RxTransaction((
                pkt,
                ctx,
            ))
            self.state.rx_transactions[ctx.src_addr] = transaction
            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            """
            transaction.main_ack_thread = Timer(
                transaction.initial_ack_delay / 1000,
                self.sending_ack_thread,
                args=(transaction, True, transaction.event),
            )
            """
            transaction.main_ack_thread = Timer(
                0,
                self.sending_ack_thread,
                args=(transaction, True, transaction.event),
            )
            transaction.main_ack_thread.start()

    def process_rx_seg_message(self, transaction, message):
        """
        Process an rx message containing a segment for the transaction
        (no control PDU)

        :param transaction: the rx_transaction matching the segment
        :type transaction: RxTransaction
        :param message: The message and its context
        :type message: (BTMesh_Lower_Transport_Segmented_Access_Message, MeshMessageContext)
        """
        # if transaction finished, resend ack after min delay
        pkt, ctx = message
        if transaction.is_transaction_finished:
            if transaction.time_last_ack is not None:
                delay = (
                    max(
                        0,
                        transaction.min_ack_delay
                        - (time() - transaction.time_last_ack),
                    )
                    / 1000
                )
            else:
                delay = transaction.min_ack_delay / 1000
            transaction.main_ack_thread = Timer(
                delay,
                self.sending_ack_thread,
                args=(transaction, False, transaction.event),
            )
            transaction.main_ack_thread.start()

        else:
            # check if segment is one we have already received
            if ctx.segment_number not in transaction.fragments.keys():
                transaction.fragments[pkt.seg_offset] = pkt.getlayer(Raw).load

            # if all segments received, send ack and send to upper_transport
            if len(transaction.fragments.keys()) == transaction.seg_n + 1:
                print("RECEIVED ALL")
                if transaction.time_last_ack is not None:
                    delay = (
                        max(
                            0,
                            transaction.min_ack_delay
                            - (time() - transaction.time_last_ack),
                        )
                        / 1000
                    )
                else:
                    delay = transaction.min_ack_delay / 1000

                ctx.seq_number = ctx.seq_auth & 0xFFFFFF
                """
                transaction.main_ack_thread = Timer(
                    delay,
                    self.sending_ack_thread,
                    args=(transaction, False, transaction.event),
                )
                """
                transaction.main_ack_thread = Timer(
                    0,
                    self.sending_ack_thread,
                    args=(transaction, False, transaction.event),
                )
                transaction.main_ack_thread.start()
                transaction.is_transaction_finished = True
                raw_upper_pkt = b""
                for index, fragment in sorted(transaction.fragments.items()):
                    raw_upper_pkt += fragment
                pkt = BTMesh_Upper_Transport_Access_PDU(raw_upper_pkt)
                self.send_to_upper_transport((pkt, transaction.ctx))

    @source("upper_transport")
    def on_upper_transport_layer_message(self, message):
        """
        Handler when the Upper transport Layer sends a PDU

        :param message: The Upper Transport Layer message and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message

        # if one active Tx transaction is already here for the dest_addr, we store the message in in the queue
        if (
            ctx.dest_addr in self.state.tx_transactions.keys()
            and not self.state.tx_transactions[ctx.dest_addr].is_transaction_finished
        ):
            if ctx.dest_addr in self.__queues.keys():
                self.__queues[ctx.dest_addr].put_nowait(message)
            else:
                self.__queues[ctx.dest_addr] = Queue()
                self.__queues[ctx.dest_addr].put_nowait(message)

        else:  # create transaction to send it
            transaction = TxTransaction(message)
            self.state.tx_transactions[ctx.dest_addr] = transaction
            self.start_sending_thread(transaction)

    def start_sending_thread(self, transaction):
        """
        Initiates the sending thread for a Transaction depending on the parameters of the PDU

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        """
        transaction.event = Event()
        if len(transaction.fragments) > 1:
            if transaction.dst_addr_type == UNICAST_ADDR_TYPE:
                transaction.sending_thread = Thread(
                    target=self.sending_thread_unicast_segmented,
                    args=(transaction, transaction.event),
                )
            else:
                transaction.sending_thread = Thread(
                    target=self.sending_thread_multicast_segmented,
                    args=(transaction, transaction.event),
                )
        else:
            transaction.sending_thread = Thread(
                target=self.sending_thread_unsegmented,
                args=(transaction, transaction.event),
            )

        transaction.sending_thread.start()

    def sending_thread_unicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send each segment to the network layer for a unicast destination

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        :param event: Event object to received signal from main thread
        :type: Event
        """
        while (
            transaction.unicast_retrans_count > 0
            and transaction.unicast_retrans_no_progress_count > 0
            and not transaction.is_transaction_finished
        ):
            if not transaction.acked_received:
                transaction.unicast_retrans_no_progress_count -= 1

            transaction.acked_received = False
            transaction.unicast_retrans_count -= 1
            for fragment_index in range(len(transaction.fragments)):
                if fragment_index not in transaction.acked_segments:
                    payload = (
                        BTMesh_Lower_Transport_Segmented_Access_Message(
                            aszmic=0,
                            seq_zero=transaction.ctx.seq_auth & 0x1FFF,
                            seg_offset=fragment_index,
                            last_seg_number=len(transaction.fragments),
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index
                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index
                    if transaction.ctx.application_key_id == -1:
                        application_key_flag = 0
                        application_key_id = 0
                    else:
                        application_key_flag = 1
                        application_key_id = transaction.ctx.application_key_id
                    self.send_to_network((
                        BTMesh_Lower_Transport_Access_Message(
                            seg=1,
                            application_key_flag=application_key_flag,
                            application_key_id=application_key_id,
                            payload_field=payload,
                        ),
                        segment_ctx,
                    ))
                    sleep(transaction.interval_step / 1000)
            if transaction.ctx.ttl == 0:
                event.wait(transaction.unicast_retrans_interval_step)
            else:
                event.wait(
                    transaction.unicast_retrans_interval_step
                    + (transaction.unicast_interval_inc * (transaction.ctx.ttl - 1))
                )

    def sending_thread_multicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send a segmented PDU to a multicast destination
        No ack needed

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        :param event: Event object to received signal from main thread
        :type: Event
        """
        while (
            transaction.multicast_retrans_count > 0
            and not transaction.is_transaction_finished
        ):
            transaction.multicast_retrans_count -= 1
            for fragment_index in range(len(transaction.fragments)):
                if fragment_index not in transaction.acked_segments:
                    if transaction.ctx.application_key_id == -1:
                        application_key_flag = 0
                        application_key_id = 0
                    else:
                        application_key_flag = 1
                        application_key_id = transaction.ctx.application_key_id

                    payload = (
                        BTMesh_Lower_Transport_Segmented_Access_Message(
                            aszmic=0,
                            seq_zero=transaction.ctx.seq_zero,
                            seg_offset=fragment_index,
                            last_seg_number=len(transaction.fragments),
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index

                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index

                    self.send_to_network((
                        BTMesh_Lower_Transport_Access_Message(
                            seg=1,
                            application_key_id=application_key_id,
                            application_key_flag=application_key_flag,
                            payload_field=payload,
                        ),
                        segment_ctx,
                    ))
                    sleep(transaction.interval_step / 1000)
            sleep(transaction.multicast_retrans_interval_step)

    def sending_thread_unsegmented(self, transaction, event):
        """
        Function running in a thread to send a unsegmented PDU
        No ack

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        :param event: Event object to received signal from main thread
        :type: Event
        """
        if transaction.ctx.application_key_id == -1:
            application_key_flag = 0
            application_key_id = 0
        else:
            application_key_flag = 1
            application_key_id = transaction.ctx.application_key_id

        self.send_to_network((
            BTMesh_Lower_Transport_Access_Message(
                seg=0,
                application_key_flag=application_key_flag,
                application_key_id=application_key_id,
            )
            / transaction.pkt,
            transaction.ctx,
        ))
        transaction.is_transaction_finished = True

    def sending_ack_thread(self, transaction, resend=True, event=None):
        """
        Function running a Timer object to send an ack in a seperate thread for the transaction
        Depending on the number of segments, it resends acks based on sar_segment_threshold and sar_ack_retrans_count

        :param transaction: The transaction in question
        :type transaction: RxTransaction
        :param resend: Resend or not ack based on threshold
        :type resend: boolean
        :param event: Event object to communicate with main thread
        :type event: Event
        """
        is_sending = True
        while is_sending:
            pkt = BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
                obo=0,
                seq_zero=transaction.ctx.seq_zero,
                acked_segments=sum(1 << num for num in transaction.fragments.keys()),
            )
            pkt = BTMesh_Lower_Transport_Control_Message(seg=0, opcode=0) / pkt
            ctx = copy(transaction.ctx)
            ctx.src_addr = transaction.ctx.dest_addr
            ctx.dest_addr = transaction.ctx.src_addr

            # the sequence number of the ack is
            ctx.seq_number = self.global_states_manager.get_next_seq_number()
            print("SENDING ACK WITH SEQ_NUMBER = " + str(ctx.seq_number))
            pkt.show()
            self.send_to_network((pkt, ctx))
            transaction.time_last_ack = time()

            is_sending = False

            if (
                resend
                and transaction.seg_n > transaction.sar_segment_threshold
                and transaction.sar_ack_retrans_count > 0
            ):
                is_sending = True
                event.wait(transaction.sar_seg_reception_interval / 1000)
                transaction.sar_ack_retrans_count = -1


LowerTransportLayer.add(UpperTransportLayer)
