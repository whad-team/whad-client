"""
        network_layer.send("lower_transport", (seg2, ctx2))
Lower Transport Layer

Handles Segmentation/Reassembly of Upper Transport PDU
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.btmesh.stack.upper_transport import UpperTransportLayer
from whad.btmesh.stack.upper_transport.df_attacks import UpperTransportDFAttacks
from whad.btmesh.stack.utils import (
    get_address_type,
    UNICAST_ADDR_TYPE,
    calculate_seq_auth,
)
from whad.btmesh.stack.constants import OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT
from queue import Queue
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Lower_Transport_Segmented_Access_Message,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Segment_Acknoledgment_Message,
    BTMesh_Lower_Transport_Control_Message,
    BTMesh_Lower_Transport_Segmented_Control_Message,
    BTMesh_Upper_Transport_Control_Friend_Poll,
    BTMesh_Upper_Transport_Control_Friend_Update,
    BTMesh_Upper_Transport_Control_Friend_Request,
    BTMesh_Upper_Transport_Control_Friend_Offer,
    BTMesh_Upper_Transport_Control_Friend_Clear,
    BTMesh_Upper_Transport_Control_Friend_Clear_Confirm,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm,
    BTMesh_Upper_Transport_Control_Heartbeat,
    BTMesh_Upper_Transport_Control_Path_Request,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Path_Confirmation,
    BTMesh_Upper_Transport_Control_Path_Echo_Request,
    BTMesh_Upper_Transport_Control_Path_Echo_Reply,
    BTMesh_Upper_Transport_Control_Dependent_Node_Update,
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
)


from scapy.all import raw, Raw
from threading import Thread, Event, Timer
from time import sleep, time
from copy import copy


logger = logging.getLogger(__name__)


class Transaction:
    def __init__(self, message):
        """
        Initiates a transaction, Rx or Tx (Lower Transport Layer)
        Used to segment and reassemble on the Lower Transport Layer

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


class TxTransaction(Transaction):

    def __init__(self, message, sar_transmitter_state):
        """
        Init the Tx transaction

        :param message: The PDU we want to send received from the Upper Transport Layer and its context
        :type message: (BTMesh_Upper_Transport_Access_PDU | BTMesh_, MeshMessageContext)
        :param sar_transmitter_state: The  SARTransmitterCompositeState  that lives in the ConfigurationServerModel
        :param:  SARTransmitterCompositeState
        """

        super().__init__(message)

        self.sending_thread = None

        raw_pkt = raw(self.pkt)
        self.fragments = []

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

        # get the rentransmission interval and counts from the SAR state in the ConfigurationServerModel
        sar_state = sar_transmitter_state
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
            "sar_unicast_retransmissions_interval_step"
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

        # if control message, get the opcode
        if self.ctx.is_ctl:
            self.opcode = list(OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT.keys())[
                list(OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT.values()).index(
                    self.pkt.__class__
                )
            ]

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
            logger.warn("WRONG KEY ID USED FOR ACKED SEGEMENT MESSAGE")
            return

        # check if seq zero derived ack pdu matches the one stored
        if pkt.seq_zero != self.ctx.seq_auth & 0x1FFF:
            logger.warn("WRONG SEQ AUTH VALUE FOR ACKED SEGMENT MESSAGE")
            return

        # if no acked segment at all, cancel transaction (specification)
        if pkt.acked_segments == 0:
            self.is_transaction_finished = True
            return

        # reverse conversion : bitfield = sum(1 << num for num in acked_segments)
        acked_segments = [
            i
            for i in range(pkt.acked_segments.bit_length())
            if pkt.acked_segments & (1 << i)
        ]
        acked_segments.sort()

        # check if a new segment has been acked since last transmission.
        if acked_segments != self.acked_segments:
            self.acked_received = True

        self.acked_segments = acked_segments

        # check is all segments have been acked
        if len(acked_segments) == self.nb_of_segments:
            self.is_transaction_finished = True
            return
        # if segements left to be sent, reset timer
        else:
            self.event.set()


class RxTransaction(Transaction):
    """
    Initiates an Rx transaction for a received PDU from the network layer (Lower Transport Layer and sniffer)
    Only segmented messages (unsegmented get sent to upper transport layer directly/yieled by sniffer)
    """

    def __init__(self, first_message, sar_receiver_state):
        """
        Init the Transaction
        The "first_message" is the first one we receive but might not be the first segment though
        No control messages for now

        :param first_message: The message received that initiated the transaction with its context
        :type first_message: (BTMesh_Lower_Transport_Segmented_Access_Message, MeshMessageContext)
        :param sar_receiver_state: The SAR received composite state  (lives in the ConfigurationServerModel), defaults to None
        :type sar_receiver_state: SARReceiverCompositeState, optional
        """

        super().__init__(first_message)

        # get the sar states
        sar_state = sar_receiver_state
        self.sar_segment_threshold = sar_state.get_sub_state(
            "sar_segment_threshold"
        ).get_value()
        self.sar_ack_delay_inc = sar_state.get_sub_state(
            "sar_acknowledgment_delay_increment"
        ).get_acknowledgement_increment()
        self.sar_ack_retrans_count = sar_state.get_sub_state(
            "sar_acknowledgment_retransmissions_count"
        ).get_acknowledgment_retransmissions_count()
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

        # Allocate enough seq numbers for all acks that could be sent for this Transaction
        # We have the initial ack, plus a number of retransmission, plus one if replay of already received transaction
        self.max_nb_ack_sent = self.sar_ack_retrans_count + 2
        self.ack_seq_num = None
        self.max_ack_seq_num = None

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

        # If ctl message, opcode (set by the layer from the layer above the segment)
        self.opcode = 0


@alias("lower_transport")
class LowerTransportLayer(Layer):
    def configure(self, options={}):
        """
        LowerTransport Layer.

        :param options: [TODO:description], defaults to {}.
        :type options: [TODO:type], optional
        """

        super().configure(options=options)

        # Custom handler for packets received from parent layer
        # Should take the message as argument (with context)
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

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

        self.state.profile = options["profile"]

        # If we need the UpperTransportLayer for the DF attacks
        if "df_attacks" in options:
            self.remove(UpperTransportLayer)
            self.add(UpperTransportDFAttacks)

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Access Message with class (Scapy packet) specified
        If long processing, creating a handler that launches a seperate thread is advised.

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking (Packet | MeshMessageContext) as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_hanlder(self, clazz):
        """
        Unregisters a previously registerd custom callback for an Access message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def send_to_network(self, message):
        """
        Sends the packet and its context to the network layer

        :param message: PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message
        self.send("network", message)

    def send_to_upper_transport(self, message):
        """
        Sends the packets and its context to the Upper Transport Layer

        :param message: PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message
        self.send("upper_transport", message)

    @source("network")
    def on_network_layer_message(self, message):
        """
        Handler when the Network layer sends a message with its context

        :param message: The PDU and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message
        # if custom handler, use it
        if type(pkt) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(pkt)](message)
            # if custom handler says to return after itself
            if not continue_processing:
                return

        # if ack received
        if isinstance(pkt, BTMesh_Lower_Transport_Control_Message):
            if pkt.opcode == 0 and ctx.src_addr in self.state.tx_transactions.keys():
                self.state.tx_transactions[ctx.src_addr].process_ack((pkt[1], ctx))
            else:
                self.dispatch_control_rx_pdu(message)

        # if access message (segment or not) received
        elif isinstance(pkt, BTMesh_Lower_Transport_Access_Message):
            # set the application_key_id (-1 if device key)
            if pkt.application_key_flag == 0:
                ctx.aid = 0
                ctx.application_key_index = -1
            else:
                ctx.aid = pkt.application_key_id
                # to be changed in upper layer if needed
                ctx.application_key_index = 0

            self.dispatch_access_rx_pdu(message)

    def dispatch_control_rx_pdu(self, message):
        """
        Checks validity of Control PDU and processes it if needed

        :param message: The message received with its context
        :type message: (BTMesh_Lower_Transport_Control_Message, MeshMessageContext)
        """
        pkt, ctx = message
        seg = pkt.seg

        if seg == 0:
            iv_index = self.state.profile.iv_index
            ctx.seq_auth = int.from_bytes(
                iv_index + ctx.seq_number.to_bytes(3, "big"), "big"
            )
            ctx.seq_number = ctx.seq_auth & 0xFFFFFF

            # if seq_auth is lower or equal than the stored one, discard
            if (
                ctx.src_addr in self.state.seq_auth_values.keys()
                and ctx.seq_auth <= self.state.seq_auth_values[ctx.src_addr]
            ):
                logger.debug(
                    "SEQAUTH VALUE LOWER OR EQUAL THAN STORED ONE IN CTL MESSAGE"
                )
                return

            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            self.send_to_upper_transport((pkt[1], ctx))
            return

        else:
            # Save opcode
            opcode = pkt.opcode
            pkt = pkt.getlayer(BTMesh_Lower_Transport_Segmented_Control_Message)
            ctx.seq_auth = calculate_seq_auth(
                self.state.profile.iv_index, ctx.seq_number, pkt.seq_zero
            )
            if ctx.src_addr in self.state.seq_auth_values.keys():
                # if segmented packet and lower seq_auth value, disacrd
                if ctx.seq_auth < self.state.seq_auth_values[ctx.src_addr]:
                    logger.debug(
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

            # get SAR received state from profile
            sar_state = self.state.profile.get_configuration_server_model().get_state(
                "sar_receiver"
            )
            transaction = RxTransaction(
                (
                    pkt,
                    ctx,
                ),
                sar_state,
            )
            transaction.opcode = opcode
            self.state.rx_transactions[ctx.src_addr] = transaction
            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            transaction.event = Event()
            transaction.event.set()

            # only send ack if message to unicast addr destination
            if get_address_type(ctx.dest_addr) == UNICAST_ADDR_TYPE:
                transaction.main_ack_thread = Timer(
                    transaction.initial_ack_delay / 1000,
                    self.sending_ack_thread,
                    args=(transaction, True, transaction.event),
                )
                transaction.main_ack_thread.start()

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
            iv_index = self.state.profile.iv_index
            ctx.seq_auth = int.from_bytes(
                iv_index + ctx.seq_number.to_bytes(3, "big"), "big"
            )
            ctx.seq_number = ctx.seq_auth & 0xFFFFFF

            # if seq_auth is lower or equal than the stored one, discard
            if (
                ctx.src_addr in self.state.seq_auth_values.keys()
                and ctx.seq_auth <= self.state.seq_auth_values[ctx.src_addr]
            ):
                logger.debug("SEQAUTH VALUE LOWER OR EQUAL THAN STORED ONE")
                return

            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            self.send_to_upper_transport((pkt[1], ctx))
            return

        else:
            pkt = pkt.getlayer(BTMesh_Lower_Transport_Segmented_Access_Message)
            ctx.seq_auth = calculate_seq_auth(
                self.state.profile.iv_index, ctx.seq_number, pkt.seq_zero
            )
            ctx.seq_zero = pkt.seq_zero
            ctx.azsmic = pkt.aszmic
            if ctx.src_addr in self.state.seq_auth_values.keys():
                # if segmented packet and lower seq_auth value, disacrd
                if ctx.seq_auth < self.state.seq_auth_values[ctx.src_addr]:
                    logger.debug(
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
                        logger.debug("RECEIVED SEGMENT FOR UNSEGEMENTED SEQAUTH !")
                        return

            # if received seq_auth higher/ not stored seq_auth, start new transaction
            sar_state = self.state.profile.get_configuration_server_model().get_state(
                "sar_receiver"
            )
            transaction = RxTransaction(
                (
                    pkt,
                    ctx,
                ),
                sar_state,
            )
            self.state.rx_transactions[ctx.src_addr] = transaction
            self.state.seq_auth_values[ctx.src_addr] = ctx.seq_auth
            transaction.event = Event()
            transaction.event.set()

            if get_address_type(ctx.dest_addr) == UNICAST_ADDR_TYPE:
                transaction.main_ack_thread = Timer(
                    transaction.initial_ack_delay / 1000,
                    self.sending_ack_thread,
                    args=(transaction, True, transaction.event),
                )
                transaction.main_ack_thread.start()

    def process_rx_seg_message(self, transaction, message):
        """
        Process an rx message containing a segment for the transaction

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

            # Stop previous thread if necessary
            transaction.event.clear()
            transaction.event = Event()

            # only start the ack thread for unicast destination...
            if get_address_type(ctx.dest_addr) == UNICAST_ADDR_TYPE:
                transaction.main_ack_thread = Timer(
                    delay,
                    self.sending_ack_thread,
                    args=(transaction, False, transaction.event),
                )
                transaction.event.set()
                transaction.main_ack_thread.start()

        else:
            # check if segment is one we have already received
            if pkt.seg_offset not in transaction.fragments.keys():
                transaction.fragments[pkt.seg_offset] = pkt.getlayer(Raw).load

            # if all segments received, send ack and send to upper_transport
            if len(transaction.fragments.keys()) == transaction.seg_n + 1:
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

                # "kill" previous ack sending thread to send last one
                transaction.event.clear()
                transaction.event = Event()

                # only start the ack thread for unicast destination...
                if get_address_type(ctx.dest_addr) == UNICAST_ADDR_TYPE:

                    transaction.main_ack_thread = Timer(
                        delay,
                        self.sending_ack_thread,
                        args=(transaction, False, transaction.event),
                    )
                    transaction.event.set()
                    transaction.main_ack_thread.start()

                transaction.is_transaction_finished = True

                raw_upper_pkt = b""
                for index, fragment in sorted(transaction.fragments.items()):
                    raw_upper_pkt += fragment

                if transaction.ctx.is_ctl:
                    pkt = OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT[transaction.opcode](
                        raw_upper_pkt
                    )
                else:
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
            sar_state = self.state.profile.get_configuration_server_model().get_state(
                "sar_transmitter"
            )
            transaction = TxTransaction(message, sar_state)
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
                if transaction.ctx.is_ctl:
                    transaction.sending_thread = Thread(
                        target=self.sending_thread_ctl_unicast_segmented,
                        args=(transaction, transaction.event),
                    )
                else:
                    transaction.sending_thread = Thread(
                        target=self.sending_thread_access_unicast_segmented,
                        args=(transaction, transaction.event),
                    )
            else:
                if transaction.ctx.is_ctl:
                    transaction.sending_thread = Thread(
                        target=self.sending_thread_ctl_multicast_segmented,
                        args=(transaction, transaction.event),
                    )
                else:
                    transaction.sending_thread = Thread(
                        target=self.sending_thread_access_multicast_segmented,
                        args=(transaction, transaction.event),
                    )
        else:
            if transaction.ctx.is_ctl:
                transaction.sending_thread = Thread(
                    target=self.sending_thread_ctl_unsegmented,
                    args=(transaction, transaction.event),
                )
            else:
                transaction.sending_thread = Thread(
                    target=self.sending_thread_access_unsegmented,
                    args=(transaction, transaction.event),
                )

        transaction.sending_thread.start()

    def sending_thread_ctl_unicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send each segment to the network layer for a unicast destination
        FOR CONTROL MESSAGES

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
                        BTMesh_Lower_Transport_Segmented_Control_Message(
                            seq_zero=transaction.ctx.seq_number,
                            seg_offset=fragment_index,
                            last_seg_number=len(transaction.fragments) - 1,
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index
                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index
                    self.send_to_network(
                        (
                            BTMesh_Lower_Transport_Control_Message(
                                seg=1,
                                opcode=transaction.opcode,
                                payload_field=payload,
                            ),
                            segment_ctx,
                        )
                    )
                    sleep(transaction.interval_step / 1000)
            if transaction.ctx.ttl == 0:
                event.wait(transaction.unicast_retrans_interval_step / 1000)
            else:
                event.wait(
                    (
                        transaction.unicast_retrans_interval_step
                        + (transaction.unicast_interval_inc * (transaction.ctx.ttl - 1))
                    )
                    / 1000
                )

    def sending_thread_access_unicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send each segment to the network layer for a unicast destination
        For Access messages

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
                            last_seg_number=len(transaction.fragments) - 1,
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index
                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index
                    if transaction.ctx.application_key_index == -1:
                        application_key_flag = 0
                        application_key_id = 0
                    else:
                        application_key_flag = 1
                        application_key_id = transaction.ctx.aid
                    self.send_to_network(
                        (
                            BTMesh_Lower_Transport_Access_Message(
                                seg=1,
                                application_key_flag=application_key_flag,
                                application_key_id=application_key_id,
                                payload_field=payload,
                            ),
                            segment_ctx,
                        )
                    )
                    sleep(transaction.interval_step / 1000)
            if transaction.ctx.ttl == 0:
                event.wait(transaction.unicast_retrans_interval_step / 1000)
            else:
                event.wait(
                    (
                        transaction.unicast_retrans_interval_step
                        + (transaction.unicast_interval_inc * (transaction.ctx.ttl - 1))
                    )
                    / 1000
                )

    def sending_thread_access_multicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send a segmented PDU to a multicast destination
        For Access messages
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
                    if transaction.ctx.application_key_index == -1:
                        application_key_flag = 0
                        application_key_id = 0
                    else:
                        application_key_flag = 1
                        application_key_id = transaction.ctx.aid

                    payload = (
                        BTMesh_Lower_Transport_Segmented_Access_Message(
                            aszmic=0,
                            seq_zero=transaction.ctx.seq_number,
                            seg_offset=fragment_index,
                            last_seg_number=len(transaction.fragments) - 1,
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index

                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index

                    self.send_to_network(
                        (
                            BTMesh_Lower_Transport_Access_Message(
                                seg=1,
                                application_key_id=application_key_id,
                                application_key_flag=application_key_flag,
                                payload_field=payload,
                            ),
                            segment_ctx,
                        )
                    )
                    sleep(transaction.interval_step / 1000)
            sleep(transaction.multicast_retrans_interval_step / 1000)

    def sending_thread_ctl_multicast_segmented(self, transaction, event):
        """
        Function running in the sending thread to send a segmented PDU to a multicast destination
        For ctl messages
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
                    payload = (
                        BTMesh_Lower_Transport_Segmented_Control_Message(
                            seq_zero=transaction.ctx.seq_number,
                            seg_offset=fragment_index,
                            last_seg_number=len(transaction.fragments) - 1,
                        )
                        / transaction.fragments[fragment_index]
                    )

                    # create new context for the segment
                    segment_ctx = copy(transaction.ctx)
                    segment_ctx.segment_number = fragment_index

                    segment_ctx.seq_number = transaction.ctx.seq_number + fragment_index

                    self.send_to_network(
                        (
                            BTMesh_Lower_Transport_Control_Message(
                                seg=1,
                                opcode=transaction.opcode,
                                payload_field=payload,
                            ),
                            segment_ctx,
                        )
                    )
                    sleep(transaction.interval_step / 1000)
            sleep(transaction.multicast_retrans_interval_step / 1000)

    def sending_thread_access_unsegmented(self, transaction, event):
        """
        Function running in a thread to send a unsegmented PDU
        For Access messages
        No ack

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        :param event: Event object to received signal from main thread
        :type: Event
        """
        if transaction.ctx.application_key_index == -1:
            application_key_flag = 0
            application_key_id = 0
        else:
            application_key_flag = 1
            application_key_id = transaction.ctx.aid

        self.send_to_network(
            (
                BTMesh_Lower_Transport_Access_Message(
                    seg=0,
                    application_key_flag=application_key_flag,
                    application_key_id=application_key_id,
                )
                / transaction.pkt,
                transaction.ctx,
            )
        )
        transaction.is_transaction_finished = True

    def sending_thread_ctl_unsegmented(self, transaction, event):
        """
        Function running in a thread to send a unsegmented PDU
        For control messages
        No ack

        :param transacion: Tx Transaction for which we start the thread
        :type transaction: TxTransaction
        :param event: Event object to received signal from main thread
        :type: Event
        """
        self.send_to_network(
            (
                BTMesh_Lower_Transport_Control_Message(seg=0, opcode=transaction.opcode)
                / transaction.pkt,
                transaction.ctx,
            )
        )
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
        # If the seq numbers for the acks have not been allocated yet
        # We allocate the total number of seq numbers for all the acks possibly sent for this RxTransaction
        if transaction.ack_seq_num is None:
            transaction.ack_seq_num = self.state.profile.get_next_seq_number(
                inc=transaction.max_nb_ack_sent
            )
            transaction.max_ack_seq_num = (
                transaction.ack_seq_num + transaction.max_nb_ack_sent - 1
            )

        while event.is_set() and transaction.ack_seq_num <= transaction.max_ack_seq_num:
            pkt = BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
                obo=0,
                seq_zero=transaction.ctx.seq_auth & 0x1FFF,
                acked_segments=sum(1 << num for num in transaction.fragments.keys()),
            )
            pkt = BTMesh_Lower_Transport_Control_Message(seg=0, opcode=0) / pkt
            ctx = copy(transaction.ctx)
            ctx.src_addr = transaction.ctx.dest_addr
            ctx.dest_addr = transaction.ctx.src_addr
            ctx.is_ctl = True
            ctx.creds = 0  # Always with managed flooding

            # the sequence number of the ack is the one from our pool for this transaction
            ctx.seq_number = transaction.ack_seq_num
            transaction.ack_seq_num += 1
            self.send_to_network((pkt, ctx))
            transaction.time_last_ack = time()
            transaction.sar_ack_retrans_count = -1

            if (
                not resend
                or transaction.seg_n <= transaction.sar_segment_threshold
                or transaction.sar_ack_retrans_count > 0
            ):
                return

            sleep(transaction.sar_seg_reception_interval / 1000)


LowerTransportLayer.add(UpperTransportLayer)
