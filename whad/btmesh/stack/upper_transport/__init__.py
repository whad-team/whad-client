"""
Upper Transport Layer

Performs encryption and decryption at application level for Access Messages
Sends and respondes to UpperLayer Control messages (no application encryption)
"""

from whad.common.stack import Layer, alias, source
from whad.btmesh.stack.utils import (
    get_address_type,
    VIRTUAL_ADDR_TYPE,
    Node,
    MeshMessageContext,
)
from whad.btmesh.stack.constants import (
    DIRECTED_FORWARDING_CREDS,
    MANAGED_FLOODING_CREDS,
)
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Model_Message,
    BTMesh_Upper_Transport_Control_Heartbeat,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Friend_Poll,
    BTMesh_Upper_Transport_Control_Friend_Clear,
    BTMesh_Upper_Transport_Control_Path_Request,
    BTMesh_Upper_Transport_Control_Friend_Offer,
    BTMesh_Upper_Transport_Control_Path_Echo_Reply,
    BTMesh_Upper_Transport_Control_Friend_Update,
    BTMesh_Upper_Transport_Control_Path_Confirmation,
    BTMesh_Upper_Transport_Control_Friend_Request,
    BTMesh_Upper_Transport_Control_Friend_Clear_Confirm,
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
    BTMesh_Upper_Transport_Control_Dependent_Node_Update,
    BTMesh_Upper_Transport_Control_Path_Echo_Request,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove,
    BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm,
    UnicastAddr,
)
from whad.btmesh.stack.access import AccessLayer
from whad.btmesh.crypto import UpperTransportLayerAppKeyCryptoManager

from queue import Queue
from scapy.all import raw
from time import sleep
import logging
from threading import Event, Timer
from copy import copy


logger = logging.getLogger(__name__)


@alias("upper_transport")
class UpperTransportLayer(Layer):
    def configure(self, options={}):
        """
        UpperTransportlayer. One for all the networks.
        For now we just discard the control messages since we dont support any of the features
        """
        super().configure(options=options)

        # Access elements and models
        self.state.profile = options["profile"]

        # Rx message queue from LowerTransportLayer
        self.__queue = Queue()

        # Set to True when a handler for an Access Message is executed
        self.state.__is_processing_message = False

        # When waiting for a specific CTL message, class we are waiting for, and the event object to notify the thread
        # The received_message containes the context and message received.
        self.state.expected_class = None
        self.state.event = Event()
        self.state.received_message = None

        # Custom handler for packets received from parent layer
        # Should take the message as argument (with context)
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

        # handlers for the Upper Transport Control messages (normal processing)
        self._handlers = {
            BTMesh_Upper_Transport_Control_Heartbeat: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Reply: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Poll: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Clear: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Request: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Offer: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Echo_Reply: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Update: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Confirmation: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Request: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Clear_Confirm: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Request_Solicitation: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Dependent_Node_Update: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Path_Echo_Request: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove: self.default_ctl_handler,
            BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm: self.default_ctl_handler,
        }

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Message with class (Scapy packet) specified

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking (Packet | MeshMessageContext) as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_hanlder(self, clazz):
        """
        Unregisters a previously registerd custom callback for a message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def check_queue(self):
        """
        If the queue is not empty, process the next UpperTransportLayer Message
        """
        if not self.__queue.empty():
            try:
                self.process_lower_transport_message(self.__queue.get_nowait())
            except Exception:
                return

    def send_to_lower_transport(self, message):
        """
        Sends an encrypted Upper Layer Access PDU and its context to the Lower Transport Layer

        :param message: The PDU and its context
        :type message: (BTMesh_Upper_Transport_Access_PDU, MeshMessageContext)
        """
        pkt, ctx = message
        self.send("lower_transport", message)

    def send_to_access_layer(self, message):
        """
        Sends the decrypted Access PDU to the Access Layer with its context

        :param message: The PDU and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        self.send("access", message)

    def wait_for_message(self, clazz):
        """
        Sets the a class for the type of message we need to receive. The others are discarded.
        When message is received, event is set to notify waiting thread.

        THE RECEIVED MESSAGE WILL NOT BE PROCESSED BY THE MODELS.

        :param clazz: Class of message we are waiting for
        :type clazz: [TODO:type]
        """
        self.state.event.clear()
        self.state.received_message = None
        self.state.expected_class = clazz

        self.state.event.wait(timeout=3)
        self.state.expected_class = None
        return self.state.received_message

    def __get_app_key_index_from_aid(self, aid):
        """
        Returns the application_key_index from the aid

        :param aid: The aid in the received packet
        :type aid: int
        """
        app_keys = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_all_values()
        )
        for key in app_keys:
            if (
                isinstance(key, UpperTransportLayerAppKeyCryptoManager)
                and key.aid == aid
            ):
                return key.key_index
        return None

    def __get_all_label_uuids(self):
        """
        Returns a set of all the label uuids of the device (one that at least one model is subscribed to)
        """
        label_uuids = []
        subscription_states = (
            self.state.profile.get_configuration_server_model().get_all_states(
                "subscription_list"
            )
        )
        for state in subscription_states:
            label_uuids.extend(state.get_value("label_uuids"))

        return list(set(label_uuids))

    def __try_decrypt_with_key(self, pkt, ctx, key):
        """
        Tries to decrypt the message with the given key in argument

        Returns the plaintext message if success, None otherwise

        :param pkt: The packet the decypher
        :type pkt: BTMesh_Upper_Transport_Access_PDU
        :param ctx: the context of the message
        :type ctx: MeshMessageContext
        :param key: The key to use to decrypt
        :type key: UpperTransportLayerAppKeyCryptoManager | UpperTransportLayerDevKeyCryptoManager
        :returns: The plaintext of the message if success, None otherwise
        :rtype: bytes | None
        """
        if get_address_type(ctx.dest_addr) == VIRTUAL_ADDR_TYPE:
            # get all the label uuids we know in the device (we cannot know the target model, so we need to get all of them ...)
            label_uuids = self.__get_all_label_uuids()
            (plaintext_message, is_auth_valid, label_uuid) = key.decrypt_virtual(
                enc_data=raw(pkt),
                aszmic=ctx.aszmic,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.profile.iv_index,
                label_uuid=label_uuids,
            )
            ctx.uuid = label_uuid
        else:
            (plaintext_message, is_auth_valid) = key.decrypt(
                enc_data=raw(pkt),
                aszmic=0,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.profile.iv_index,
            )

        if not is_auth_valid and plaintext_message is not None:
            logger.debug("WRONG AUTHENTICATION VALUE IN UpperTransportlayer")
            logger.debug(key)
            logger.debug(is_auth_valid)
            logger.debug(plaintext_message)
            return None

        return plaintext_message

    def __try_decrypt(self, pkt, ctx):
        """
        Tries to decrypt the message based on the context (fetch the keys and try to decipher)
        Will try to decrypt with appropriate AppKey if we have it, or DevKey if we have it.

        If decryption fails (no key, or wrong MIC), returns None
        if decryption pass, returns the plaintext

        :param pkt: The packet the decypher
        :type pkt: BTMesh_Upper_Transport_Access_PDU
        :param ctx: the context of the message
        :type ctx: MeshMessageContext
        :returns: The plaintext of the message if success, None otherwise
        :rtype: bytes | None
        """
        # get the actual application_key_index from aid if AppKey
        if ctx.application_key_index != -1:
            ctx.application_key_index = self.__get_app_key_index_from_aid(ctx.aid)
            app_key = (
                self.state.profile.get_configuration_server_model()
                .get_state("app_key_list")
                .get_value(ctx.application_key_index)
            )

            # If we dont have the app_key, we discard the message
            if app_key is None:
                return

            return self.__try_decrypt_with_key(pkt, ctx, app_key)

        # if device key used, we don't know if its dst or src dev key.
        else:
            dev_key_src = self.state.profile.get_dev_key(ctx.src_addr)
            # if we have no key to decrypt, discard
            if dev_key_src is not None:
                plaintext_message = self.__try_decrypt_with_key(pkt, ctx, dev_key_src)
                if plaintext_message is not None:
                    ctx.dev_key_address = ctx.src_addr
                    return plaintext_message

            dev_key_dst = self.state.profile.get_dev_key(ctx.dest_addr)
            if dev_key_dst:
                ctx.dev_key_address = ctx.dest_addr
                return self.__try_decrypt_with_key(pkt, ctx, dev_key_dst)

        return None

    @source("access")
    def on_access_message(self, message):
        """
        Process an Access message sent by the Access layer

        :param message: Message and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message

        # Get the appropriate key from context
        if ctx.application_key_index == -1:
            key = self.state.profile.get_dev_key(address=ctx.dev_key_address)
        else:
            key = self.state.profile.get_app_key(ctx.application_key_index)

        if key is None:
            logger.debug("No key found for the message !")
            return

        ctx.aid = key.aid

        # set the PDU sequence number
        # max 4 fragments !
        # Only if the seq_num is None, otherwise means we hardcoded it (in shell for ex)
        if ctx.seq_number is None:
            ctx.seq_number = self.state.profile.get_next_seq_number(inc=4)
        
        if get_address_type(ctx.dest_addr) == VIRTUAL_ADDR_TYPE:
            encrypted_message, ctx.seq_auth = key.encrypt(
                access_message=raw(pkt),
                aszmic=ctx.aszmic,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.profile.iv_index,
                label_uuid=ctx.uuid,
            )
        else:
            encrypted_message, ctx.seq_auth = key.encrypt(
                access_message=raw(pkt),
                aszmic=ctx.aszmic,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.profile.iv_index,
            )
        pkt = BTMesh_Upper_Transport_Access_PDU(encrypted_message)
        self.send_to_lower_transport((pkt, ctx))

    @source("lower_transport")
    def on_lower_transport_message(self, message):
        """
        Handler when an UpperTransportLayer message is received from Network

        :param message: Message received with its context
        :type message: (Packet, MeshMessageContext)
        """
        self.__queue.put_nowait(message)
        if not self.state.__is_processing_message:
            self.check_queue()

    def process_lower_transport_message(self, message):
        """
        Process a message sent by the Lower Transport Layer with its context
        Can be a control message OR an encrypted Access message
        For now control messages are discarded

        :param message: Message and its context
        :type message: (Packet, MeshMessageContext)
        """
        self.state.__is_processing_message = True
        pkt, ctx = message
        # if custom handler, use it
        if type(pkt) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(pkt)](message)
            # if custom handler says to return after itself
            if not continue_processing:
                self.state.__is_processing_message = False
                self.check_queue()
                return

        # if control message, get handler for message and run it
        if not isinstance(pkt, BTMesh_Upper_Transport_Access_PDU):
            # Check if we are waiting for a message in particular
            if (
                self.state.expected_class is not None
                and type(pkt) is self.state.expected_class
            ):
                self.state.expected_class = None
                self.state.received_message = message
                self.state.event.set()

            self._handlers[type(pkt)](message)
            self.state.__is_processing_message = False
            self.check_queue()
            return

        plaintext = self.__try_decrypt(pkt, ctx)

        if plaintext is None:
            logger.debug("Decryption failed in UpperTransportlayer")
            self.state.__is_processing_message = False
            self.check_queue()
            return

        pkt = BTMesh_Model_Message(plaintext)
        self.send_to_access_layer((pkt, ctx))

        self.state.__is_processing_message = False
        self.check_queue()

    def default_ctl_handler(self, message):
        """
        Default Handler for received control messages

        :param message: The ctl control message packet and its context
        :type message: (Packet, MeshMessageContext)
        """
        logger.debug("DEFAULT CTL PACKET HANDLER, NOTHING TO DO")
        pkt, ctx = message
        # pkt.show()
        return

    def send_control_message(self, message):
        """
        Inject into the protocol stack a control message

        :param msg: The Control packet and its context
        :type pkt: (Packet, MeshMessageContext)
        """
        pkt, ctx = message
        if (
            ctx.src_addr == self.state.profile.get_primary_element_addr()
            or ctx.seq_number is None
        ):
            ctx.seq_number = self.state.profile.get_next_seq_number(inc=5)
            pkt.path_origin_forwarding_number = (
                self.state.profile.get_next_forwarding_number()
            )

        iv_index = self.state.profile.iv_index
        ctx.seq_auth = int.from_bytes(
            iv_index + ctx.seq_number.to_bytes(3, "big"), "big"
        )
        self.send_to_lower_transport((pkt, ctx))

    """Functions and callbacks for the Network discovery method using Directed Forwarding, not protocol compliant"""

    def on_path_reply_network_discovery(self, message):
        """
        On Path Reply received when in a network discovery mode (thread running)
        For network discovery (A1), or for A5 (dependent_nodes_update attack)

        :param message: Path Reply Received with its context
        :type message: (BTMesh_Upper_Transport_Control_Path_Reply,MeshMessageContext)
        """

        pkt, ctx = message
        # reply probably for the topology discovery
        if pkt.path_origin == 0x7FFF:
            if pkt.confirmation_request == 1:
                resp_pkt = BTMesh_Upper_Transport_Control_Path_Confirmation(
                    path_origin=pkt.path_origin,
                    path_target=pkt.path_target_unicast_addr_range.range_start,
                )
                resp_ctx = MeshMessageContext()
                resp_ctx.creds = DIRECTED_FORWARDING_CREDS
                resp_ctx.src_addr = self.state.profile.get_primary_element_addr()
                resp_ctx.dest_addr = 0xFFFB
                resp_ctx.ttl = 0
                resp_ctx.is_ctl = True
                resp_ctx.net_key_id = 0
                timer = Timer(
                    0.5, self.send_control_message, args=[(resp_pkt, resp_ctx)]
                )
                timer.start()

            if pkt.path_target_unicast_addr_range.length_present:
                range_length = pkt.path_target_unicast_addr_range.range_length
            else:
                range_length = 0

            distant_node_addr = pkt.path_target_unicast_addr_range.range_start
            distant_node = self.state.profile.get_distant_node(distant_node_addr)

            if distant_node is None:
                distant_node = Node(address=distant_node_addr, addr_range=range_length)
                self.state.profile.add_distant_node(distant_node)

            return

    def discover_topology_thread(self, addr_low, addr_high, delay=3.5):
        """
        "Attack" to discover all the nodes that support DF (they all should ...) and the distance to them

        We send PATH_REQUEST with a PATH_ORIGIN that doesnt exist (very high address) for all the addrs in the range specified

        :param addr_low: [TODO:description]
        :type addr_low: [TODO:type]
        :param addr_high: [TODO:description]
        :type addr_high: [TODO:type]
        :param delay: Delay between 2 Path Request sent, defaults to 3.5
        :type: float, optional
        """
        base_pkt = BTMesh_Upper_Transport_Control_Path_Request(
            on_behalf_of_dependent_origin=0,
            path_origin_path_metric_type=0,
            path_discovery_interval=0,
            path_origin_path_lifetime=0,
            path_origin_path_metric=0,
            destination=0,
            path_origin_unicast_addr_range=UnicastAddr(range_start=0x7FFF),
        )
        base_ctx = MeshMessageContext()
        base_ctx.creds = DIRECTED_FORWARDING_CREDS
        base_ctx.src_addr = self.state.profile.get_primary_element_addr()
        base_ctx.dest_addr = 0xFFFB  # all directed forwading nodes
        base_ctx.ttl = 0
        base_ctx.is_ctl = True
        base_ctx.net_key_id = 0

        try:
            old_callback = self._handlers[BTMesh_Upper_Transport_Control_Path_Reply]
        except KeyError:
            old_callback = lambda message: None
        self.register_callback_ctl_message(
            BTMesh_Upper_Transport_Control_Path_Reply,
            self.on_path_reply_network_discovery,
        )
        for dest in range(addr_low, addr_high + 1):
            if self.state.profile.is_unicast_addr_ours(dest):
                continue
            base_pkt.destination = dest
            self.send_control_message(
                (
                    base_pkt,
                    base_ctx,
                )
            )
            sleep(delay)

        # Wait a little to be sure we receive all resonponses before resetting the Path_Reply callback
        sleep(3)
        self.register_callback_ctl_message(
            BTMesh_Upper_Transport_Control_Path_Reply, old_callback
        )

    def discovery_get_hops_thread(self):
        """
        For the nodes we have discovered with the network discovery attack, we try to get their distance with the
        Path Echo Request technique
        """

        ctx = MeshMessageContext()
        ctx.ttl = 127
        ctx.creds = DIRECTED_FORWARDING_CREDS
        ctx.src_addr = 0x7FFF
        ctx.is_ctl = True
        ctx.net_key_id = 0

        try:
            old_callback = self._handlers[
                BTMesh_Upper_Transport_Control_Path_Echo_Reply
            ]
        except KeyError:
            old_callback = lambda message: None

        self.register_callback_ctl_message(
            BTMesh_Upper_Transport_Control_Path_Echo_Reply,
            self.on_path_echo_reply_network_discovery,
        )

        distant_nodes = self.state.profile.distant_nodes
        for addr in distant_nodes.keys():
            pkt = BTMesh_Upper_Transport_Control_Path_Echo_Request()
            ctx_send = copy(ctx)
            ctx_send.dest_addr = addr
            self.send_control_message((pkt, ctx_send))
            sleep(1)

        # Wait a little to be sure we receive all resonponses before resetting the Path_Reply callback
        sleep(1)
        self.register_callback_ctl_message(
            BTMesh_Upper_Transport_Control_Path_Echo_Reply, old_callback
        )

    def on_path_echo_reply_network_discovery(self, message):
        pkt, ctx = message

        # Path Echo reply for the network discovery
        if ctx.dest_addr == 0x7FFF:
            try:
                distant_node = self.state.profile.get_distant_node(pkt.destination)
            except KeyError:
                return
            if (
                distant_node.distance is None
                or (0x7F - ctx.ttl) < distant_node.distance
            ):
                distant_node.distance = 0x7F - ctx.ttl


UpperTransportLayer.add(AccessLayer)
