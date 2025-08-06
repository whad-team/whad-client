"""
Upper Transport Layer

Performs encryption and decryption at application level for Access Messages
Sends and respondes to UpperLayer Control messages (no application encryption)
"""

import logging
from threading import Event
from whad.common.stack import Layer, alias, source
from whad.btmesh.stack.utils import (
    get_address_type,
    VIRTUAL_ADDR_TYPE,
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
)
from whad.btmesh.stack.access import AccessLayer
from queue import Queue
from scapy.all import raw
from whad.btmesh.crypto import UpperTransportLayerAppKeyCryptoManager

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

        # handlers for the Upper Transport Control messages
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

    def check_queue(self):
        """
        If the queue is not empty, process the next UpperTransportLayer Message
        """
        if not self.__queue.empty():
            self.process_lower_transport_message(self.__queue.get_nowait())

    def send_to_lower_transport(self, message):
        """
        Sends an encrypted Upper Layer Access PDU and its context to the Lower Transport Layer

        :param message: The PDU and its context
        :type message: (BTMesh_Upper_Transport_Access_PDU, MeshMessageContext)
        """
        self.send("lower_transport", message)

    def send_to_access_layer(self, message):
        """
        Sends the decrypted Access PDU to the Access Layer with its context

        :param message: The PDU and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
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
        pkt, ctx = message

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
            return

        plaintext = self.__try_decrypt(pkt, ctx)

        if plaintext is None:
            logger.debug("Decryption failed in UpperTransportlayer")
            return

        pkt = BTMesh_Model_Message(plaintext)
        self.send_to_access_layer((pkt, ctx))

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
            ctx.src_addr == self.state.profile.primary_element_addr.to_bytes(2, "big")
            or ctx.seq_number is None
        ):
            ctx.seq_number = self.state.profile.get_next_seq_number(inc=5)
        if isinstance(pkt, BTMesh_Upper_Transport_Control_Path_Request):
            pkt.path_origin_forwarding_number = (
                self.state.profile.get_next_forwarding_number()
            )
        self.send_to_lower_transport((pkt, ctx))

    def register_callback_ctl_message(self, clazz, callback):
        """
        Registers a callback for a type of ctl packet on reception.
        Callback should be declared in the Connector

        :param clazz: The packet class
        :type clazz: [TODO:type]
        :param callback: The callback to call with message as argument
        :type callback: [TODO:type]
        """
        self._handlers[clazz] = callback


UpperTransportLayer.add(AccessLayer)
