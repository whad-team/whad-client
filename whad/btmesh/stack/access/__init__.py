"""
Accces Layer

Manages which Element, Model gets a Message and forwards it to the Model handler.
Manages checks on whether or not the conditions of a message to a Model in an Element are ok (which key is used, addr...)
Allows other layers to internally fetch State data from Foundation Models (SAR informations, keys, ...)
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.btmesh.stack.utils import (
    MeshMessageContext,
    get_address_type,
    UNICAST_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    VIRTUAL_ADDR_TYPE,
)
from queue import Queue
from threading import Event
from whad.scapy.layers.btmesh import (
    BTMesh_Model_Generic_OnOff_Set,
    BTMesh_Model_Message,
)

from whad.btmesh.models import ModelServer


logger = logging.getLogger(__name__)


@alias("access")
class AccessLayer(Layer):
    def configure(self, options={}):
        """
        AccessLayer. One for all the networks.
        """
        super().configure(options=options)

        # Rx message queue from UpperTransportLayer
        self.__queue = Queue()

        # Set to True when a handler for an Access Message is executed
        self.state.__is_processing_message = False

        # Custom handlers for specific packets (will skip the elements)
        self._custom_handlers = {}

        self.state.profile = options["profile"]

        # When waiting for a specific message, class we are waiting for, and the event object to notify the thread
        # The received_message containes the context and message received.
        self.state.expected_class = None
        self.state.event = Event()
        self.state.received_message = None

        # For onoff messages (testing), transaction_id
        self.transaction_id = 0

    def check_queue(self):
        """
        If the queue is not empty, process the next Access Message
        """
        if not self.__queue.empty():
            self.process_access_message(self.__queue.get_nowait())

    @source("upper_transport")
    def on_access_message(self, message):
        """
        Handler when Access Message is received from network

        :param message: Message Received with its context
        :type message: (Packet,MeshMessageContext)
        """
        self.__queue.put_nowait(message)
        if not self.state.__is_processing_message:
            self.check_queue()

    def send_to_upper_transport(self, message):
        """
        Sends a message and its context to the upper transport layer to send on the network

        :param message: Message and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        self.send("upper_transport", message)

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

    def process_access_message(self, message):
        """
        Function used to process an Access Message received from the network

        :param message: Message received with context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        packet, ctx = message
        dst_addr = ctx.dest_addr

        packet.show()
        # If waiting for a particular message, check and set event if needed
        if self.state.expected_class is not None:
            if type(packet[1]) is self.state.expected_class:
                self.state.expected_class = None
                self.state.received_message = (packet[1], ctx)
                self.state.event.set()
            return

        if type(packet[1]) in self._custom_handlers:
            self._custom_handlers[type(packet[1])](message)
            return

        # Elements that will process the message
        target_elements = []

        dst_addr_type = get_address_type(dst_addr)

        # if all nodes address, send to all elements
        if dst_addr == 0xFFFF:
            target_elements = self.state.profile.get_all_elements()

        # if dst addr is unicast, only need to use the relevent element
        elif dst_addr_type == UNICAST_ADDR_TYPE:
            # Convert addr to offset from primary addr
            element_index = dst_addr - self.state.profile.get_primary_element_addr()

            target_elements.append(
                self.state.profile.local_node.get_element(element_index)
            )

        # Check which element have a model that subscribed to this address
        elif dst_addr_type == GROUP_ADDR_TYPE:
            for e in self.state.profile.local_node.get_all_elements():
                if e.check_group_subscription(dst_addr):
                    target_elements.append(e)

        elif dst_addr_type == VIRTUAL_ADDR_TYPE:
            for e in self.state.profile.local_node.get_all_elements():
                if e.check_virtual_subscription(dst_addr):
                    target_elements.append(e)

        # for all the element that are supposed to receive the message, check it and process it if ok
        for e in target_elements:
            if e is None:
                continue

            # get model that will handle the message
            model = e.get_model_for_opcode(packet.opcode)
            if model is None:
                continue

            # if dev key is used, check if the model allows the dev_key used
            if ctx.application_key_index == -1:
                # If dev_key not allowed, skip model
                if not model.allows_dev_keys:
                    continue
                # if model is Server, only our own dev_key can be used, otherwise skip
                elif (
                    isinstance(model, ModelServer)
                    and ctx.dev_key_address
                    != self.state.profile.get_primary_element_addr()
                ):
                    continue

            else:
                # check if app_key used is bound to the model
                app_key_indexes = (
                    self.state.profile.get_configuration_server_model()
                    .get_state("model_to_app_key_list")
                    .get_value(model.model_id)
                )

                if ctx.application_key_index not in app_key_indexes:
                    continue

            response = model.handle_message(message)

            # only send responses if unicast addr for destination
            if dst_addr_type == UNICAST_ADDR_TYPE and response is not None:
                new_ctx = MeshMessageContext()
                new_ctx.aid = ctx.aid
                new_ctx.application_key_index = ctx.application_key_index
                new_ctx.dev_key_address = ctx.dev_key_address
                new_ctx.src_addr = (
                    e.index + self.state.profile.get_primary_element_addr()
                )
                new_ctx.dest_addr = ctx.src_addr
                new_ctx.net_key_id = ctx.net_key_id
                new_ctx.is_ctl = False
                new_ctx.azsmic = 0
                if ctx.ttl == 0:
                    new_ctx.ttl = 0
                else:
                    new_ctx.ttl = (
                        self.state.profile.get_configuration_server_model()
                        .get_state("default_ttl")
                        .get_value()
                    )
                self.send_to_upper_transport((response, new_ctx))

    def process_new_message(self, message):
        """
        Process a message originating from us directly (not in response from another message, usually a message from a ModelClient/Shell)

        :param message: Packet and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        ctx.is_ctl = False
        ctx.azsmic = 0
        self.send_to_upper_transport(message)

    def do_onoff(self, value, ctx, tid):
        """
        Sends a Generic On/Off set message (acked or unacked)

        :param value: Value to be set (0 or 1)
        :type value: int
        :param ctx: Context of the message
        :type ctx: MeshMessageContext
        :param tid: Transaction Id
        :type tid: int
        """
        if tid is None:
            tid = self.transaction_id
            self.transaction_id = (self.transaction_id + 1) % 256

        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=value, transaction_id=tid)

        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
