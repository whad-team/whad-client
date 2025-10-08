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
from threading import Thread


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

        # Set to True when a handler for an Access Message is executed (from upper transport)
        self.state.__is_processing_message = False

        # If this layer is not active, ignore all messages comming in.
        self.state.is_layer_active = True

        # Custom handler for packets received from parent layer
        # Should take the message as argument (with context)
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

        self.state.profile = options["profile"]

        # When waiting for a specific message, class we are waiting for, and the event object to notify the thread
        # The received_message containes the context and message received.
        self.state.expected_class = None
        self.state.event = Event()
        self.state.received_message = None

        # For onoff messages (testing), transaction_id
        self.transaction_id = 0

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Access Message with class (Scapy packet) specified

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking (Packet | MeshMessageContext) as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_handler(self, clazz):
        """
        Unregisters a previously registerd custom callback for an Access message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def check_queue(self):
        """
        If the queue is not empty, process the next Access Message received from upper transport layer
        """
        if not self.__queue.empty():
            try:
                thread = Thread(
                    target=self.process_access_message,
                    args=(self.__queue.get_nowait(),),
                )
                thread.start()
            except Exception:
                return

    def set_layer_active(self):
        """
        Activate the layer to receive and process messages.
        """
        self.state.is_layer_active = True

    def set_layer_active(self):
        """
        Activate the layer to receive and process messages.
        """
        self.state.is_layer_active = False

    @source("upper_transport")
    def on_access_message(self, message):
        """
        Handler when Access Message is received from network

        :param message: Message Received with its context
        :type message: (Packet,MeshMessageContext)
        """
        if not self.state.is_layer_active:
            return

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
        self.state.__is_processing_message = True
        packet, ctx = message

        if not self.state.is_layer_active:
            self.state.__is_processing_message = False
            return

        # if custom handler, use it
        if type(packet) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(packet)](message)
            # if custom handler says to return after itself
            if not continue_processing:
                self.state.__is_processing_message = False
                return

        # If waiting for a particular message, check and set event if needed
        if self.state.expected_class is not None:
            if type(packet[1]) is self.state.expected_class:
                self.state.expected_class = None
                self.state.received_message = (packet[1], ctx)
                self.state.event.set()

            self.state.__is_processing_message = False
            return

            # Elements that will process the message
        target_elements = []

        dst_addr = ctx.dest_addr
        dst_addr_type = get_address_type(dst_addr)

        # if all nodes address, send to all elements
        if dst_addr == 0xFFFF:
            target_elements = self.state.profile.local_node.get_all_elements()

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

                if (
                    app_key_indexes is not None
                    and ctx.application_key_index not in app_key_indexes
                ):
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
                new_ctx.aszmic = 0
                new_ctx.ttl = ctx.ttl
                self.send_to_upper_transport((response, new_ctx))

        self.state.__is_processing_message = False

    def send_access_message(
        self, model, message, is_acked=False, expected_response_clazz=None, timeout=3
    ):
        """
        Sends a message from the model (client) specified.
        The message should be a valid message sent by the model specified (no BTMesh_Model_Message layer needed !)

        Handlers to send these messages are defined in the `handler` object of the ModelClient object.
        If is_acked is True, message is expecting a Status response before Timeout.

        Blocking function for timeout time maximum.

        :param model: The model to send the message from. If Acked message, will handle the response and return relevant information (based on handler implementation).
        :type model: ModelClient
        :param message: The Model message to send. Context can be None or non existant, use of default values.
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        :param is_acked: Is the message acked, defaults to False
        :type is_acked: bool, optional
        :param expected_response_clazz: Expected class of the response if acked. Should be a valid message listed in hanlders of model. If not specified, first valid message received in model processed, defaults to None
        :param expected_response_clazz: Any
        :param timeout: Timeout delay before if message is acked and no response received (in sec), defaults to 3
        :type timeout: int, optional
        :returns: If unacked message, None. If acked, returns the status packet (or custom return in Model has specific implementation) or None
        :rtype: Any
        """
        # Send the message
        pkt, ctx = message
        ctx.is_ctl = False
        ctx.aszmic = 0

        # Setup the model to send the message (may modify the message, and sets the expected response if any)
        model.expected_response_clazz = expected_response_clazz
        model.message_sending_setup(message)
        self.send_to_upper_transport(message)

        # Wait for response and return it
        response = None
        if is_acked:
            response = model.wait_response(timeout)
        return response

    def send_direct_message(self, message):
        """
        Process a message originating from us directly (not in response from another message, usually a message from a ModelClient/Shell)
        Only used when sending a raw message from CLI command "senda_raw_access")

        :param message: Packet and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        ctx.is_ctl = False
        ctx.azsmic = 0
        self.send_to_upper_transport(message)
