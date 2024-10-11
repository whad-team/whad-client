"""
Accces Layer

Manages which Element, Model gets a Message and forwards it to the Model handler.
Manages checks on whether or not the conditions of a message to a Model in an Element are ok (which key is used, addr...)
Allows other layers to internally fetch State data from Foundation Models (SAR informations, keys, ...)
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.stack.utils import (
    MeshMessageContext,
    get_address_type,
    UNICAST_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    VIRTUAL_ADDR_TYPE,
)
from whad.bt_mesh.models import Element
from queue import Queue

from whad.bt_mesh.models import GlobalStatesManager


logger = logging.getLogger(__name__)


@alias("access")
class AccessLayer(Layer):
    def configure(self, options={}):
        """
        AccessLayer. One for all the networks.
        """
        super().configure(options=options)

        # List of elements of the Device. Addr -> element instance
        self.state.elements = {}

        # Rx message queue from UpperTransportLayer
        self.__queue = Queue()

        # Set to True when a handler for an Access Message is executed
        self.state.__is_processing_message = False

        self.state.global_states_manager = GlobalStatesManager()

    def check_queue(self):
        """
        If the queue is not empty, process the next Access Message
        """
        if not self.__queue.empty():
            self.process_access_message(self.__queue.get_nowait())

    def register_element(self, element):
        """
        Adds an element to the device

        :param element: Element to add
        :type element: Element
        """
        self.state.elements[element.addr] = element

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
        self.send("upper_transport", message)

    def process_access_message(self, message):
        """
        Function used to process an Access Message received from the network

        :param message: Message received with context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        packet, ctx = message
        dst_addr = ctx.dest_addr
        element = []

        dst_addr_type = get_address_type(dst_addr)
        print(self.state.elements)

        # if all nodes address, send to all elements
        if dst_addr == b"\xff\xff":
            element = self.state.elements.values()

        # if dst addr is unicast, only need to use the relevent element
        elif dst_addr_type == UNICAST_ADDR_TYPE:
            element.append(self.state.elements[dst_addr])
        # Check which element have a model that subscribed to this address
        elif dst_addr_type == GROUP_ADDR_TYPE:
            print("GROUP ADDR MESSAGE")
            print(dst_addr)
            for e in self.state.elements:
                if e.check_group_subscription(dst_addr):
                    element.append(e)
        elif dst_addr_type == VIRTUAL_ADDR_TYPE:
            for e in self.state.elements:
                if e.check_virtual_subscription(dst_addr):
                    element.append(e)

        # for all the element that are supposed to receive the message, handle it
        for e in element:
            response = e.handle_message(message)

            # only send responses if unicast addr for destination
            if dst_addr_type == UNICAST_ADDR_TYPE and response is not None:
                new_ctx = MeshMessageContext()
                new_ctx.aid = ctx.aid
                new_ctx.application_key_index = ctx.application_key_index
                new_ctx.src_addr = e.addr
                new_ctx.dest_addr = ctx.src_addr
                new_ctx.net_key_id = ctx.net_key_id
                new_ctx.is_ctl = False
                if ctx.ttl == 0:
                    new_ctx.ttl = 0
                else:
                    new_ctx.ttl = self.state.global_states_manager.get_state(
                        "default_ttl"
                    ).get_value()
                self.send_to_upper_transport((response, new_ctx))

    def process_new_message(self, message):
        """
        Process a message originating from us directly (not in response from another message, usually a message from a keypress and a ModelClient)

        :param message: [TODO:description]
        :type message: [TODO:type]
        """
        pkt, ctx = message
        ctx.is_ctl = False
        self.send_to_upper_transport(message)
