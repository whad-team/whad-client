"""
WHAD default bridge module.

This module provides multiple classes to implement a transparent bridge between
two connectors.
"""
import logging
from threading import Event

from whad.hub.message import AbstractPacket, HubMessage

from .connector import Connector

logger = logging.getLogger(__name__)

class BridgeIfaceWrapper(Connector):
    """Interface bridging wrapper used by our default `Bridge` class
    to wrap an existing and initialized WHAD device.
    """

    def __init__(self, device, processor):
        super().__init__(device)
        self.__processor = processor

    def send_message(self, message, keep=None):
        """Forward message to the underlying interface.
        """
        logger.debug("[PacketProcIfaceWrapper][%s] prepare callback for message %s",
                     self.device.interface, message)
        message.callback(self.on_message_sent)
        logger.debug("[PacketProcIfaceWrapper] send_message: %s", message)
        super().send_message(message, keep=keep)

    def on_message_sent(self, message, status):
        """Called when a message has been sent to the target interface.
        """
        if status == 0:
            self.__processor.on_message_sent(self, message)
        else:
            # TODO: implement or remove on_message_error()
            self.__processor.on_message_error(self, message, status)


    def on_disconnection(self):
        """Notify bridge on disconnection.
        """
        self.__processor.on_disconnect(self)

    def unlock(self, dispatch_callback=None):
        """Unlock connector and dispatch pending PDUs.

        :param  dispatch_callback: PDU dispatch callback that overrides the
                                   internal dispatch routine
        :type   dispatch_callback: callable
        """
        super().unlock(self.dispatch_locked_pdus)

    def dispatch_locked_pdus(self, pdu):
        """Process locked pdus.
        """
        # convert packet to message
        msg = self.hub.convert_packet(pdu)
        #logger.debug("[PacketProcIfaceWrapper] process locked pdu %s", msg)
        self.on_any_msg(msg)

    def on_any_msg(self, message):
        self.__processor.on_any_msg(self, message)

    def on_generic_msg(self, message):
        pass

    def on_discovery_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        pass

    def on_packet(self, packet):
        pass

    def on_event(self, event):
        pass


class Bridge:
    """WHAD default interface bridge.

    This class implements a bridge between two connectors that offers
    the possibility to filter ingress and egress packets. By default,
    every packet is forward from one interface to the other.
    """

    def __init__(self, input_connector, output_connector):
        """Initialize our packet processor.
        """
        # Stopped event
        self.__stopped = Event()

        # Save our input connector and its device
        self.__in = input_connector
        self.__in_device = self.__in.device
        self.__in_disconnected = False

        # Save our output cnnector and its device
        self.__out = output_connector
        self.__out_device =self.__out.device
        self.__out_disconnected = False

        # Disable message queue filters
        self.__in_device.set_queue_filter(None)
        self.__out_device.set_queue_filter(None)

        # Bridge our two interfaces with our own connectors.
        # This will replace each device connector with our own and avoid
        # any other packet processing.
        self.__in_wrapper = BridgeIfaceWrapper(self.__in_device, self)
        self.__out_wrapper = BridgeIfaceWrapper(self.__out_device, self)

        # Unlock connectors, if locked.
        self.unlock()

    def detach(self):
        """Detach BridgeIfaceWrappers from bridge's devices.
        """
        self.__in_device.set_connector(self.__in)
        self.__out_device.set_connector(self.__out)


    @property
    def input(self) -> Connector:
        """Get the input connector

        :return: Input connector
        :rtype: Connector
        """
        return self.__in

    @property
    def output(self) -> Connector:
        """Get the output connector

        :return: Output connector
        :rtype: Connector
        """
        return self.__out

    @property
    def input_wrapper(self) -> Connector:
        """Get the internal connector for input
        """
        return self.__in_wrapper
    
    @property
    def output_wrapper(self) -> Connector:
        """Get the internal connector for output
        """
        return self.__out_wrapper

    def on_message_sent(self, _, __):
        """Called whenever a wrapped interface has successfully sent a message
        to the hardware device.
        """

        # Is the output interface disconnected and input interface done ?
        if self.__out_disconnected and not self.__in_wrapper.busy():
            logger.debug("[bridge::msg_sent] We are done with packets !")
            # We are done processing packets, bridge stops.
            self.__stopped.set()

        # Is the input interface disconnected and output interface done ?
        elif self.__in_disconnected and not self.__out_wrapper.busy():
            logger.debug("[bridge::msg_sent] We are done with packets !")
            # We are done processing packets, bridge stops.
            self.__stopped.set()

    def on_disconnect(self, wrapper: BridgeIfaceWrapper):
        """When a wrapper disconnects, stop bridge.
        """
        if wrapper == self.__in_wrapper:
            # Input interface has disconnected, we won't receive messages from
            # this interface anymore. We still need to make sure the output
            # interface has processed and sent all the messages we sent to it
            # before closing the bridge.
            logger.debug("[bridge][%s] interface has just disconnected",
                         self.__in_device.interface)
            self.__in_disconnected = True

            # If the output wrapper is not busy, we are done processing packets.
            if not self.__out_wrapper.busy():
                logger.debug("[bridge] We are done with packets !")
                self.__stopped.set()

        elif wrapper == self.__out_wrapper:
            logger.debug("[bridge][%s] interface has just disconnected",
                self.__out_device.interface)
            self.__out_disconnected = True

            # If the input wrapper is not busy, we are done processing packets.
            if not self.__in_wrapper.busy():
                logger.debug("[bridge] We are done with packets !")
                self.__stopped.set()


    def on_any_msg(self, wrapper, message: HubMessage):
        """Callback method for any message.

        :param wrapper: Calling wrapper object
        :type wrapper: BridgeIfaceWrapper
        :param message: Incoming message
        :type message: HubMessage
        """
        logger.debug("bridge::on_any_msg - %s", message)
        if wrapper == self.__in_wrapper:
            self.on_outbound(message)
        elif wrapper == self.__out_wrapper:
            self.on_inbound(message)
        else:
            logger.error("on_any_msg() called by an unknown wrapper (%s)", wrapper)

    def on_inbound(self, message: HubMessage):
        """Inbound message hook

        This hook is called whenever a message is received on the input
        connector and about to be relayed to the output connector.

        :param message: Message to process
        :type message: HubMessage
        """
        if message is not None:
            # Monitor packet if required
            if issubclass(message, AbstractPacket):
                packet = message.to_packet()
                if packet is not None:
                    self.__in.monitor_packet_rx(packet)
                    self.__out.monitor_packet_tx(packet)

            # Forward message
            message.callback(self.on_message_sent)
            self.__in.send_message(message)

    def on_outbound(self, message: HubMessage):
        """Outbound message hook.

        This hook is called whenever a message is received on the output
        connector and about to be relayed to the input connector.

        :param message: Message to process
        :type message: HubMessage
        """
        if message is not None:
            # Monitor packet if required
            if issubclass(message, AbstractPacket):
                packet = message.to_packet()
                if packet is not None:
                    self.__out.monitor_packet_tx(packet)
                    self.__in.monitor_packet_rx(packet)

            message.callback(self.on_message_sent)
            self.__out.send_message(message)

    def unlock(self):
        """Unlock bridge's interfaces.
        """
        # Unlock connector, causing packets to be sent to the output connector
        if self.__in.is_locked():
            logger.debug("[bridge] %s is locked, unlocking it", self.__in.device.interface)
            self.__in.unlock(dispatch_callback=self.dispatch_pending_input)
        if self.__out.is_locked():
            logger.debug("[bridge] %s is locked, unlocking it", self.__out.device.interface)
            self.__out.unlock(dispatch_callback=self.dispatch_pending_output)

    def dispatch_pending_output(self, message: HubMessage):
        """Forward pending output messages to input.
        """
        packet = message.to_packet()
        if packet is not None:
            self.output.monitor_packet_rx(packet)
            self.input.monitor_packet_tx(packet)
        self.input.send_message(message)

    def dispatch_pending_input(self, message: HubMessage):
        """Forward pending input messages to output.
        """
        packet = message.to_packet()
        if packet is not None:
            self.output.monitor_packet_tx(packet)
            self.input.monitor_packet_rx(packet)
        self.output.send_message(message)

    def join(self):
        """Wait for bridge termination. Bridge termination is triggered when
        at least one of the bridge's interface is disconnected and every pending
        messages forwarded.
        """
        return self.__stopped.wait()
