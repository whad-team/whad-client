"""
WHAD default bridge module.

This module provides multiple classes to implement a transparent bridge between
two connectors.
"""
import logging
from whad.device.connector import WhadDeviceConnector
from whad.hub.message import AbstractPacket

logger = logging.getLogger(__name__)

class BridgeIfaceWrapper(WhadDeviceConnector):
    """Interface bridging wrapper used by our default `Bridge` class
    to wrap an existing and initialized WHAD device.
    """

    def __init__(self, device, processor):
        super().__init__(device)
        self.__processor = processor

    def send_message(self, message, filter=None):
        logger.debug("[PacketProcIfaceWrapper] send_message: %s", message)
        super().send_message(message, filter=filter)

    def on_disconnection(self):
        """Notify bridge on disconnection.
        """
        logger.debug("[PacketProcIfaceWrapper] on_disconnection")
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
        # Save our input connector and its device
        self.__in = input_connector
        self.__in_device = self.__in.device

        # Save our output cnnector and its device
        self.__out = output_connector
        self.__out_device =self.__out.device

        # Disable message queue filters
        self.__in_device.set_queue_filter(None)
        self.__out_device.set_queue_filter(None)

        # Bridge our two interfaces with our own connectors.
        # This will replace each device connector with our own and avoid
        # any other packet processing.
        self.__in_wrapper = BridgeIfaceWrapper(self.__in_device, self)
        self.__out_wrapper = BridgeIfaceWrapper(self.__out_device, self)

    def detach(self):
        """Detach BridgeIfaceWrappers from bridge's devices.
        """
        self.__in_device.set_connector(self.__in)
        self.__out_device.set_connector(self.__out)


    @property
    def input(self) -> WhadDeviceConnector:
        """Get the input connector

        :return: Input connector
        :rtype: WhadDeviceConnector
        """
        return self.__in

    @property
    def output(self) -> WhadDeviceConnector:
        """Get the output connector

        :return: Output connector
        :rtype: WhadDeviceConnector
        """
        return self.__out

    @property
    def input_wrapper(self) -> WhadDeviceConnector:
        """Get the internal connector for input
        """
        return self.__in_wrapper
    
    @property
    def output_wrapper(self) -> WhadDeviceConnector:
        """Get the internal connector for output
        """
        return self.__out_wrapper

    def on_disconnect(self, wrapper):
        """When a wrapper disconnects, stop bridge.
        """

    def on_any_msg(self, wrapper, message):
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

    def on_inbound(self, message):
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
                self.__in.monitor_packet_rx(packet)
                self.__out.monitor_packet_tx(packet)

            # Forward message
            self.__in.send_message(message)

    def on_outbound(self, message):
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
                self.__out.monitor_packet_tx(packet)
                self.__in.monitor_packet_rx(packet)

            self.__out.send_message(message)
