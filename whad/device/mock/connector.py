"""Mock for WHAD default connector.

This module provides a mock connector that implement every required method.
"""
from whad.hub.message import HubMessage

from ..connector import Connector
from ..device import Device

class MockConnector(Connector):

    def __init__(self, device: Device = None):
        super().__init__(device)
        self.__discovery = []
        self.__generic = []
        self.__domain = []
        self.__packets = []
        self.__events = []

    def on_discovery_msg(self, message: HubMessage):
        """Handle discovery messages.

        :param message: Discovery message
        :type message: HubMessage
        """
        self.__discovery.append(message)

    def on_generic_msg(self, message: HubMessage):
        """Handle generic messages.

        :param message: Generic message
        :type message: HubMessage
        """
        self.__generic.append(message)

    def on_domain_msg(self, message: HubMessage):
        """Handle domain messages.

        :param message: Domain message
        :type message: HubMessage
        """
        self.__domain.append(message)

    def on_packet(self, packet):
        """Default handler for received packet.

        :param packet: Received packet
        :type packet: Packet
        """
        self.__packets.append(packet)

    def on_event(self, event):
        """Default handler for received event.

        :param packet: Received event
        :type packet: Event
        """
        self.__events.append(event)

