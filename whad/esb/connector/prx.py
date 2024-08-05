"""
This module provides a ::class:`whad.esb.connector.prx.PRX` connector that
implements Nordic Semiconductor's *Primary Receiver* role.

The *primary receiver* (*PRX*) role consists in receiving packets from other devices
and sending acknowledgements if required to the sending device. When a device
is in *PRX* mode, it is only capable of receiving ESB packets on a specific
channel, including *ESB pings*.

The :class:`whad.esb.connector.prx.PRX` class relies on a custom protocol stack
to handle acknowledgements and pings automatically.
"""
from typing import Generator
from scapy.packet import Packet
from whad.esb.connector import ESB
from whad.esb.stack import ESBStack
from whad.exceptions import UnsupportedCapability


class PRX(ESB):
    """
    Enhanced ShockBurst Primary Receiver Role (PRX) implementation for compatible WHAD device.
    """
    def __init__(self, device):
        """Instantiate a new Primary Receiver connector.

        :param device: ESB-compatible device
        :type device: :class:`whad.device.WhadDevice`
        """
        super().__init__(device)

        # Check if device can modify its address and enter the PRX role
        self.__stack = ESBStack(self)
        self.__channel = 8
        self.__address = "11:22:33:44:55"

        self.__started = False

        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        if not self.can_be_prx():
            raise UnsupportedCapability("PrimaryReceiverMode")
        self._enable_role()

    def _enable_role(self):
        """Enable PRX role.
        """
        self.set_node_address(self.__address)
        self.enable_prx_mode(self.__channel)
        if self.__started:
            self.start()

    @property
    def stack(self) -> ESBStack:
        """Return current ESB stack instance.

        :return: Current ESB stack instance
        :rtype: :class:`whad.esb.stack.ESBStack`
        """
        return self.__stack

    @property
    def channel(self) -> int:
        """Return current channel.

        :return: current channel number
        :rtype: int
        """
        return self.__channel

    @channel.setter
    def channel(self, channel: int):
        """Set channel.

        :param channel: Channel to set
        :type channel: int
        """
        self.stop()
        self.__channel = channel
        self._enable_role()

    @property
    def address(self) -> str:
        """Return current address

        :return: ESB address
        :rtype: str
        """
        return self.__address

    @address.setter
    def address(self, address: str):
        """Set ESB address

        :param address: ESB address to set
        :type address: str
        """
        self.stop()
        self.__address = address
        self._enable_role()

    def start(self):
        """Start PRX mode.
        """
        super().start()
        self.__started = True

    def stop(self):
        """Stop PRX mode.
        """
        super().stop()
        self.__started = False

    def prepare_acknowledgment(self, ack: bytes):
        """Prepare and send acknowledgement packet

        :param ack: Acknowledgement packet to prepare
        :type ack: bytes
        """
        self.__stack.ll.prepare_acknowledgment(ack)

    def on_pdu(self, packet: Packet):
        """ESB packet reception callback

        :param packet: ESB packet received
        :type packet: :class:`scapy.packet.Packet`
        """
        self.__stack.on_pdu(packet)

    def stream(self) -> Generator[Packet, None, None]:
        """Stream received ESB packets
        """
        for pdu in self.__stack.ll.data_stream():
            yield pdu
