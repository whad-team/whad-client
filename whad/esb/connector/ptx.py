"""
This module provides the :class:`whad.esb.connector.ptx.PTX` connector class
that implements Nordic Semiconductor's *Enhanced ShockBurst* *Primary transmitter*
role.

The *primary transmitter* (*PTX*) role consists in sending packets to another
*Enhanced ShockBurst* device in *primary receiver* (*PRX*) role and determine
if they have correctly been received. Correct packet reception is checked through
*acknowledgements* packets sent by the device in *PRX* mode, if required by
the device in *PTX* mode.

The :class:`whad.esb.connector.ptx.PTX` connector embeds a custom stack to
provide this behaviour and exposes some methods to send data. 
"""
from scapy.packet import Packet
from whad.device import WhadDevice
from whad.esb.connector import ESB
from whad.esb.stack import ESBStack
from whad.exceptions import UnsupportedCapability

class PTX(ESB):
    """
    Enhanced ShockBurst Primary Transmitter Role (PTX) implementation for compatible WHAD device.
    """
    def __init__(self, device: WhadDevice):
        """
        """
        super().__init__(device)

        # Check if device can modify its address and enter the PRX role
        self.__stack = ESBStack(self)
        self.__channel = 8
        self.__address = "11:22:33:44:55"

        self.__started = False
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        if not self.can_be_ptx():
            raise UnsupportedCapability("PrimaryTransmitterMode")
        self._enable_role()

    def _enable_role(self):
        self.set_node_address(self.__address)
        self.enable_ptx_mode(self.__channel)
        if self.__started:
            self.start()

    @property
    def stack(self) -> ESBStack:
        """Return the current ESB stack instance.
        """
        return self.__stack

    @property
    def channel(self) -> int:
        """Channel getter.

        :return: current channel
        :rtype: int
        """
        return self.__channel

    @channel.setter
    def channel(self, channel: int):
        """Change channel to `channel`.

        :param channel: New channel to use.
        :type channel: int
        """
        self.stop()
        self.__channel = channel
        self._enable_role()

    @property
    def address(self):
        """Return current address.

        :return: Current target address
        :rtype: str
        """
        return self.__address

    @address.setter
    def address(self, address: str):
        """Set target ESB address.

        :param address: Target ESB address
        :type address: str
        """
        self.stop()
        self.__address = address
        self._enable_role()

    def start(self):
        """Start PTX mode. A call to this method is required before calling
        :func:`send_data`.
        """
        super().start()
        self.__started = True

    def stop(self):
        """Stop PTX mode.
        """
        super().stop()
        self.__started = False

    def on_pdu(self, packet: Packet):
        """ESB packet callback.

        This function feeds the stack with the received packet.

        :param packet: Received ESB packet
        :type packet: :class:`scapy.packet.Packet`
        """
        self.__stack.on_pdu(packet)

    def send_data(self, data: bytes, waiting_ack: bool = False) -> bool:
        """Send an ESB payload.

        :param data: Data/payload to send
        :type data: bytes
        :param waiting_ack: If set to True, will wait for the acknowledgement
                            packet to be received
        :type waiting_ack: bool, optional
        :return: True if the packet has been correctly sent, False otherwise
        :rtype: bool
        """
        return self.__stack.ll.send_data(data, waiting_ack=waiting_ack)

    def synchronize(self, timeout: float = 10.0) -> bool:
        """Synchronize with the target ESB device.

        :param timeout: Timeout in seconds
        :type timeout: float
        :return: `True` if synchronization succeeded, `False` otherwise
        :rtype: bool
        """
        return self.__stack.ll.synchronize(timeout=timeout)
