"""
WHAD Enhanced ShockBurst Stack - Link-layer management

This module provides the ESB stack Link-layer management class
`LinkLayer`. This class uses its own associated state class
`LinkLayerState`.
"""
import logging
from queue import Queue, Empty
from time import sleep, time
from typing import Optional, Generator

from scapy.packet import Packet

from whad.esb.stack.llm.exceptions import LinkLayerTimeoutException
from whad.esb.stack.llm.constants import ESBRole
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response
from whad.common.stack import Layer, alias, source, state, LayerState, instance

logger = logging.getLogger(__name__)

class LinkLayerState(LayerState):
    """ESB Link-layer state class.

    This class stores the link-layer state.
    """

    def __init__(self):
        """Initialization of link-layer state.
        """
        super().__init__()

        self.pid = 0
        self.role = ESBRole.PTX

        self.synchronized = False
        self.promiscuous = False

        self.last_timestamp = time()

        self.ack_miss = 0


@alias('ll')
@state(LinkLayerState)
class LinkLayer(Layer):
    """ESB Link-layer management class.

    This class manages a single ESB connection and its state,
    as well as promiscuous mode.
    """

    def configure(self, options: Optional[dict] = None):
        """Configure this ESB link-layer instance.

        This method is called by the underlying layer management
        system to configure this layer.

        :param options: Layer options
        :type options: dict, optional
        """
        self.__ack_queue = Queue()
        self.__data_queue = Queue()

    @property
    def channel(self) -> int:
        """Return the current channel number

        :return: Current channel number
        :rtype: int
        """
        return self.get_layer('phy').channel

    @channel.setter
    def channel(self, channel: int):
        """Set the current channel number

        :param channel: New channel number to use
        :type channel: int
        """
        self.get_layer('phy').channel = channel

    @property
    def address(self) -> str:
        """Return the current ESB address.

        :return: Current ESB address
        :rtype: str
        """
        return self.get_layer('phy').address

    @address.setter
    def address(self, address: str):
        """Set ESB address

        :param address: New ESB address to use
        :type address: str
        """
        self.get_layer('phy').address = address

    @property
    def app(self):
        """Return the associated application layer instance

        :return: Associated application layer instance
        :rtype: Layer
        """
        return self.get_layer('app')

    @property
    def promiscuous(self) -> bool:
        """Determine if promiscuous mode is enabled or not

        :return: Promiscuous mode state
        :rtype: bool
        """
        return self.state.promiscuous

    @promiscuous.setter
    def promiscuous(self, promiscuous: bool):
        """Enable or disable promiscuous mode.

        :param promiscuous: Set to `True` to enable promiscuous mode,
                            `False` to disable.
        :type promiscuous: bool
        """
        self.state.promiscuous = promiscuous

    @property
    def synchronized(self) -> bool:
        """Determine if connection is synchronized or not.

        :return: Synchronization state
        :rtype: bool
        """
        return self.state.synchronized

    @property
    def role(self) -> int:
        """Get the current role.

        :return: Current role as defined in `ESBRole` constants.
        :rtype: int
        """
        return self.state.role

    @role.setter
    def role(self, role: int):
        """Set current role.

        :param role: New role
        :type role: int
        """
        self.state.role = role

    def _increment_pid(self):
        """Increment PID.
        """
        self.state.pid = (self.state.pid + 1) % 4

    def synchronize(self, timeout: float = 10.0):
        """Synchronize with current connection.

        :param timeout: Synchronization timeout
        :type timeout: float
        """
        self.state.role = ESBRole.PTX
        self.channel = None
        start_time = time()
        self.__ack_queue.queue.clear()
        self.__data_queue.queue.clear()
        self.state.promiscuous = True
        queue = self.__ack_queue
        while (time() - start_time) < timeout:
            try:
                queue = self.__ack_queue if queue == self.__data_queue else self.__data_queue
                msg = queue.get(block=False,timeout=0.05)

                if hasattr(msg, "metadata") and hasattr(msg.metadata, "channel"):
                    self.channel = msg.metadata.channel

                    if not self.state.synchronized:
                        self.state.synchronized = True
                        self.on_synchronized()
                    break
            except Empty:
                pass
        self.state.promiscuous = False
        return self.state.synchronized

    @source('app', 'data')
    def send_data(self, data: bytes, waiting_ack: Optional[bool] = False):
        """Send data to current connection.

        :param data: Data to send
        :type data: bytes
        :param waiting_ack: Set to `True` to wait for the remote device's
                            acknowledgement, `False` to skip.
        :type waiting_ack: bool, optional
        """
        self.state.role = ESBRole.PTX
        packet = ESB_Hdr(
                pid=self.state.pid,
                address=self.get_layer('phy').address,
                no_ack=0
        ) / ESB_Payload_Hdr() / data

        self.send('phy', packet, channel=self.get_layer('phy').channel)
        self._increment_pid()
        if waiting_ack:
            try:
                ack = self.wait_for_ack()
                self.state.ack_miss = 0
                self.state.synchronized = True
                return ack
            except LinkLayerTimeoutException:
                self.state.ack_miss += 1
                if self.state.ack_miss > 10:
                    self.state.ack_miss = 0
                    if self.state.synchronized:
                        self.state.synchronized = False
                        self.on_desynchronized()
        # No ack received
        return None

    def wait_for_ack(self, timeout: Optional[float] = 0.1):
        """Wait for an acknowledgement from remote device.

        :param timeout: Waiting timeout
        :type timeout: float, optional
        :raises: LinkLayerTimeoutException
        """
        self.state.role = ESBRole.PTX
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def wait_for_data(self, timeout: Optional[float] = 0.1):
        """Wait for incoming data packet.

        :param timeout: Waiting timeout
        :type timeout: float, optional
        :raises: LinkLayerTimeoutException
        """
        self.state.role = ESBRole.PRX
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__data_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def data_stream(self) -> Generator[Packet, None, None]:
        """Generator that yields received data packets as they
        come.
        """
        self.state.role = ESBRole.PRX
        while True:
            yield self.__data_queue.get(block=True)

    @source('app', 'ack')
    def prepare_acknowledgment(self, data: bytes):
        """Send an acknowledgement for a given packet.

        :param data: Packet to acknowledge
        :type data: bytes
        """
        self.state.role = ESBRole.PRX
        packet = ESB_Hdr(
                pid=self.state.pid,
                address=self.get_layer('phy').address,
                no_ack=True
        ) / ESB_Payload_Hdr() / data
        self.send('phy', packet)

    def on_synchronized(self):
        """Synchronization callback that is called each time
        the stack has synchronized with the remote device.
        """
        if self.get_layer('app') is not None:
            self.send('app', time(), tag='synchronized')

    def on_desynchronized(self):
        """Desynchronization callback that is called each time
        the stack has desynchronized from the remote device.
        """
        if self.get_layer('app') is not None:
            self.send('app', time(), tag='desynchronized')


    def on_prx_pdu(self, pdu: Packet):
        """PRX packet reception callback.

        :param pdu: Packet received
        :type pdu: Packet
        """
        if (self.state.role == ESBRole.PTX or self.state.promiscuous):
            self.__ack_queue.put(pdu)

            if self.get_layer('app') is not None and len(bytes(pdu)) > 0:
                self.send('app', pdu[ESB_Payload_Hdr:], tag='ack')

    def on_ptx_pdu(self, pdu: Packet):
        """PTX packet reception callback.

        :param pdu: Packet transmitted
        :type pdu: Packet
        """
        if (self.state.role == ESBRole.PRX or self.state.promiscuous):

            self.__data_queue.put(pdu)

            if self.get_layer('app') is not None:
                self.send('app', pdu[ESB_Payload_Hdr:], tag='data')

    @source('phy')
    def on_pdu(self, pdu):
        """Packet reception callback.

        This callback dispatches the received packets to
        correct callbacks depending on the current mode.
        """
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            self.on_prx_pdu(pdu)
        else:
            self.on_ptx_pdu(pdu)
