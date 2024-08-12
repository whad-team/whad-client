from whad.esb.stack.llm.exceptions import LinkLayerTimeoutException
from whad.esb.stack.llm.constants import ESBRole
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response
from whad.common.stack import Layer, alias, source, state, LayerState, instance
from queue import Queue, Empty
from time import sleep, time

import logging
logger = logging.getLogger(__name__)

class LinkLayerState(LayerState):

    def __init__(self):
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
    def configure(self, options={}):
        self.__ack_queue = Queue()
        self.__data_queue = Queue()

    @property
    def channel(self):
        return self.get_layer('phy').channel

    @channel.setter
    def channel(self, channel):
        self.get_layer('phy').channel = channel

    @property
    def address(self):
        return self.get_layer('phy').address

    @address.setter
    def address(self, address):
        self.get_layer('phy').address = address

    @property
    def app(self):
        return self.get_layer('app')

    @property
    def promiscuous(self):
        return self.state.promiscuous

    @promiscuous.setter
    def promiscuous(self, promiscuous):
        self.state.promiscuous = promiscuous

    @property
    def synchronized(self):
        return self.state.synchronized

    @property
    def role(self):
        return self.state.role

    @role.setter
    def role(self, role):
        self.state.role = role

    def _increment_pid(self):
        self.state.pid = (self.state.pid + 1) % 4

    def synchronize(self, timeout: float = 10.0):
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
    def send_data(self, data: bytes, waiting_ack: bool = False):
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
                return None

    def wait_for_ack(self, timeout=0.1):
        self.state.role = ESBRole.PTX
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def wait_for_data(self, timeout=0.1):
        self.state.role = ESBRole.PRX
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__data_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def data_stream(self):
        self.state.role = ESBRole.PRX
        while True:
            yield self.__data_queue.get(block=True)

    @source('app', 'ack')
    def prepare_acknowledgment(self, data):
        self.state.role = ESBRole.PRX
        packet = ESB_Hdr(
                pid=self.state.pid,
                address=self.get_layer('phy').address,
                no_ack=True
        ) / ESB_Payload_Hdr() / data
        self.send('phy', packet)

    def on_synchronized(self):
        if self.get_layer('app') is not None:
            self.send('app', time(), tag='synchronized')

    def on_desynchronized(self):
        if self.get_layer('app') is not None:
            self.send('app', time(), tag='desynchronized')


    def on_prx_pdu(self, pdu):
        if (self.state.role == ESBRole.PTX or self.state.promiscuous):
            self.__ack_queue.put(pdu)

            if self.get_layer('app') is not None and len(bytes(pdu)) > 0:
                self.send('app', pdu[ESB_Payload_Hdr:], tag='ack')

    def on_ptx_pdu(self, pdu):
        if (self.state.role == ESBRole.PRX or self.state.promiscuous):

            self.__data_queue.put(pdu)

            if self.get_layer('app') is not None:
                self.send('app', pdu[ESB_Payload_Hdr:], tag='data')

    @source('phy')
    def on_pdu(self, pdu):
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            self.on_prx_pdu(pdu)
        else:
            self.on_ptx_pdu(pdu)
