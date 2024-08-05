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

    def synchronize(self, timeout=10):
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
    def send_data(self, data, waiting_ack=False):
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
'''
class EsbLinkLayerManager:
    """
    This class handles the Enhanced ShockBurst Link Layer.
    It handles all the low-level operations, e.g., packet transmission, reception, synchronization and acknowledgements,
    for both roles supported by the Enhanced ShockBurst protocol:
        - Primary Transmitter (PTX): node able to transmit data at any time
        - Primary Receiver (PRX): node able to receive data at any time and acknowledge it
    """
    def __init__(self, stack, app_class = None):
        self.__stack = stack
        self.__app = app_class(self) if app_class is not None else None
        self.__pid = 0
        self.__last_timestamp = time()
        self.__role = ESBRole.PTX
        self.__synchronized = False
        self.__promiscuous = False
        self.__ack_queue = Queue()
        self.__data_queue = Queue()
        self.__ackmiss = 0

    @property
    def channel(self):
        return self.__stack.channel

    @channel.setter
    def channel(self, channel):
        self.__stack.channel = channel

    @property
    def address(self):
        return self.__stack.address

    @address.setter
    def address(self, address):
        self.__stack.address = address

    @property
    def app(self):
        return self.__app

    @property
    def promiscuous(self):
        return self.__promiscuous

    @promiscuous.setter
    def promiscuous(self, promiscuous):
        self.__promiscuous = promiscuous

    @property
    def synchronized(self):
        return self.__synchronized

    @property
    def role(self):
        return self.__role

    @role.setter
    def role(self, role):
        self.__role = role

    def _increment_pid(self):
        self.__pid = (self.__pid + 1) % 4

    def synchronize(self, timeout=10):
        self.__role = ESBRole.PTX
        self.channel = None
        start_time = time()
        self.__ack_queue.queue.clear()
        self.__data_queue.queue.clear()
        self.__promiscuous = True
        queue = self.__ack_queue
        while (time() - start_time) < timeout:
            try:
                queue = self.__ack_queue if queue == self.__data_queue else self.__data_queue
                msg = queue.get(block=False,timeout=0.05)
                if hasattr(msg, "metadata") and hasattr(msg.metadata, "channel"):
                    self.channel = msg.metadata.channel
                    if not self.__synchronized:
                        self.__synchronized = True
                        self.on_synchronized()
                    break
            except Empty:
                pass
        self.__promiscuous = False
        return self.__synchronized

    def send_data(self, data, waiting_ack=False):
        self.__role = ESBRole.PTX
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__stack.address,
                no_ack=0
        ) / ESB_Payload_Hdr() / data

        self.__stack.send(packet, channel=self.__stack.channel)
        self._increment_pid()
        if waiting_ack:
            try:
                ack = self.wait_for_ack()
                self.__ackmiss = 0
                self.__synchronized = True
                return ack
            except LinkLayerTimeoutException:
                self.__ackmiss += 1
                if self.__ackmiss > 10:
                    self.__ackmiss = 0
                    if self.__synchronized:
                        self.__synchronized = False
                        self.on_desynchronized()
                return None

    def wait_for_ack(self, timeout=0.1):
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def wait_for_data(self, timeout=0.1):
        self.__role = ESBRole.PRX
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__data_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def data_stream(self):
        self.__role = ESBRole.PRX
        while True:
            yield self.__data_queue.get(block=True)

    def prepare_acknowledgment(self, data):
        self.__role = ESBRole.PRX
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__stack.address,
                no_ack=True
        ) / ESB_Payload_Hdr() / data
        self.__stack.send(packet)

    def on_synchronized(self):
        if self.__app is not None:
            self.__app.on_synchronized()

    def on_desynchronized(self):
        if self.__app is not None:
            self.__app.on_desynchronized()

    def on_prx_pdu(self, pdu):
        if (self.__role == ESBRole.PTX or self.__promiscuous):
            self.__ack_queue.put(pdu)

            if self.__app is not None and len(bytes(pdu)) > 0:
                self.__app.on_acknowledgement(pdu[ESB_Payload_Hdr:])

    def on_ptx_pdu(self, pdu):
        if (self.__role == ESBRole.PRX or self.__promiscuous):

            self.__data_queue.put(pdu)

            if self.__app is not None:
                self.__app.on_data(pdu[ESB_Payload_Hdr:])


    def on_pdu(self, pdu):
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            self.on_prx_pdu(pdu)
        else:
            self.on_ptx_pdu(pdu)
'''
