from whad.esb.stack.llm.exceptions import LinkLayerTimeoutException
from whad.esb.stack.llm.constants import ESBRole
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Ping_Request
from queue import Queue, Empty
from time import sleep, time

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
        self.__ack_queue = Queue()
        self.__data_queue = Queue()
        self.__channels = list(range(101))

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
        start_time = time()
        self.__synchronized = False
        while (time() - start_time) < timeout:
            for channel in self.__channels:
                self.channel = channel
                if self.send_data(ESB_Ping_Request()):
                    self.__synchronized = True
                    self.on_synchronized()
                    return True
        return False

    def send_data(self, data, waiting_ack=False):
        self.__role = ESBRole.PTX
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__stack.address,
                no_ack=0
        ) / ESB_Payload_Hdr() / data
        success = self.__stack.send(packet, channel=self.__stack.channel)
        self._increment_pid()
        return success

    def wait_for_ack(self, timeout=1):
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.001)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def wait_for_data(self, timeout=1):
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

    def ack_stream(self):
        self.__role = ESBRole.PTX
        while True:
            yield self.__ack_queue.get(block=True)

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
        self.__ack_queue.put(pdu)
        if self.__app is not None:
            self.__app.on_acknowledgement(pdu[ESB_Payload_Hdr:])

    def on_ptx_pdu(self, pdu):
        self.__data_queue.put(pdu)
        if self.__app is not None:
            self.__app.on_data(pdu[ESB_Payload_Hdr:])


    def on_pdu(self, pdu):
        if (self.__role == ESBRole.PTX):
            self.on_prx_pdu(pdu)
        else:
            self.on_ptx_pdu(pdu)
