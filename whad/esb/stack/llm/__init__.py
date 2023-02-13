from whad.esb.stack.llm.exceptions import LinkLayerTimeoutException
from whad.esb.stack.llm.constants import ESBRole
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response
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
        self.__promiscuous = False
        self.__populate_queues = False
        self.__ack_queue = Queue()
        self.__data_queue = Queue()
        self.__ackmiss = 0

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

    def _increment_pid(self):
        self.__pid = (self.__pid + 1) % 4

    def synchronize(self, timeout=10):
        self.__role = ESBRole.PTX
        self.__stack.set_channel(None)
        start_time = time()
        self.__ack_queue.queue.clear()
        self.__data_queue.queue.clear()
        self.__promiscuous = True
        self.__populate_queues = True
        queue = self.__ack_queue
        while (time() - start_time) < timeout:
            try:
                queue = self.__ack_queue if queue == self.__data_queue else self.__data_queue
                msg = queue.get(block=False,timeout=0.05)
                if hasattr(msg, "metadata") and hasattr(msg.metadata, "channel"):
                    print(msg.metadata.channel)
                    self.__stack.set_channel(msg.metadata.channel)
                    if not self.__synchronized:
                        self.__synchronized = True
                        self.on_synchronized()
                    break
            except Empty:
                pass
        self.__populate_queues = False
        self.__promiscuous = False
        return self.__synchronized

    def send_data(self, data, waiting_ack=False):
        self.__role = ESBRole.PTX
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__stack.get_address(),
                no_ack=0
        ) / ESB_Payload_Hdr() / data

        if waiting_ack:
            self.__stack.send(packet, channel=self.__stack.get_channel())
            self._increment_pid()
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
        else:
            acked = self.__stack.send(packet, channel=self.__stack.get_channel())
            self._increment_pid()
            if not acked:
                self.__ackmiss += 1
                if self.__ackmiss > 10:
                    self.__ackmiss = 0
                    if self.__synchronized:
                        self.__synchronized = False
                        self.on_desynchronized()
            else:
                self.__ackmiss = 0
                if not self.__synchronized:
                    self.__synchronized = True
                    self.on_synchronized()
            return acked

    def wait_for_ack(self, timeout=0.1):
        self.__populate_queues = True
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.001)
                self.__populate_queues = False
                return msg
            except Empty:
                pass
        self.__populate_queues = False
        raise LinkLayerTimeoutException

    def prepare_acknowledgment(self, data):
        self.__role = ESBRole.PRX
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__stack.get_address(),
                no_ack=True
        ) / ESB_Payload_Hdr() / data
        self.__stack.send(packet)

    def on_synchronized(self):
        if self.__app is not None:
            self.__app.on_synchronized()

    def on_desynchronized(self):
        if self.__app is not None:
            self.__app.on_desynchronized()

    def on_pdu(self, pdu):
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            if (self.__role == ESBRole.PTX or self.__promiscuous):
                if self.__populate_queues:
                    self.__ack_queue.put(pdu)
                if self.__app is not None and len(bytes(pdu)) > 0:
                    self.__app.on_acknowledgement(pdu[ESB_Payload_Hdr:])
        else:
            if (self.__role == ESBRole.PRX or self.__promiscuous):
                if self.__populate_queues:
                    self.__data_queue.put(pdu)
                if self.__app is not None:
                    self.__app.on_data(pdu[ESB_Payload_Hdr:])
