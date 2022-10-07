from whad.esb.stack.llm.exceptions import LinkLayerTimeoutException
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response
from queue import Queue, Empty
from time import sleep, time

class EsbLinkLayerManager:

    def __init__(self, connector, app_class = None):
        self.__connector = connector
        self.__app = app_class(self) if app_class is not None else None
        self.__pid = 0
        self.__synchronized = False
        self.__ack_queue = Queue()
        self.__data_queue = Queue()

    def _increment_pid(self):
        self.__pid = self.__pid + 1 % 4

    def synchronize(self, timeout=10):
        self.__connector.set_channel(0xFF)
        start_time = time()
        queue = self.__data_queue
        while (time() - start_time) < timeout:
            try:
                queue = self.__ack_queue if queue == self.__data_queue else self.__data_queue
                msg = queue.get(block=False,timeout=0.1)
                if hasattr(msg, "metadata") and hasattr(msg.metadata, "channel"):
                    self.__connector.set_channel(msg.metadata.channel)
                    self.__synchronized = True
                    break
            except Empty:
                pass
        return self.__synchronized

    def send_data(self, data, acknowledged=True):
        packet = ESB_Hdr(
                pid=self.__pid,
                address=self.__connector.get_address(),
                no_ack=not acknowledged
        ) / ESB_Payload_Hdr() / data

        self.__connector.send(packet)
        if acknowledged:
            try:
                message = self.wait_for_ack()
                self._increment_pid()
                return message
            except LinkLayerTimeoutException:
                return None
        else:
            self._increment_pid()
            return None

    def wait_for_ack(self, timeout=0.2):
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.__ack_queue.get(block=False,timeout=0.1)
                return msg
            except Empty:
                pass
        raise LinkLayerTimeoutException

    def prepare_acknowledgment(self, data):
        pass

    def on_pdu(self, pdu):
        if ESB_Ack_Response in pdu or len(bytes(pdu)) == 0:
            self.__ack_queue.put(pdu)
        else:
            self.__data_queue.put(pdu)
