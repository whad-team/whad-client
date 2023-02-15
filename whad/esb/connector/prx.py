from whad.esb.connector import ESB
from whad.esb.stack import ESBStack
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type


class PRX(ESB):
    """
    Enhanced ShockBurst Primary Receiver Role (PRX) implementation for compatible WHAD device.
    """
    def __init__(self, device):
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
        self.set_node_address(self.__address)
        self.enable_prx_mode(self.__channel)
        if self.__started:
            self.start()

    @property
    def stack(self):
        return self.__stack

    @property
    def channel(self):
        return self.__channel

    @channel.setter
    def channel(self, channel):
        self.stop()
        self.__channel = channel
        self._enable_role()

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, address):
        self.stop()
        self.__address = address
        self._enable_role()

    def start(self):
        super().start()
        self.__started = True

    def stop(self):
        super().stop()
        self.__started = False

    def prepare_acknowledgment(self, ack):
        self.__stack.ll.prepare_acknowledgment(ack)

    def on_pdu(self, pdu):
        self.__stack.on_pdu(pdu)

    def stream(self):
        for pdu in self.__stack.ll.data_stream():
            yield pdu
