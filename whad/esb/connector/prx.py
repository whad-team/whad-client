from whad.esb.connector import ESB
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type


class PRX(ESB):
    """
    Enhanced ShockBurst Primary Receiver Role (PRX) implementation for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)

        # Check if device can modify its address and enter the PRX role

        self.__channel = 8
        self.__address = "11:22:33:44:55"

        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        if not self.can_be_prx():
            raise UnsupportedCapability("PrimaryReceiverMode")
        self._enable_role()

    def _enable_role(self):
        self.set_node_address(self.__address)
        self.enable_prx_mode(self.__channel)

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
