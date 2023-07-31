from whad.phy.connector import Phy
from whad.phy import Endianness
from whad.phy.sniffing import SnifferConfiguration
from whad.phy.exceptions import NoModulation
from whad.common.sniffing import EventsManager
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type


class Sniffer(Phy, EventsManager):
    """
    Phy Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        Phy.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        self.set_frequency(self.__configuration.frequency)
        self.set_packet_size(self.__configuration.packet_size)
        self.set_datarate(self.__configuration.datarate)
        if self.__configuration.gfsk:
            self.set_gfsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.bfsk:
            self.set_bfsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.qfsk:
            self.set_qfsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.ask:
            self.set_ask()
        elif self.__configuration.bpsk:
            self.set_bpsk()
        elif self.__configuration.qpsk:
            self.set_qpsk()


        self.set_endianness(
            Endianness.LITTLE if
            self.__configuration.little_endian else
            Endianness.BIG
        )
        self.set_sync_word(self.__configuration.sync_word)

        self.sniff_phy()

    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    @property
    def frequency(self):
        return self.__configuration.frequency

    @frequency.setter
    def frequency(self, frequency=2402000000):
        self.stop()
        self.__configuration.frequency = frequency
        self._enable_sniffing()


    def available_actions(self, filter=None):
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self):
        while True:
            if self.support_raw_iq_stream():
                message_type = "raw_packet"
            else:
                message_type = "packet"

            message = self.wait_for_message(filter=message_filter('phy', message_type))
            packet = self.translator.from_message(message.phy, message_type)
            self.monitor_packet_rx(packet)

            yield packet
