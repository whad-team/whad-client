from queue import Queue

from whad.exceptions import WhadDeviceDisconnected
from whad.phy.connector import Phy
from whad.phy import Endianness
from whad.phy.sniffing import SnifferConfiguration
from whad.phy.exceptions import NoModulation
from whad.common.sniffing import EventsManager
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type

from whad.hub.phy import PacketReceived, RawPacketReceived
from whad.hub.message import AbstractPacket

# TODO: every sniffer is broken (sniff() method does not catch packets, we
#       have to catch them in on_packet() and put them in a queue)

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

        # Set data rate for all modulations but LoRa
        if not self.__configuration.lora:
            self.set_datarate(self.__configuration.datarate)

        if self.__configuration.gfsk:
            self.set_gfsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.bfsk:
            self.set_bfsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.qfsk:
            self.set_4fsk(deviation=self.__configuration.fsk_configuration.deviation)
        elif self.__configuration.ask:
            self.set_ask()
        elif self.__configuration.bpsk:
            self.set_bpsk()
        elif self.__configuration.qpsk:
            self.set_qpsk()
        elif self.__configuration.lora:
            self.set_lora(
                self.__configuration.lora_configuration.spreading_factor,
                self.__configuration.lora_configuration.coding_rate,
                self.__configuration.lora_configuration.bandwidth,
                12,
                crc=self.__configuration.lora_configuration.enable_crc,
                explicit=self.__configuration.lora_configuration.enable_explicit_mode
            )

        # Set endianness for all modulations but LoRa
        if not self.__configuration.lora:
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
        try:
            while True:
                if self.support_raw_iq_stream():
                    message_type = RawPacketReceived
                else:
                    message_type = PacketReceived
                message = self.wait_for_message(filter=message_filter(message_type), timeout=.1)

                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    self.monitor_packet_rx(packet)
                    yield packet
        except WhadDeviceDisconnected:
            return
