from queue import Queue

from whad.exceptions import WhadDeviceDisconnected
from whad.phy.connector import Phy
from whad.phy import Endianness
from whad.hub.phy import Modulation as PhyModulation, Endianness as PhyEndianness
from whad.phy.injecting import InjectionConfiguration
from whad.phy.exceptions import NoModulation
from whad.exceptions import UnsupportedCapability

# TODO: every sniffer is broken (sniff() method does not catch packets, we
#       have to catch them in on_packet() and put them in a queue)

class Injector(Phy):
    """
    Phy Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device):
        Phy.__init__(self, device)
        self._metadata_check = False
        # Check if device can perform injection
        if not self.can_send():
            raise UnsupportedCapability("Inject")

        self.__configuration = InjectionConfiguration()


    @property
    def configuration(self) -> InjectionConfiguration:
        """Retrieve this injector configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: InjectionConfiguration):
        """Set the injector configuration.
        """
        self.stop()
        self.__configuration = new_configuration
        if self.__configuration.frequency is not None:
            self.set_frequency(self.__configuration.frequency)
        if self.__configuration.packet_size is not None:
            self.set_packet_size(self.__configuration.packet_size)

        # Set data rate for all modulations but LoRa
        if not self.__configuration.lora:
            if self.__configuration.datarate is not None:
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
        if self.__configuration.sync_word is not None:
            self.set_sync_word(self.__configuration.sync_word)
        self.start()

    def inject(self, packet):

        if not self._metadata_check:
            if hasattr(packet, "metadata") and hasattr(packet.metadata, "modulation") and packet.metadata.modulation is not None:
                deviation = packet.metadata.deviation
            else:
                deviation = None
            if deviation is not None:
                self.stop()
                if hasattr(packet, "metadata") and hasattr(packet.metadata, "modulation"):
                    if packet.metadata.modulation == PhyModulation.ASK and not self.__configuration.ask:
                        self.set_ask()
                    elif packet.metadata.modulation == PhyModulation.FSK and deviation is not None and not self.__configuration.bfsk:
                        self.set_bfsk(deviation=deviation)
                    elif (packet.metadata.modulation == PhyModulation.GFSK or packet.metadata.modulation == PhyModulation.MSK) and deviation is not None and not self.__configuration.gfsk:
                        self.set_gfsk(deviation=deviation)
                    elif packet.metadata.modulation == PhyModulation.FOURFSK and deviation is not None and not self.__configuration.qfsk:
                        self.set_4fsk(deviation=deviation)
                    elif packet.metadata.modulation == PhyModulation.BPSK and not self.__configuration.bpsk:
                        self.set_bpsk()
                    elif packet.metadata.modulation == PhyModulation.QPSK and not self.__configuration.qpsk:
                        self.set_qpsk()
                    elif packet.metadata.modulation == PhyModulation.LORA and not self.__configuration.lora:
                        self.set_lora(
                            self.__configuration.lora_configuration.spreading_factor,
                            self.__configuration.lora_configuration.coding_rate,
                            self.__configuration.lora_configuration.bandwidth,
                            12,
                            crc=self.__configuration.lora_configuration.enable_crc,
                            explicit=self.__configuration.lora_configuration.enable_explicit_mode
                        )

                if hasattr(packet, "metadata") and hasattr(packet.metadata, "frequency") and self.__configuration.frequency is None:
                    self.set_frequency(packet.metadata.frequency)

                if hasattr(packet, "metadata") and hasattr(packet.metadata, "packet_size") and self.__configuration.packet_size is None:
                    self.set_packet_size(packet.metadata.packet_size)

                if hasattr(packet, "metadata") and hasattr(packet.metadata, "datarate") and self.__configuration.datarate is None:
                    self.set_datarate(packet.metadata.datarate)

                if hasattr(packet, "metadata") and hasattr(packet.metadata, "syncword") and self.__configuration.sync_word is None:
                    self.set_sync_word(packet.metadata.syncword)

                if hasattr(packet, "metadata") and hasattr(packet.metadata, "endianness") and self.__configuration.endianness:
                    self.set_endianness(
                        Endianness.LITTLE if
                        packet.metadata.endianness == PhyEndianness.LITTLE else
                        Endianness.BIG
                    )

                self.start()
                self._metadata_check = True

        super().send(packet)
