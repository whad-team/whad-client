"""
This module provides a single :py:class:`~whad.phy.connector.sniffer.Sniffer`
class that supports the following modulations:

- ASK
- GFSK
- BFSK
- QFSK
- BPSK
- QPSK
- LoRa

This sniffer is configured using a dedicated configuration class,
:py:class:`~whad.phy.sniffing.SnifferConfiguration`. This class allows users
to configure some default fields like the frequency, data rate and synchronization
word, but also some packet-specific parameters like the maximum packet size or
its endianness:

>>> config = SnifferConfiguration()
>>> config.frequency = 2402000000
>>> config.datarate = 1000000
>>> config.endianness = Endianness.LITTLE
>>> config.packet_size = 200
>>> config.sync_word = b'\\xAA\\xAA'

Modulation is selected by setting the correct modulation scheme to `True`:

>>> config.gfsk = True

Some modulations offer extra parameters, like the FSK and LoRa modulations.
FSK modulation can be customized through a :py:class:`~whad.phy.sniffing.FSKConfiguration`
object and LoRa through a :py:class:`~whad.phy.sniffing.LoRaConfiguration` object.

Once the sniffer configuration set, sniffing is quite easy:

>>> sniffer = Sniffer(WhadDevice.create("uart0"))
>>> sniffer.configuration = config
>>> sniffer.start()
>>> for packet in sniffer.sniff():
        packet.show()
"""

from time import time
from queue import Queue, Empty
from typing import Generator
from scapy.packet import Packet

from whad.exceptions import WhadDeviceDisconnected
from whad.hub.phy import Endianness
from whad.common.sniffing import EventsManager
from whad.exceptions import UnsupportedCapability

from .base import Phy
from ..sniffing import SnifferConfiguration

class Sniffer(Phy, EventsManager):
    """
    Phy Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device):
        Phy.__init__(self, device)
        EventsManager.__init__(self)

        # Queue to hold sniffed packets
        self.__packets = Queue()

        # Default configuration
        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def __enable_sniffing(self):
        """Enable sniffing.

        Configure the associated hardware and set the sniffer parameters.
        """
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
                self.__configuration.lora_configuration.preamble_length,
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

        # Set synchronization word
        self.set_sync_word(self.__configuration.sync_word)

        # Put WHAD interface in sniffing mode
        self.sniff_phy()

    @property
    def configuration(self):
        """Current sniffing configuration
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration: SnifferConfiguration):
        """Set the sniffer's configuration.

        It will stop the sniffer if it is enabled, update its configuration
        and resume sniffing. Sniffing starts automatically each time a new
        configuration is set.
        """
        self.stop()
        self.__configuration = new_configuration
        self.__enable_sniffing()

    @property
    def frequency(self) -> int:
        """Configured frequency in Hertz.
        """
        return self.__configuration.frequency

    @frequency.setter
    def frequency(self, frequency: int = 2402000000):
        """Update snffer's frequency. If already active, sniffing is stopped and resumed.
        """
        self.stop()
        self.__configuration.frequency = frequency
        self.__enable_sniffing()

    def available_actions(self, action_filter=None) -> list:
        """List available actions.
        """
        actions = []
        return [action for action in actions if action_filter is None or isinstance(action, filter)]

    def on_packet(self, packet: Packet):
        """Packet reception handler: put packets in sniffing queue.

        :param  packet: Received packet
        :type   packet: Packet
        """
        self.__packets.put(packet)

    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff packets out of thin air.

        :param timeout: Specify the number of seconds after which sniffing will stop.
                        Wait forever if set to `None`.
        :type timeout: float
        """
        try:
            while (timeout is None) or (timeout>0.0):
                # Wait for a packet
                start = time()
                packet = self.__packets.get(True, timeout=timeout)

                # Update remaining time if required
                if timeout is not None:
                    timeout = timeout - (time() - start)

                # Notify packet reception
                yield packet
        except Empty:
            # Timeout reached, exit
            return
        except WhadDeviceDisconnected:
            # Device disconnected, exit
            return
