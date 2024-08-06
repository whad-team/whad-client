'''
This module provides the :class:`whad.phy.connector.lora.LoRa` connector that wraps PHY's
default :class:`whad.phy.connector.Phy` connector and make it easier to receive
and send LoRa packets.
'''
from queue import Queue, Empty
from scapy.packet import Packet
from whad.device import WhadDevice
from whad.exceptions import UnsupportedCapability
from whad.phy.connector import Phy
from whad.phy.exceptions import InvalidParameter


class LoRa(Phy):
    '''LoRa modulation/demodulation connector.
    '''

    SYNCWORD_M2M = b'\x24\x14'
    SYNCWORD_LORAWAN = b'\x44\x34'

    domain = "lora"

    def __init__(self, device: WhadDevice = None):
        '''Initialization
        '''
        # Initialize our underlying Phy connector.
        super().__init__(device)

        # Make sure LoRa is supported by the device
        if not self.can_use_lora():
            raise UnsupportedCapability('SetLoRaModulation')

        # Set LoRa default parameters
        self.__spreading_factor = 7             # SF7
        self.__coding_rate = 45                 # Coding rate 4/5
        self.__bandwidth = 125000               # 125 kHz
        self.__preamble_length = 12             # Preamble length (in symbols)
        self.__crc_enabled = False              # CRC disabled by default
        self.__explicit_mode = False            # Explicit mode is disabled by default
        self.__invert_iq = False                # Invert IQ is disabled by default
        self.__syncword = LoRa.SYNCWORD_M2M     # LoRa M2M by default

        self.__pkt_queue = Queue()


    ##
    # Getters for LoRa modulation parameters
    ##

    @property
    def sf(self):
        '''Current spreading factor.
        '''
        return self.__spreading_factor


    @sf.setter
    def sf(self, value: int):
        '''Spreading factor setter.
        '''
        if value in range(7, 13):
            self.__spreading_factor = value
        else:
            raise InvalidParameter('sf')


    @property
    def cr(self):
        '''Current coding rate.
        '''
        return self.__coding_rate


    @cr.setter
    def cr(self, value: int):
        '''Coding rate setter.
        '''
        if value in range(45, 49):
            self.__coding_rate = value
        else:
            raise InvalidParameter('cr')


    @property
    def bw(self):
        '''Current bandwidth.
        '''
        return self.__bandwidth


    @bw.setter
    def bw(self, value: int):
        '''Bandwidth setter.
        '''
        if value in [125000, 250000, 500000]:
            self.__bandwidth = value
        else:
            raise InvalidParameter('bw')


    @property
    def preamble_length(self):
        '''Current preamble size (in symbols).
        '''
        return self.__preamble_length


    @preamble_length.setter
    def preamble_length(self, value: int):
        '''Preamble length setter.
        '''
        if value in range(0, 65536):
            self.__preamble_length = value
        else:
            raise InvalidParameter('preamble')


    @property
    def crc_enabled(self):
        '''Current CRC configuration.
        '''
        return self.__crc_enabled


    def enable_crc(self, enabled: bool):
        '''Enable or disable CRC.
        '''
        self.__crc_enabled = enabled


    @property
    def explicit_mode(self):
        '''Current packet type (check if Explicit mode is set)
        '''
        return self.__explicit_mode


    def enable_explicit_mode(self, enabled: bool):
        '''Enable or disable explicit mode (variable packet length).
        '''
        self.__explicit_mode = enabled

    @property
    def invert_iq(self):
        """Current IQ inversion setting
        """
        return self.__invert_iq

    @invert_iq.setter
    def invert_iq(self, enabled : bool):
        """Set IQ inversion.
        """
        self.__invert_iq = enabled


    @property
    def syncword(self):
        '''Current configured synchronization word.
        '''
        return self.__syncword

    @syncword.setter
    def syncword(self, syncword: bytes):
        '''Set synchronization word.

        :param syncword: new synchronization word
        :type syncword: bytes
        '''
        self.__syncword = syncword



    ##
    # LoRa start/stop
    ##

    def start(self):
        '''Start device in LoRa mode (continuous RX)
        '''
        # Configure the device for LoRa modulation
        self.set_lora(
            self.__spreading_factor,
            self.__coding_rate,
            self.__bandwidth,
            self.__preamble_length,
            self.__crc_enabled,
            self.__explicit_mode,
            self.__invert_iq
        )

        # Set syncword
        self.set_sync_word(self.__syncword)

        # Start RX
        super().start()


    def on_packet(self, packet):
        """Incoming packet handler.
        """
        # Add packet to our packet queue
        self.__pkt_queue.put(packet)


    def wait_packet(self, timeout: float = None) -> Packet:
        """Wait for a LoRa packet.

        :param timeout: if set, wait ``timeout`` seconds until returning
        :type timeout: float
        :return: received packet if any, ``None`` otherwise
        :rtype: :class:`scapy.packet.Packet`
        """
        try:
            packet = self.__pkt_queue.get(block=True, timeout=timeout)
            return packet
        except Empty:
            return None
