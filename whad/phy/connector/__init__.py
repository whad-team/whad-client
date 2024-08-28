from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter
from whad.phy.utils.definitions import OOKModulationScheme, ASKModulationScheme, \
    QPSKModulationScheme, BPSKModulationScheme, \
    FSKModulationScheme, GFSKModulationScheme, QFSKModulationScheme
from whad.phy.utils.helpers import lora_sf, lora_cr
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.scapy.layers.phy import Phy_Packet
from whad.phy.exceptions import UnsupportedFrequency, InvalidParameter, ScheduleFifoFull, \
    UnknownPhysicalLayer, UnknownPhysicalLayerFunction
from whad.phy.connector.translator import PhyMessageTranslator

from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.phy import Commands, TxPower, Endianness, SupportedFreqRanges, \
    SchedulePacketResponse, PhyMetadata

class Phy(WhadDeviceConnector):
    """
    Physical layer connector.

    This connector drives a Physical Layer capable device with specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    translator = PhyMessageTranslator
    domain = "phy"

    def __init__(self, device=None):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        self.__ready = False
        super().__init__(device)

        # Capability cache
        self.__can_send = None
        self.__can_send_raw = None

        # Frequency cache
        self.__cached_supported_frequencies = None
        self.__cached_frequency = None

        # Address cache
        self.__address = None

        # Physical layer
        self.__physical_layer = None

        # Configurations
        self.__configured_datarate = False
        self.__configured_endianness = False
        self.__configured_frequency = False
        self.__configured_syncword = False
        self.__configured_packetsize = False
        self.__configured_modulation = False

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Initialize translator
        self.translator = PhyMessageTranslator(self.hub)

        # Check if device supports Logitech Unifying
        if not self.device.has_domain(WhadDomain.Phy):
            raise UnsupportedDomain("PHY")
        else:
            self.__ready = True


    def format(self, packet):
        """
        Format a packet for PCAP export.
        """
        if isinstance(packet, bytes):
            packet = Phy_Packet(packet)
        packet.metadata = PhyMetadata(syncword=b"")
        return self.hub.phy.format(packet)

    def close(self):
        self.stop()
        self.device.close()

    def can_use_ask(self):
        """
        Determine if the device can be configured to use Amplitude Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetASKModulation)) > 0


    def can_use_fsk(self):
        """
        Determine if the device can be configured to use Frequency Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetFSKModulation)) > 0


    def can_get_supported_frequencies(self):
        """
        Determine if the device can get a list of supported frequencies.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.GetSupportedFrequencies)) > 0

    def can_set_frequency(self):
        """
        Determine if the device can select a specific frequency.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetFrequency)) > 0

    def can_use_gfsk(self):
        """
        Determine if the device can be configured to use Gaussian Frequency Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetGFSKModulation)) > 0

    def can_use_4fsk(self):
        """
        Determine if the device can be configured to use 4-Frequency Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.Set4FSKModulation)) > 0

    def can_use_bpsk(self):
        """
        Determine if the device can be configured to use Binary Phase Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetBPSKModulation)) > 0

    def can_use_qpsk(self):
        """
        Determine if the device can be configured to use Quadrature Phase Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetQPSKModulation)) > 0

    def can_use_lora(self):
        """
        Determine if the device can be configured to use LoRa modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetLoRaModulation)) > 0

    def can_schedule_packets(self):
        """
        Determine if the device can send scheduled packets.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.ScheduleSend)) > 0

    def set_ask(self, on_off_keying=True):
        """
        Enable Amplitude Shift Keying modulation scheme.
        """
        if not self.can_use_ask():
            raise UnsupportedCapability("ASKModulation")

        # Create a SetAskMod message.
        msg = self.hub.phy.create_set_ask_mod(on_off_keying)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success

    def set_bfsk(self, deviation=250000):
        """
        Enable Frequency Shift Keying modulation scheme.

        Typical deviations:
        - ESB_1MBPS_PHY: 170000 Hz
        - BLE_1MBPS_PHY: 250000 Hz
        - ESB_2MBPS_PHY: 320000 Hz
        - BLE_2MBPS_PHY: 500000 Hz
        """
        if not self.can_use_fsk():
            raise UnsupportedCapability("FSKModulation")

        # Create a SetFskMod message.
        msg = self.hub.phy.create_set_fsk_mod(deviation)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success

    def set_4fsk(self, deviation=250000):
        """
        Enable 4-Frequency Shift Keying modulation scheme.
        """
        if not self.can_use_4fsk():
            raise UnsupportedCapability("4FSKModulation")

        # Create a Set4fskMod message.
        msg = self.hub.phy.create_set_4fsk_mod(deviation)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success


    def set_gfsk(self, deviation=250000):
        """
        Enable Gaussian Frequency Shift Keying modulation scheme.

        Typical deviations:
        - ESB_1MBPS_PHY: 170000 Hz
        - BLE_1MBPS_PHY: 250000 Hz
        - ESB_2MBPS_PHY: 320000 Hz
        - BLE_2MBPS_PHY: 500000 Hz
        """
        if not self.can_use_gfsk():
            raise UnsupportedCapability("GFSKModulation")

        # Create a SetGfskMod message.
        msg = self.hub.phy.create_set_gfsk_mod(deviation)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success


    def set_bpsk(self):
        """
        Enable Binary Phase Shift Keying modulation scheme.
        """
        if not self.can_use_bpsk():
            raise UnsupportedCapability("BPSKModulation")

        # Create a SetBpskMod message.
        msg = self.hub.phy.create_set_bpsk_mod()

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success


    def set_qpsk(self):
        """
        Enable Quadrature Phase Shift Keying modulation scheme.
        """
        if not self.can_use_qpsk():
            raise UnsupportedCapability("QPSKModulation")


        # Create a SetQpskMod message (offset set to False by default).
        msg = self.hub.phy.create_set_qpsk_mod(False)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success


    def set_lora(self, sf=7, cr=48, bw=125000, preamble=12, crc=False, explicit=False, invert_iq=False):
        """
        Enable LoRa modulation scheme.

        @param  sf          Spreading factor (values between 7 and 12)
        @param  cr          Coding rate (values between 45 (4/5) and 48 (4/8))
        @param  bw          Bandwidth (125, 250 or 500)
        @param  preamble    Preamble length (0-65535) in number of symbols
        @param  crc         Enable CRC if set to True, disable it otherwise
        @param  explicit    LoRa explicit header mode enabled if set to True (implicit header mode if False)
        """
        if not self.can_use_lora():
            raise UnsupportedCapability("LoRaModulation")

        # Make sure parameters are valid
        if sf not in range(7, 13):
            raise InvalidParameter('spreading factor')

        if cr not in range(45, 49):
            raise InvalidParameter('coding rate')

        if bw not in [125000, 250000, 500000]:
            raise InvalidParameter('bandwidth')

        # Create a SetLoRaMod message.
        msg = self.hub.phy.create_set_lora_mod(
            bw,
            lora_sf(sf),
            lora_cr(cr),
            preamble,
            enable_crc=crc,
            explicit_mode=explicit,
            invert_iq=invert_iq
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_modulation = True
        return success


    def get_supported_frequencies(self):
        """
        Get list of supported frequency ranges (in Hz).
        """
        if not self.can_get_supported_frequencies():
            raise UnsupportedCapability("GetSupportedFrequencies")

        # Create a GetSupportedFreqs message.
        msg = self.hub.phy.create_get_supported_freqs()

        resp = self.send_command(msg, message_filter(SupportedFreqRanges))
        assert isinstance(resp, SupportedFreqRanges)
        return [(i.start, i.end) for i in resp.ranges]


    def set_frequency(self, frequency):
        """
        Configure frequency (in Hz).
        """
        if not self.can_set_frequency():
            raise UnsupportedCapability("SetFrequency")

        if frequency is None:
            return False

        if self.__cached_supported_frequencies is None:
            self.__cached_supported_frequencies = self.get_supported_frequencies()
            #print(self.__cached_supported_frequencies)
        if all([frequency < freq_range[0] or frequency > freq_range[1] for freq_range in self.__cached_supported_frequencies]):
            raise UnsupportedFrequency(frequency)

        # Create a SetFreq message.
        msg = self.hub.phy.create_set_freq(frequency)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__cached_frequency = frequency
            self.__configured_frequency = True
        return success

    def can_set_datarate(self):
        """
        Checks if the device supports datarate configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetDataRate)) > 0

    def set_datarate(self, rate=1000000):
        """
        Configure datarate (in bauds).
        """

        if not self.can_set_datarate():
            raise UnsupportedCapability("DataRate")

        # Create a SetDatarate message.
        msg = self.hub.phy.create_set_datarate(rate)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_datarate = True
        return success

    def can_set_endianness(self):
        """
        Checks if the device supports Endianness configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetEndianness)) > 0

    def set_endianness(self, endianness=Endianness.BIG):
        """
        Configure endianness.
        """
        if not self.can_set_endianness():
            raise UnsupportedCapability("Endianness")

        # Create a SetEndianness message.
        msg = self.hub.phy.create_set_endianness(endianness==Endianness.LITTLE)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_endianness = True
        return success

    def can_send(self):
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Phy)
            self.__can_send = ((commands & (1 << Commands.Send))>0 or (commands & (1 << Commands.SendRaw)))
        return self.__can_send

    def can_set_tx_power(self):
        """
        Checks if the device supports TX Power level configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetTXPower)) > 0


    def set_tx_power(self, tx_power = TxPower.MEDIUM):
        """
        Configure TX Power level.
        """
        if not self.can_set_tx_power():
            raise UnsupportedCapability("TXPower")

        # Create a SetTxPower message.
        msg = self.hub.phy.create_set_tx_power(tx_power)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_set_packet_size(self):
        """
        Checks if the device can configure packet size.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetPacketSize)) > 0


    def set_packet_size(self, size=32):
        """
        Configure packet size in use.
        """
        if not self.can_set_packet_size():
            raise UnsupportedCapability("PacketSize")

        # Create a SetPacketSize message
        msg = self.hub.phy.create_set_packet_size(size)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_packetsize = True
        return success

    def can_set_sync_word(self):
        """
        Checks if the device can configure a synchronization word.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << Commands.SetSyncWord)) > 0


    def set_sync_word(self, sync_word = b"\xAA\xAA"):
        """
        Configure synchronization word.
        """
        if not self.can_set_sync_word():
            raise UnsupportedCapability("SyncWord")

        # Create a SetSyncWord message
        msg = self.hub.phy.create_set_sync_word(sync_word)

        resp = self.send_command(msg, message_filter(CommandResult))
        success = isinstance(resp, Success)
        if success:
            self.__configured_syncword = True
        return success

    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def support_raw_iq_stream(self):
        """
        Determine if the device supports raw IQ stream.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.Phy)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def sniff_phy(self, iq_stream = False):
        """
        Sniff Physical Layer packets.
        """
        if iq_stream and not self.support_raw_iq_stream():
            raise UnsupportedCapability("RawIQStream")

        """
        if not self.__configured_modulation:
            raise NoModulation()
        if not self.__configured_datarate:
            raise NoDatarate()
        if not self.__configured_packetsize:
            raise NoPacketSize()
        if not self.__configured_frequency:
            raise NoFrequency()
        if not self.__configured_syncword:
            raise NoSyncWord()
        if not self.__configured_endianness:
            raise NoEndianess()
        """

        # Create a SniffMode message
        msg = self.hub.phy.create_sniff_mode(iq_stream)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def start(self):
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.phy.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.phy.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_channel(self, channel):
        if self.__physical_layer is None:
            raise UnknownPhysicalLayer()

        if self.__physical_layer.channel_to_frequency is None:
            raise UnknownPhysicalLayerFunction("channel_to_frequency")

        if hasattr(self.__physical_layer.configuration, "channel"):
            self.__physical_layer.configuration.channel = channel

        return self.set_frequency(self.__physical_layer.channel_to_frequency(channel))


    def get_channel(self, channel):
        if self.__physical_layer is None:
            raise UnknownPhysicalLayer()

        if self.__physical_layer.frequency_to_channel is None:
            raise UnknownPhysicalLayerFunction("frequency_to_channel")

        if self.__cached_frequency is None:
            return None

        return self.__physical_layer.frequency_to_channel(self.__cached_frequency)


    def set_address(self, address):
        if self.__physical_layer is None:
            raise UnknownPhysicalLayer()

        if self.__physical_layer.format_address is None:
            raise UnknownPhysicalLayerFunction("format_address")

        self.__address = address
        self.translator.address = address

        if hasattr(self.__physical_layer.configuration, "address"):
            self.__physical_layer.configuration.address = address

        bytes_address = self.__physical_layer.format_address(self.__address)
        pattern = (self.__physical_layer.synchronization_word + bytes_address)
        self.translator.pattern_cropped_bytes = len(pattern) - 4
        self.translator.pattern = pattern
        self.set_sync_word(self.translator.pattern[-4:])


    def get_address(self, address):
        if self.__physical_layer is None:
            raise UnknownPhysicalLayer()

        return self.__address

    def set_configuration(self, configuration):
        if self.__physical_layer is None:
            raise UnknownPhysicalLayer()

        if hasattr(configuration, "channel"):
            self.set_channel(configuration.channel)

        if hasattr(configuration, "address"):
            self.set_address(configuration.address)

        self.__physical_layer.configuration = configuration

    def set_physical_layer(self, physical_layer):
        """
        Sets a specific physical layer.
        """
        if isinstance(physical_layer.modulation, OOKModulationScheme):
            success = self.set_ask(on_off_keying=True)
        elif isinstance(physical_layer.modulation, ASKModulationScheme):
            success = self.set_ask(on_off_keying=False)
        elif isinstance(physical_layer.modulation, QFSKModulationScheme):
            success = self.set_4fsk(deviation=physical_layer.modulation.deviation)
        elif isinstance(physical_layer.modulation, GFSKModulationScheme):
            success = self.set_gfsk(deviation=physical_layer.modulation.deviation)
        elif isinstance(physical_layer.modulation, FSKModulationScheme):
            success = self.set_fsk(deviation=physical_layer.modulation.deviation)
        elif isinstance(physical_layer.modulation, QPSKModulationScheme):
            success = self.set_qpsk()
        elif isinstance(physical_layer.modulation, BPSKModulationScheme):
            success = self.set_bpsk()
        else:
            return False

        if not success:
            return False

        success = self.set_endianness(physical_layer.endianness)
        if not success:
            return False

        success = self.set_datarate(physical_layer.datarate)
        if not success:
            return False

        success = self.set_sync_word(physical_layer.synchronization_word)
        if not success:
            return False

        success = self.set_packet_size(physical_layer.maximum_packet_size)
        if not success:
            return False

        supported_frequencies = self.get_supported_frequencies()
        start, end = physical_layer.frequency_range[0], physical_layer.frequency_range[1]
        success = False
        for i in supported_frequencies:
            if start >= i[0] and end <= i[1]:
                success = True
                break

        if not success:
            return False

        self.__physical_layer = physical_layer
        self.translator.physical_layer = self.__physical_layer
        return True

    def send(self, packet):
        """
        Send Phy packets .
        """
        if not self.can_send():
            raise UnsupportedCapability("Send")
        if isinstance(packet, bytes):
            packet = Phy_Packet(packet)

        # Generate TX metadata
        packet.metadata = PhyMetadata()
        packet.metadata.frequency = self.__cached_frequency

        return super().send_packet(packet)

    def schedule_send(self, packet, timestamp: float = 0.0) -> int:
        """Schedule a packet to be sent at a given time.
        """
        if not self.can_send():
            raise UnsupportedCapability("Send")
        if not self.can_schedule_packets():
            raise UnsupportedCapability("ScheduledSend")

        if isinstance(packet, bytes):
            packet = Phy_Packet(packet)

        # Generate TX metadata
        packet.metadata = PhyMetadata()
        packet.metadata.frequency = self.__cached_frequency

        # Set timestamp
        msg = self.hub.phy.create_schedule_packet(
            bytes(packet),
            int(timestamp*1000000)
        )

        # Schedule a packet
        resp = self.send_command(msg, message_filter(SchedulePacketResponse))
        assert isinstance(resp, SchedulePacketResponse)
        if resp.full:
            raise ScheduleFifoFull
        else:
            return resp.id

    def on_discovery_msg(self, message):
        pass

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        pass

    def on_packet(self, packet):
        """Incoming packet handler.
        """
        pass

    def on_event(self, event):
        """Incoming event handler.
        """
        pass
