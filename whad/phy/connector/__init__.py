from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.phy.phy_pb2 import SetASKModulation, SetFSKModulation, \
    SetGFSKModulation, SetBPSKModulation, SetQPSKModulation, Start, Stop, \
    SetBPSKModulationCmd, SetQPSKModulationCmd, SetSubGhzFrequency, \
    SetTwoDotFourGhzFrequency, SetFiveGhzFrequency, SetDataRate, SetEndianness, \
    Endianness, SetTXPower, TXPower, SetPacketSize, SetSyncWord
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.exceptions import RequiredImplementation, UnsupportedCapability, UnsupportedDomain
from whad.scapy.layers.phy import Phy_Packet

class Phy(WhadDeviceConnector):
    """
    Physical layer connector.

    This connector drives a Physical Layer capable device with specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """

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

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Check if device supports Logitech Unifying
        if not self.device.has_domain(WhadDomain.Phy):
            raise UnsupportedDomain()
        else:
            self.__ready = True


    def close(self):
        self.stop()
        self.device.close()


    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_packet':
                packet = Phy_Packet(bytes(message.raw_packet.packet))
                packet.metadata = generate_phy_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

            elif msg_type == 'packet':
                packet = Phy_Packet(bytes(message.packet.packet))
                packet.metadata = generate_phy_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

        except AttributeError:
            return None

    def can_use_ask(self):
        """
        Determine if the device can be configured to use Amplitude Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetASKModulation)) > 0


    def can_use_fsk(self):
        """
        Determine if the device can be configured to use Frequency Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetFSKModulation)) > 0


    def can_use_gfsk(self):
        """
        Determine if the device can be configured to use Gaussian Frequency Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetGFSKModulation)) > 0

    def can_use_bpsk(self):
        """
        Determine if the device can be configured to use Binary Phase Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetBPSKModulation)) > 0

    def can_use_qpsk(self):
        """
        Determine if the device can be configured to use Quadrature Phase Shift Keying modulation scheme.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetQPSKModulation)) > 0

    def configure_ask(self, on_off_keying=True):
        """
        Enable Amplitude Shift Keying modulation scheme.
        """
        if not self.can_use_ask():
            raise UnsupportedCapability("ASKModulation")

        msg = Message()
        msg.phy.mod_ask.ook = ook
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def configure_fsk(self, deviation=250000):
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

        msg = Message()
        msg.phy.mod_fsk.deviation = deviation
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def configure_gfsk(self, deviation=250000):
        """
        Enable Gaussian Frequency Shift Keying modulation scheme.

        Typical deviations:
        - ESB_1MBPS_PHY: 170000 Hz
        - BLE_1MBPS_PHY: 250000 Hz
        - ESB_2MBPS_PHY: 320000 Hz
        - BLE_2MBPS_PHY: 500000 Hz
        """
        if not self.can_use_fsk():
            raise UnsupportedCapability("GFSKModulation")

        msg = Message()
        msg.phy.mod_gfsk.deviation = deviation
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def configure_bpsk(self):
        """
        Enable Binary Phase Shift Keying modulation scheme.
        """
        if not self.can_use_bpsk():
            raise UnsupportedCapability("BPSKModulation")

        msg = Message()
        msg.phy.mod_bpsk.CopyFrom(SetBPSKModulationCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def configure_qpsk(self):
        """
        Enable Quadrature Phase Shift Keying modulation scheme.
        """
        if not self.can_use_qpsk():
            raise UnsupportedCapability("QPSKModulation")

        msg = Message()
        msg.phy.mod_qpsk.CopyFrom(SetQPSKModulationCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def can_use_subghz_band(self):
        """
        Checks if the device supports SubGHz frequency bands.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetSubGhzFrequency)) > 0

    def can_use_2_4_ghz_band(self):
        """
        Checks if the device supports 2.4GHz ISM frequency band.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetTwoDotFourGhzFrequency)) > 0

    def can_use_5_ghz_band(self):
        """
        Checks if the device supports 5GHz frequency band.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetFiveGhzFrequency)) > 0

    def set_subghz_frequency(self, frequency):
        """
        Configure frequency in the SubGHz band (in MHz).
        """
        if not self.can_use_subghz_band():
            raise UnsupportedCapability("SubGHzBand")

        msg = Message()
        msg.phy.freq_subghz.frequency_offset = frequency
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_2_4_ghz_frequency(self, frequency):
        """
        Configure frequency in the 2.4GHz band (in MHz).
        """
        if not self.can_use_2_4_ghz_band():
            raise UnsupportedCapability("TwoDotFourGHzBand")

        msg = Message()
        msg.phy.freq_twodotfour.frequency_offset = (2400 - frequency)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def set_5_ghz_frequency(self, frequency):
        """
        Configure frequency in the 5GHz band (in MHz).
        """
        if not self.can_use_5_ghz_band():
            raise UnsupportedCapability("FiveGHzBand")

        msg = Message()
        msg.phy.freq_fiveghz.frequency_offset = (5000 - frequency)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def set_frequency(self, frequency):
        """
        Configure frequency (in MHz).
        """
        if frequency >= 0 and frequency <= 1000:
            return self.set_subghz_frequency(frequency)

        elif frequency >= 2400 and frequency <= 2500:
            return self.set_2_4_ghz_frequency(frequency)

        elif frequency >= 5000 and frequency <= 6000:
            return self.set_5_ghz_frequency(frequency)

        else:
            raise RequiredImplementation()

    def can_set_datarate(self):
        """
        Checks if the device supports datarate configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetDataRate)) > 0

    def set_datarate(self, rate=1000000):
        """
        Configure datarate (in bauds).
        """

        if not self.can_set_datarate():
            raise UnsupportedCapability("DataRate")


        msg = Message()
        msg.phy.datarate.rate = rate
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_set_endianness(self):
        """
        Checks if the device supports Endianness configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetEndianness)) > 0

    def set_endianness(self, endianness=Endianness.BIG):
        """
        Configure endianness.
        """
        if not self.can_set_endianness():
            raise UnsupportedCapability("Endianness")

        msg = Message()
        msg.phy.endianness.endianness = endianness
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def can_set_tx_power(self):
        """
        Checks if the device supports TX Power level configuration.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetTXPower)) > 0


    def set_tx_power(self, tx_power = TXPower.MEDIUM):
        """
        Configure TX Power level.
        """
        if not self.can_set_tx_power():
            raise UnsupportedCapability("TXPower")

        msg = Message()
        msg.phy.tx_power.tx_power = tx_power
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_set_packet_size(self):
        """
        Checks if the device can configure packet size.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetPacketSize)) > 0


    def set_packet_size(self, size=32):
        """
        Configure packet size in use.
        """
        if not self.can_set_packet_size():
            raise UnsupportedCapability("PacketSize")

        msg = Message()
        msg.phy.packet_size.packet_size = size
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_set_sync_word(self):
        """
        Checks if the device can configure a synchronization word.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (commands & (1 << SetSyncWord)) > 0


    def set_sync_word(self, sync_word = b"\xAA\xAA"):
        """
        Configure synchronization word.
        """
        if not self.can_set_sync_word():
            raise UnsupportedCapability("SyncWord")

        msg = Message()
        msg.phy.sync_word.sync_word = sync_word
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Phy)
        return (
            (commands & (1 << Sniff)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
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

        msg = Message()
        msg.phy.sniff.iq_stream = iq_stream
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def start(self):
        """
        Start currently enabled mode.
        """
        msg = Message()
        msg.phy.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.phy.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        if domain == 'phy':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'packet':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_packet(packet)

            elif msg_type == 'raw_pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_raw_packet(packet)


    def on_raw_packet(self, packet):
        self.on_packet(packet)

    def on_packet(self, packet):
        pass
