from whad import WhadDomain, WhadCapability
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr, Dot15d4TAP_FCS_Type
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.zigbee.metadata import generate_zigbee_metadata, ZigbeeMetadata
from whad.zigbee.stack import ZigbeeStack
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.zigbee.zigbee_pb2 import Sniff, Start, Stop, StartCmd, StopCmd, \
    Send, SendCmd, EnergyDetection, EnergyDetectionCmd
from whad.zigbee.sniffing import SnifferConfiguration
from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
import struct

class Zigbee(WhadDeviceConnector):
    """
    Zigbee protocol connector.

    This connector drives a Zigbee-capable device with Zigbee-specific WHAD messages.
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

        # Check if device supports Zigbee
        if not self.device.has_domain(WhadDomain.Zigbee):
            raise UnsupportedDomain()
        else:
            self.__ready = True
            conf.dot15d4_protocol = 'zigbee'

    def close(self):
        self.stop()
        self.device.close()

    def format(self, packet):
        if hasattr(packet, "metadata"):
            header, timestamp = packet.metadata.convert_to_header()
        else:
            header = Dot15d4TAP_Hdr()
            timestamp = None

        header.data.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_FCS_Type(
            fcs_type=int(Dot15d4FCS in packet)
            )
        )
        formatted_packet = header/packet
        return formatted_packet, timestamp

    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = Dot15d4FCS(bytes(message.raw_pdu.pdu) + bytes(struct.pack(">H", message.raw_pdu.fcs)))
                packet.metadata = generate_zigbee_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

            elif msg_type == 'pdu':
                packet = Dot15d4(bytes(message.pdu.pdu))
                packet.metadata = generate_zigbee_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

        except AttributeError:
            return None

    def _build_message_from_scapy_packet(self, packet, channel=11):
        msg = Message()

        self._signal_packet_transmission(packet)

        if Dot15d4FCS in packet:
            msg.zigbee.send_raw.channel = channel
            pdu = raw(packet)[:-2]
            msg.zigbee.send_raw.pdu = pdu
            msg.zigbee.send_raw.fcs = packet.fcs

        elif Dot15d4 in packet:
            msg.zigbee.send.channel = channel
            pdu = raw(packet)
            msg.zigbee.send.pdu = pdu
        else:
            msg = None

        return msg

    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << Sniff)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def can_send(self):
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Zigbee)
            self.__can_send =  (commands & (1 << Send)) > 0
        return self.__can_send


    def can_perform_ed_scan(self):
        """
        Determine if the device can perform energy detection scan.
        """
        commands = self.device.get_domain_commands(WhadDomain.Zigbee)
        return (
            (commands & (1 << EnergyDetection)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )


    def support_raw_pdu(self):
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.Zigbee)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw

    def sniff_zigbee(self, channel=11):
        """
        Sniff Zigbee packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.zigbee.sniff.channel = channel
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def send(self,pdu,channel=11):
        """
        Send Zigbee packets (on a single channel).
        """
        if self.can_send():
            if self.support_raw_pdu():
                if Dot15d4FCS not in pdu:
                    packet = Dot15d4FCS(raw(pdu)+Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu
            elif Dot15d4FCS in pdu:
                pdu = Dot15d4(raw(pdu)[:-2])
            else:
                packet = pdu
            msg = self._build_message_from_scapy_packet(packet, channel)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

        else:
            return False

    def perform_ed_scan(self, channel=11):
        """
        Perform an Energy Detection scan.
        """
        if self.can_perform_ed_scan():
            msg = Message()
            msg.zigbee.ed.channel = channel
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)
        else:
            return False

    def start(self):
        """
        Start currently enabled mode.
        """
        msg = Message()
        msg.zigbee.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.zigbee.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def process_messages(self):
        self.device.process_messages()

    def on_generic_msg(self, message):
        print('generic: %s' % message)
        pass

    def on_discovery_msg(self, message):
        pass


    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        if domain == 'zigbee':

            msg_type = message.WhichOneof('msg')
            if msg_type == 'pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_raw_pdu(packet)
            elif msg_type == "ed_sample":
                self.on_ed_sample(message.ed_sample.timestamp, message.ed_sample.sample)

    def on_raw_pdu(self, packet):
        self.on_pdu(Dot15d4(raw(packet)[:-2]))

    def on_pdu(self, packet):
        pass

    def on_ed_sample(self, timestamp, sample):
        print(sample)

class EndDevice(Zigbee):
    """
    Zigbee End Device interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)

        self.__stack = ZigbeeStack(self)
        if not self.can_sniff() or not self.can_send():
            raise UnsupportedCapability("EndDevice")

        self.__channel = 11
        self.__channel_page = 0
        self.enable_reception()

    @property
    def stack(self):
        return self.__stack

    def enable_reception(self):
        self.sniff_zigbee(channel=self.__channel)

    def set_channel(self, channel=11):
        self.__channel = channel
        self.enable_reception()

    def perform_ed_scan(self, channel):
        if not self.can_perform_ed_scan():
            raise UnsupportedCapability("EnergyDetection")
        self.__channel = channel
        super().perform_ed_scan(channel)

    def set_channel_page(self, page=0):
        if page != 0:
            raise UnsupportedCapability("ChannelPageSelection")
        else:
            self.__channel_page = page

    def send(self, packet):
        super().send(packet, channel=self.__channel)

    def on_pdu(self, pdu):
        if (
            hasattr(pdu,"metadata") and
            hasattr(pdu.metadata, "is_fcs_valid") and
            not pdu.metadata.is_fcs_valid
        ):
            print("dropped packet")
            return

        self.__stack.on_pdu(pdu)

    def on_ed_sample(self, timestamp, sample):
        self.__stack.on_ed_sample(timestamp, sample)

class Sniffer(Zigbee):
    """
    Zigbee Sniffer interface for compatible WHAD device.
    """
    def __init__(self, device):
        super().__init__(device)
        self.__configuration = SnifferConfiguration()

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        self.sniff_zigbee(channel=self.__configuration.channel)

    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=11):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    def available_actions(self, filter=None):
        actions = []
        return [action for action in actions if filter is None or isinstance(action, filter)]

    def sniff(self):
        while True:
            if self.support_raw_pdu():
                message_type = "raw_pdu"
            else:
                message_type = "pdu"

            message = self.wait_for_message(filter=message_filter('zigbee', message_type))
            yield self._build_scapy_packet_from_message(message.zigbee, message_type)
