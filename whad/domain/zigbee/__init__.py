from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.zigbee.zigbee_pb2 import Sniff, Start, Stop, StartCmd, StopCmd
from whad.domain.zigbee.sniffing import SnifferConfiguration
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

        # User packets callbacks
        self.__user_callbacks = {}

        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Check if device supports Zigbee
        if not self.device.has_domain(WhadDomain.Zigbee):
            raise UnsupportedDomain()
        else:
            self.__ready = True
            conf.dot15d4_protocol = 'zigbee'

    def attach_user_callbacks(self, callback, filter=lambda pkt:True):
        self.__user_callbacks[callback] = filter

    def detach_user_callbacks(self, callback):
        if callback in self.__user_callbacks:
            del self.__user_callbacks[callback]
            return True
        return False

    def _run_user_callbacks(self, packet):
        for callback,packet_filter in self.__user_callbacks.items():
            if packet_filter(packet):
                callback(packet)


    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = Dot15d4FCS(bytes(message.raw_pdu.pdu)[1:] + bytes(struct.pack(">H", message.raw_pdu.fcs)))
                #packet.metadata = generate_metadata(message, msg_type)
                return packet

            elif msg_type == 'pdu':
                packet = Dot15d4(bytes(message.pdu.pdu)[1:])
                #packet.metadata = generate_metadata(message, msg_type)
                return packet

        except AttributeError:
            return None

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
        print(msg)
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

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


    def on_raw_pdu(self, packet):
        if self.support_raw_pdu():
            self._run_user_callbacks(packet)

        self.on_pdu(Dot15d4(raw(packet)[:-2]))

    def on_pdu(self, packet):
        if not self.support_raw_pdu():
            self._run_user_callbacks(packet)


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
