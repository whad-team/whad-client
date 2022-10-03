from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.esb.metadata import ESBMetadata, generate_esb_metadata
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Pseudo_Packet
#from whad.scapy.layers.unifying import *
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.esb.esb_pb2 import Sniff, Start, Stop, StartCmd, StopCmd, \
    Send, SendCmd

class ESB(WhadDeviceConnector):
    """
    Enhanced ShockBurst protocol connector.

    This connector drives a Enhanced ShockBurst (ESB) capable device with ESB-specific WHAD messages.
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

        # Check if device supports Enhanced ShockBurst
        if not self.device.has_domain(WhadDomain.Esb):
            raise UnsupportedDomain()
        else:
            self.__ready = True

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        packet.preamble = 0xAA
        formatted_packet = ESB_Pseudo_Packet(bytes(packet)[1:])

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp

    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = ESB_Hdr(bytes(message.raw_pdu.pdu))
                packet.metadata = generate_esb_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

            elif msg_type == 'pdu':
                packet = ESB_Payload_Hdr(bytes(message.pdu.pdu))
                packet.metadata = generate_esb_metadata(message, msg_type)
                self._signal_packet_reception(packet)
                return packet

        except AttributeError:
            return None


    def close(self):
        self.stop()
        self.device.close()


    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
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
            capabilities = self.device.get_domain_capability(WhadDomain.Esb)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << SetNodeAddress)) > 0
        )

    def sniff_esb(self, channel=None, address="FF:FF:FF:FF:FF", show_acknowledgements=False):
        """
        Sniff Enhanced ShockBurst packets.
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        msg = Message()
        msg.esb.sniff.channel = channel if channel is not None else 0xFF
        try:
            msg.esb.sniff.address = bytes.fromhex(address.replace(":", ""))
        except ValueError:
            return False
        msg.esb.sniff.show_acknowledgements = show_acknowledgements
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def start(self):
        """
        Start currently enabled mode.
        """
        msg = Message()
        msg.esb.start.CopyFrom(StartCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        msg = Message()
        msg.esb.stop.CopyFrom(StopCmd())
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        if not self.__ready:
            return

        if domain == 'esb':
            msg_type = message.WhichOneof('msg')
            if msg_type == 'pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                packet = self._build_scapy_packet_from_message(message, msg_type)
                self.on_raw_pdu(packet)


    def on_raw_pdu(self, packet):
        pdu = packet[ESB_Payload_Hdr:]
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        pass
