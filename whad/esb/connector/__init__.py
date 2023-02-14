from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.esb.metadata import ESBMetadata, generate_esb_metadata
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
#from whad.scapy.layers.unifying import *
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.whad_pb2 import Message
from whad.protocol.esb.esb_pb2 import Sniff, Start, Stop, StartCmd, StopCmd, \
    Send, SendCmd, SendRawCmd, SendRaw, PrimaryReceiverMode, PrimaryTransmitterMode, \
    SetNodeAddress

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

        # Metadata cache
        self.__cached_channel = None
        self.__cached_address = None

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
        if ESB_Hdr not in packet:
            packet = ESB_Hdr(address=self.__cached_address)/packet

        packet.preamble = 0xAA # force a rebuild
        formatted_packet = ESB_Pseudo_Packet(bytes(packet)[1:])

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp

    def _build_scapy_packet_from_message(self, message, msg_type):
        try:
            if msg_type == 'raw_pdu':
                packet = ESB_Hdr(bytes(message.raw_pdu.pdu))
                packet.preamble = 0xAA # force a rebuild
                packet.metadata = generate_esb_metadata(message, msg_type)
                self.monitor_packet_rx(packet)
                return packet

            elif msg_type == 'pdu':
                packet = ESB_Payload_Hdr(bytes(message.pdu.pdu))
                packet.metadata = generate_esb_metadata(message, msg_type)
                self.monitor_packet_rx(packet)
                return packet

        except AttributeError:
            return None

    def _build_message_from_scapy_packet(self, packet, channel=None, retransmission_count=15):
        msg = Message()

        self.monitor_packet_tx(packet)

        if ESB_Hdr in packet:
            msg.esb.send_raw.channel = channel if channel is not None else 0xFF
            packet.preamble = 0xAA
            # print(">", bytes(packet).hex())
            msg.esb.send_raw.pdu = bytes(packet)
            msg.esb.send_raw.retransmission_count = retransmission_count
        elif ESB_Payload_Hdr in packet:
            msg.esb.send.channel = channel if channel is not None else 0xFF
            msg.esb.send.pdu = bytes(packet)
            msg.esb.send.retransmission_count = retransmission_count

        else:
            msg = None
        return msg

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

    def can_send(self):
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Esb)
            self.__can_send = ((commands & (1 << Send))>0 or (commands & (1 << SendRaw)))
        return self.__can_send

    def send(self,pdu, address=None, channel=None, retransmission_count=15):
        """
        Send Enhanced ShockBurst packets (on a single channel).
        """
        if self.can_send():
            if self.support_raw_pdu():
                if ESB_Hdr not in pdu:
                    packet = ESB_Hdr(address) / packet
                else:
                    packet = pdu
            elif ESB_Hdr in pdu:
                packet = pdu[ESB_Payload_Hdr:]
            else:
                packet = pdu

            packet.metadata = ESBMetadata()
            packet.metadata.channel = self.__cached_channel if channel is None else channel
            packet.metadata.address = self.__cached_address if address is None else address

            msg = self._build_message_from_scapy_packet(packet, channel, retransmission_count)
            resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
            return (resp.generic.cmd_result.result == ResultCode.SUCCESS)

        else:
            return False
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
        self.__cached_channel = channel
        self.__cached_address = address

        try:
            msg.esb.sniff.address = bytes.fromhex(address.replace(":", ""))
        except ValueError:
            return False
        msg.esb.sniff.show_acknowledgements = show_acknowledgements
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_be_prx(self):
        """
        Determine if the device implements a Primary Receiver (PRX) role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << PrimaryReceiverMode)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def enable_prx_mode(self, channel):
        """
        Enable Enhanced ShockBurst primary receiver (PRX) mode.
        """
        if not self.can_be_prx():
            raise UnsupportedCapability("PrimaryReceiverMode")

        if channel is None:
            return False

        self.__cached_channel = channel
        msg = Message()
        msg.esb.prx.channel = channel
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_be_ptx(self):
        """
        Determine if the device implements a Primary Transmitter (PTX) role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << PrimaryTransmitterMode)) > 0 and
            (commands & (1 << Start))>0 and
            (commands & (1 << Stop))>0
        )

    def enable_ptx_mode(self, channel):
        """
        Enable Enhanced ShockBurst primary transmitter (PTX) mode.
        """
        if not self.can_be_prx():
            raise UnsupportedCapability("PrimaryTransmitterMode")

        self.__cached_channel = channel

        msg = Message()
        msg.esb.ptx.channel = channel if channel is not None else 0xFF
        resp = self.send_command(msg, message_filter('generic', 'cmd_result'))
        return (resp.generic.cmd_result.result == ResultCode.SUCCESS)


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << SetNodeAddress)) > 0
        )

    def set_node_address(self, address):
        """
        Enable Enhanced ShockBurst primary receiver (PRX) mode.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        msg = Message()
        self.__cached_address = address
        msg.esb.set_node_addr.address = bytes.fromhex(address.replace(":", ""))
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

    def on_discovery_msg(self, message):
        pass

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

        if ESB_Payload_Hdr in packet:
            pdu = packet[ESB_Payload_Hdr:]
        else:
            pdu = ESB_Payload_Hdr()/ESB_Ack_Response()
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        pass

from whad.esb.connector.sniffer import Sniffer
from whad.esb.connector.prx import PRX
from whad.esb.connector.ptx import PTX
