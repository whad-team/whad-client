from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.esb.connector.translator import ESBMessageTranslator
from whad.esb.esbaddr import ESBAddress
from whad.esb.metadata import ESBMetadata
from whad.scapy.layers.esb import ESB_Hdr,ESB_Payload_Hdr,ESB_Ack_Response
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
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

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return self.translator.format(packet)

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

        # Initialize translator
        self.translator = ESBMessageTranslator()

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

    def send(self,pdu, address=None, channel=None, retransmission_count=1):
        """
        Send Enhanced ShockBurst packets (on a single channel).
        """
        if self.can_send():
            # If we don't have address or channels, use the cached ones
            tx_address = address if address is not None else self.__cached_address
            tx_channel = channel if channel is not None else self.__cached_channel
            if self.support_raw_pdu():
                # If we support raw PDU but only got a payload, build a packet
                if ESB_Hdr not in pdu:
                    packet = ESB_Hdr(address=tx_address) / pdu
                else:
                    packet = pdu
            # if we don't support raw PDU and got a packet, crop to keep only the payload
            elif ESB_Hdr in pdu:
                packet = pdu[ESB_Payload_Hdr:]
            # if we don't support raw PDU and got a payload, keep it as it is
            else:
                packet = pdu

            # Generate TX metadata
            packet.metadata = ESBMetadata()
            packet.metadata.channel = tx_channel
            packet.metadata.address = tx_address

            self.monitor_packet_tx(packet)
            msg = self.translator.from_packet(packet, channel, retransmission_count)
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

    def sniff(self, channel=None, address="FF:FF:FF:FF:FF", show_acknowledgements=False):
        """
        Sniff Enhanced ShockBurst packets.
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")


        msg = Message()
        self.__cached_address = ESBAddress(address)
        if channel is None:
            # Enable scanning mode
            msg.esb.sniff.channel = 0xFF
        else:
            self.__cached_channel = channel
            msg.esb.sniff.channel = self.__cached_channel

        msg.esb.sniff.address = self.__cached_address.value
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

        # Check that we got a channel provided
        if channel is None:
            return False

        # Keep provided channel in cache
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
        if not self.can_be_ptx():
            raise UnsupportedCapability("PrimaryTransmitterMode")

        msg = Message()
        if channel is None:
            # Enable scanning mode
            msg.esb.ptx.channel = 0xFF
        else:
            # Keep channel in cache
            self.__cached_channel = channel
            msg.esb.ptx.channel = self.__cached_channel
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

        node_address = ESBAddress(address)
        # Keep address in cache
        self.__cached_address = node_address

        msg = Message()
        msg.esb.set_node_addr.address = node_address.value
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
                packet = self.translator.from_message(message, msg_type)
                self.monitor_packet_rx(packet)
                self.on_pdu(packet)

            elif msg_type == 'raw_pdu':
                packet = self.translator.from_message(message, msg_type)
                self.monitor_packet_rx(packet)
                self.on_raw_pdu(packet)


    def on_raw_pdu(self, packet):
        # Extract the PDU from raw packet
        if ESB_Payload_Hdr in packet:
            pdu = packet[ESB_Payload_Hdr:]
        else:
            pdu = ESB_Payload_Hdr()/ESB_Ack_Response()

        # Propagate metadata to PDU
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        pass

from whad.esb.connector.scanner import Scanner
from whad.esb.connector.sniffer import Sniffer
from whad.esb.connector.prx import PRX
from whad.esb.connector.ptx import PTX
