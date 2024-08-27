from scapy.packet import Packet

from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.esb.esbaddr import ESBAddress
from whad.hub.esb import ESBMetadata
from whad.scapy.layers.esb import ESB_Hdr,ESB_Payload_Hdr,ESB_Ack_Response
from whad.helpers import message_filter
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.hub.generic.cmdresult import Success
from whad.hub.esb import EsbNodeAddress, Commands
from whad.hub.events import JammedEvt


class ESB(WhadDeviceConnector):
    """
    Enhanced ShockBurst protocol connector.

    This connector drives a Enhanced ShockBurst (ESB) capable device with ESB-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """

    domain = "esb"

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        if isinstance(packet, bytes):
            packet = ESB_Hdr(packet)
        return self.hub.esb.format(packet)

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).

        If `synchronous` is set to True, PDUs must be processed manually and
        won't be forwarded to PDU-related callbacks.
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
            raise UnsupportedDomain("ESB")
        else:
            self.__ready = True

        # Set synchronous mode
        self.enable_synchronous(synchronous)

    def close(self):
        self.stop()
        self.device.close()

    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_send(self):
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(WhadDomain.Esb)
            self.__can_send = ((commands & (1 << Commands.Send))>0 or (commands & (1 << Commands.SendRaw)))
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
            packet.metadata.retransmission_count = retransmission_count
            if self.support_raw_pdu():
                packet.metadata.raw = True
                if bytes.fromhex(packet.address[:2])[0] >= 0x80:
                    packet.preamble = 0xAA
                else:
                    packet.preamble = 0x55

            # Send packet
            return super().send_packet(packet)
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
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def sniff(self, channel : int = None, address : str = "FF:FF:FF:FF:FF",
              show_acknowledgements : bool = False):
        """
        Sniff Enhanced ShockBurst packets.

        :param channel: Channel to listen, None to iterate over all possible channels
        :type channel: int
        :param address: Device address to target
        :type address: str
        :param show_acknowledgements: Sniff packets acknowledgements if set to True (default: False)
        :type show_acknowledgements: bool
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        self.__cached_address = ESBAddress(address)
        if channel is None:
            # Enable scanning mode
            channel = 0xFF
        else:
            self.__cached_channel = channel

        msg = self.hub.esb.create_sniff_mode(
            EsbNodeAddress(self.__cached_address.value),
            channel,
            show_acknowledgements
        )
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)



    def can_be_prx(self):
        """
        Determine if the device implements a Primary Receiver (PRX) role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << Commands.PrimaryReceiverMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
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

        # Create a PrxMode message.
        msg = self.hub.esb.create_prx_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_be_ptx(self):
        """
        Determine if the device implements a Primary Transmitter (PTX) role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << Commands.PrimaryTransmitterMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def enable_ptx_mode(self, channel):
        """
        Enable Enhanced ShockBurst primary transmitter (PTX) mode.
        """
        if not self.can_be_ptx():
            raise UnsupportedCapability("PrimaryTransmitterMode")


        if channel is None:
            # Enable scanning mode
            channel = 0xFF
        else:
            # Keep channel in cache
            self.__cached_channel = channel

        # Create a PtxMode message.
        msg = self.hub.esb.create_ptx_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.Esb)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
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

        # Create a SetNodeAddress message
        msg = self.hub.esb.create_set_node_address(
            EsbNodeAddress(node_address.value)
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def start(self):
        """
        Start currently enabled mode.
        """
        # Create a Start message.
        msg = self.hub.esb.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        # Create a Stop message.
        msg = self.hub.esb.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def on_discovery_msg(self, message):
        pass

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        pass

    def on_packet(self, packet):
        """Incoming packet callback.
        """
        if not self.__ready:
            return

        # Dispatch packet
        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    def on_event(self, event):
        """Process incoming events.
        """
        if not self.__ready:
            return

        if isinstance(event, JammedEvt):
            self.on_jammed(event.timestamp)

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

    def on_jammed(self, timestamp: int):
        """Jammed event handler.
        """
        pass

from whad.esb.connector.scanner import Scanner
from whad.esb.connector.sniffer import Sniffer
from whad.esb.connector.prx import PRX
from whad.esb.connector.ptx import PTX
