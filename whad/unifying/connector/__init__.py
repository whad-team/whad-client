from whad import WhadDomain, WhadCapability
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.hub.esb import ESBMetadata
#from whad.esb.connector.translator import ESBMessageTranslator
from whad.esb.esbaddr import ESBAddress
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet
from whad.scapy.layers.unifying import bind

from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.unifying import EsbNodeAddress, Commands, RawPduReceived, PduReceived, UnifyingMetadata

class Unifying(WhadDeviceConnector):
    """
    Logitech Unifying protocol connector.

    This connector drives a Logitech Unifying (ESB-based) capable device with Unifying-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "unifying"

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        return self.hub.unifying.format(packet)

    def __init__(self, device=None, synchronous=False):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).

        If `auto` is set to False, PDUs must be processed manually and
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

        # Check if device supports Logitech Unifying
        if not self.device.has_domain(WhadDomain.LogitechUnifying):
            raise UnsupportedDomain("Logitech Unifying")
        else:
            self.__ready = True
            bind()


        # Set synchronous mode
        self.enable_synchronous(synchronous)

    def close(self):
        self.stop()
        self.device.close()

    def can_sniff(self):
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
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
            commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
            self.__can_send = ((commands & (1 << Commands.Send))>0 or (commands & (1 << Commands.SendRaw)))
        return self.__can_send

    def send(self,pdu, address=None, channel=None, retransmission_count=1):
        """
        Send Logitech Unifying packets (on a single channel).
        """

        # Packet is not raw by default
        metadata = UnifyingMetadata()
        metadata.raw = False

        if not self.can_send():
            raise UnsupportedCapability("Send")
        # If we don't have address or channels, use the cached ones
        tx_address = address if address is not None else self.__cached_address
        tx_channel = channel if channel is not None else self.__cached_channel
        if self.support_raw_pdu():
            # If we support raw PDU but only got a payload, build a packet
            if ESB_Hdr not in pdu:
                packet = ESB_Hdr(address=tx_address) / pdu
            else:
                packet = pdu

            # Mark packet as raw
            metadata.raw = True

        # if we don't support raw PDU and got a packet, crop to keep only the payload
        elif ESB_Hdr in pdu:
            packet = pdu[ESB_Payload_Hdr:]
        # if we don't support raw PDU and got a payload, keep it as it is
        else:
            packet = pdu

        # Generate TX metadata
        packet.metadata = metadata
        packet.metadata.channel = tx_channel
        packet.metadata.address = tx_address

        if self.support_raw_pdu():
            # Set packet preamble depending on address
            if bytes.fromhex(packet.address[:2])[0] >= 0x80:
                packet.preamble = 0xAA
            else:
                packet.preamble = 0x55

        # Send packet
        ret = super().send_packet(packet)
        return ret

    def support_raw_pdu(self):
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(WhadDomain.LogitechUnifying)
            self.__can_send_raw = not (capabilities & WhadCapability.NoRawData)
        return self.__can_send_raw


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def sniff(self, channel=None, address="FF:FF:FF:FF:FF", show_acknowledgements=False):
        """
        Sniff Logitech Unifying packets.
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        self.__cached_address = ESBAddress(address)
        if channel is None:
            # Enable scanning mode
            channel = 0xFF
        else:
            self.__cached_channel = channel


        # Create a SniffMode message.
        msg = self.hub.unifying.create_sniff_mode(
            EsbNodeAddress(self.__cached_address.value),
            channel,
            show_acknowledgements
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_be_dongle(self):
        """
        Determine if the device implements a Logitech Dongle role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.LogitechDongleMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def enable_dongle_mode(self, channel):
        """
        Enable Logitech Unifying dongle mode.
        """
        if not self.can_be_dongle():
            raise UnsupportedCapability("LogitechDongleMode")

        if channel is None:
            return False

        # Keep track of channel
        self.__cached_channel = channel

        # Create a DongleMode message
        msg = self.hub.unifying.create_dongle_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_be_keyboard(self):
        """
        Determine if the device implements a Logitech Keyboard role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.LogitechKeyboardMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def enable_keyboard_mode(self, channel):
        """
        Enable Logitech Unifying Keyboard mode.
        """
        if not self.can_be_keyboard():
            raise UnsupportedCapability("LogitechKeyboardMode")

        if channel is None:
            # Enable scanning mode
            channel = 0xFF
        else:
            # Keep channel in cache
            self.__cached_channel = channel

        # Create a KeyboardMode message
        msg = self.hub.unifying.create_keyboard_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def can_be_mouse(self):
        """
        Determine if the device implements a Logitech Mouse role mode.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.LogitechMouseMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def enable_mouse_mode(self, channel):
        """
        Enable Logitech Unifying mouse mode.
        """
        if not self.can_be_mouse():
            raise UnsupportedCapability("LogitechMouseMode")

        if channel is None:
            # Enable scanning mode
            channel = 0xFF
        else:
            # Keep channel in cache
            self.__cached_channel = channel

        # Create a MouseMode message
        msg = self.hub.unifying.create_mouse_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_set_node_address(self):
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def set_node_address(self, address):
        """
        Select a specific node address.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        node_address = ESBAddress(address)
        # Keep address in cache
        self.__cached_address = node_address

        # Create a SetNodeAddress message.
        msg = self.hub.unifying.create_set_node_address(
            EsbNodeAddress(node_address.value)
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_sniff_pairing(self):
        """
        Determine if the device can follow a pairing procedure.
        """
        commands = self.device.get_domain_commands(WhadDomain.LogitechUnifying)
        return (
            (commands & (1 << Commands.SniffPairing)) > 0
        )


    def sniff_pairing(self):
        """
        Follow a pairing procedure.
        """
        if not self.can_sniff_pairing():
            raise UnsupportedCapability("SniffPairing")

        # Create a SniffPairing message.
        msg = self.hub.unifying.create_sniff_pairing()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def start(self):
        """
        Start currently enabled mode.
        """
        # Create a Start message.
        msg = self.hub.unifying.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self):
        """
        Stop currently enabled mode.
        """
        # Create a Stop message.
        msg = self.hub.unifying.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def on_discovery_msg(self, message):
        pass

    def on_generic_msg(self, message):
        pass

    def on_domain_msg(self, domain, message):
        pass

    def on_packet(self, packet):
        """Incoming packet handler.
        """
        if not self.__ready:
            return

        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    def on_event(self, event):
        """Incoming event handler.
        """
        pass

    def on_raw_pdu(self, packet):
        """Process incoming packet.
        """
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


from whad.unifying.connector.sniffer import Sniffer
from whad.unifying.connector.keylogger import Keylogger
from whad.unifying.connector.mouselogger import Mouselogger
from whad.unifying.connector.mouse import Mouse
from whad.unifying.connector.keyboard import Keyboard
from whad.unifying.connector.dongle import Dongle
from whad.unifying.connector.injector import Injector
