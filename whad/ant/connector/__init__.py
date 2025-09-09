import logging
from typing import Union, Tuple

# packaging
from packaging.version import Version

# scapy imports
from whad.scapy.layers.ant import ANT_Hdr

# Main whad imports
from whad.device import WhadDeviceConnector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability

# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.discovery import Domain, Capability
from whad.hub.ant import Commands, AvailableChannels, AvailableNetworks, \
    ChannelType, ANTMetadata, ChannelEvent, ChannelEventCode

# ANT-specific imports
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.ant.channel import ChannelDirection

logger = logging.getLogger(__name__)

class ANT(WhadDeviceConnector):
    """
    ANT protocol connector.

    This connector drives an ANT-capable device with ANT-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "ant"

    def __init__(self, device=None, synchronous=False):
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

        # Check if device supports ANT
        if not self.device.has_domain(Domain.ANT):
            raise UnsupportedDomain("ANT")
        else:
            self.__ready = True

        self.enable_synchronous(synchronous)

    def close(self):
        """
        Close the connector and the underlying device.
        """
        self.stop()
        self.device.close()


    def format(self, packet:Union[bytes, ANT_Hdr]) -> Tuple[ANT_Hdr, int]:
        """
        Format a packet using the underlying translator.
        """
        if isinstance(packet, bytes):
            packet = ANT_Hdr(packet)
        return self.hub.ant.format(packet)
        
    def can_sniff(self) -> bool:
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(Domain.ANT)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def can_manage_channels(self) -> bool:
        """
        Determine if the device can manage channels.
        """
        commands = self.device.get_domain_commands(Domain.ANT)
        return (
            (commands & (1 << Commands.AssignChannel)) > 0 and
            (commands & (1 << Commands.UnassignChannel)) > 0 and
            (commands & (1 << Commands.OpenChannel))>0 and
            (commands & (1 << Commands.CloseChannel))>0 and
            (commands & (1 << Commands.SetDeviceNumber))>0 and
            (commands & (1 << Commands.SetDeviceType))>0 and
            (commands & (1 << Commands.SetTransmissionType))>0 and
            (commands & (1 << Commands.SetNetworkKey))>0 and
            (commands & (1 << Commands.SetRFChannel))>0
        )


    def can_list_channels(self) -> bool:
        """
        Determine if the device can list available channels.
        """
        commands = self.device.get_domain_commands(Domain.ANT)
        return (
            (commands & (1 << Commands.ListChannels)) > 0
        )

    def can_list_networks(self) -> bool:
        """
        Determine if the device can list available networks.
        """
        commands = self.device.get_domain_commands(Domain.ANT)
        return (
            (commands & (1 << Commands.ListNetworks)) > 0
        )

    def can_send(self) -> bool:
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(Domain.ANT)
            self.__can_send = ((commands & (1 << Commands.Send)) > 0 or (commands & (1 << Commands.SendRaw)) > 0)
        return self.__can_send


    def support_raw_pdu(self) -> bool:
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(Domain.ANT)
            self.__can_send_raw = not (capabilities & Capability.NoRawData)
        return self.__can_send_raw

    def start(self) -> bool:
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.ant.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self) -> bool:
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.ant.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def list_channels(self) -> bool:
        """
        List the available channels.
        """
        # Check if channels listing is available
        if not self.can_list_channels():
            raise UnsupportedCapability("ListChannels")

        # Create a ListChannels message
        msg = self.hub.ant.create_list_channels()

        # Get the notification and returns the max number of channels
        resp = self.send_command(msg, message_filter(AvailableChannels))
        return resp.number_of_channels

    def list_networks(self) -> bool:
        """
        List the available networks.
        """
        # Check if networks listing is available
        if not self.can_list_networks():
            raise UnsupportedCapability("ListNetworks")

        # Create a ListNetworks message
        msg = self.hub.ant.create_list_networks()

        # Get the notification and returns the max number of networks
        resp = self.send_command(msg, message_filter(AvailableNetworks))
        return resp.number_of_networks


    def sniff_ant(
                    self, 
                    device_number : int, 
                    device_type : int, 
                    transmission_type : int,
                    network_key : bytes = ANT_PLUS_NETWORK_KEY, 
                    rf_channel : int = 57
    ) -> bool:
        """
        Sniff ANT packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        # Create a SniffMode message
        msg = self.hub.ant.create_sniff(
            rf_channel = rf_channel , 
            network_key = network_key, 
            device_number = device_number, 
            device_type = device_type, 
            transmission_type = transmission_type
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)



    def open_channel(self, channel_number : int) -> bool:
        """
        Open an ANT channel.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_open_channel(
            channel_number = channel_number 
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def close_channel(self, channel_number : int) -> bool:
        """
        Close an ANT channel.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_close_channel(
            channel_number = channel_number 
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)



    def set_device_number(self, channel_number : int, device_number : int) -> bool:
        """
        Configure an ANT channel with a given device number.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_device_number(
            channel_number = channel_number, 
            device_number = device_number
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)



    def set_transmission_type(self, channel_number : int, transmission_type : int) -> bool:
        """
        Configure an ANT channel with a given transmission type.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_transmission_type(
            channel_number = channel_number, 
            transmission_type = transmission_type
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)



    def set_rf_channel(self, channel_number : int, rf_channel : int) -> bool:
        """
        Configure an ANT channel with a given RF channel.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_rf_channel(
            channel_number = channel_number, 
            rf_channel = rf_channel
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def set_network_key(self, network_number : int, network_key : bytes) -> bool:
        """
        Configure an ANT network with a given Network Key.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_network_key(
            network_number = network_number, 
            network_key = network_key
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_device_type(self, channel_number : int, device_type : int) -> bool:
        """
        Configure an ANT channel with a given device type.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_device_type(
            channel_number = channel_number, 
            device_type = device_type
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def set_channel_period(self, channel_number : int, period : int) -> bool:
        """
        Configure an ANT channel with a given channel period.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_set_channel_period(
            channel_number = channel_number, 
            channel_period = period
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def unassign_channel(self, channel_number : int) -> bool:
        """
        Unassign an ANT channel.
        """
        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        # Create a SniffMode message
        msg = self.hub.ant.create_unassign_channel(
            channel_number = channel_number 
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def assign_channel(
            self,
            channel_number : int, 
            network_number : int, 
            direction : ChannelDirection = ChannelDirection.RX, 
            unidirectional : bool = False, 
            shared : bool = False, 
            background_scanning : bool = True
    ) -> bool:
        """
        Assign an ANT channel.
        """

        if not self.can_manage_channels():
            raise UnsupportedCapability("ChannelManagement")

        if direction == ChannelDirection.RX:
            mode = "SLAVE"
            if shared:
                channel_type = ChannelType.SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL
            elif unidirectional:
                channel_type = ChannelType.RECEIVE_ONLY_CHANNEL
            else:
                channel_type = ChannelType.BIDIRECTIONAL_RECEIVE_CHANNEL
        else:
            mode = "MASTER"

            if shared:
                channel_type = ChannelType.SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL
            elif unidirectional:
                channel_type = ChannelType.TRANSMIT_ONLY_CHANNEL
            else:
                channel_type = ChannelType.BIDIRECTIONAL_TRANSMIT_CHANNEL

        # Create a SniffMode message
        msg = self.hub.ant.create_assign_channel(
            channel_number = channel_number, 
            network_number = network_number,
            channel_type = channel_type , 
            background_scanning =background_scanning
        )

        resp = self.send_command(msg, message_filter(CommandResult))
        if isinstance(resp, Success):
            if mode == "MASTER":
                msg = self.hub.ant.create_master_mode(channel_number = channel_number)
            else:
                msg = self.hub.ant.create_slave_mode(channel_number = channel_number)
            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return False


    def send(self, pdu: bytes, channel_number: int = 0, rf_channel: int = None, add_crc : bool = False):
        """
        Send ANT packets (on a single channel).

        :param pdu: ANT packet to send
        :type pdu: bytes
        :param channel_number: (Logical) channel on which the packet has to be sent
        :type channel_number: int
        :param rf_channel: Send the packet on a specific RF channel (priority over the logical channel)
        :type rf_channel: int
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            # If raw mode is supported by the hardware, handle FCS value
            if self.support_raw_pdu():
                # Enable raw mode
                raw_mode = True

                # Add CRC if required
                if add_crc:
                    packet = ANT_Hdr(bytes(pdu))
                    packet.crc_present = 1
                    packet.crc = None
                else:
                    packet = ANT_Hdr(bytes(pdu))
            else:
                # Disable raw mode
                raw_mode = False

                # Cannot add/remove FCS, let hardware generate it
                logger.debug((
                    "[ant::send()] cannot add or remove CRC because HW"
                    "does not support raw packets, rollback to classic ANT"
                    "frames with valid CRC."
                ))
                packet = ANT_Hdr(bytes(pdu))

            # Add Dot15d4 metadata
            packet.metadata = ANTMetadata()
            packet.metadata.raw = raw_mode
            packet.metadata.channel_number = channel_number
            if rf_channel is not None:
                packet.metadata.rf_channel = rf_channel

            # Send packet
            return super().send_packet(packet)

        # Failed at sending packet.
        return False

    def on_generic_msg(self, message):
        """
        Generic message handler.
        """

    def on_discovery_msg(self, message):
        """
        Discovery message handler.
        """

    def on_domain_msg(self, domain:str, message):
        """
        Domain message handler. Dispatches domain message to processing methods.
        """
        if not self.__ready:
            return
        if isinstance(message, ChannelEvent):
            self.on_channel_event(message.channel_number, message.event)

    def on_channel_event(self, channel_number:int, event:ChannelEventCode):
        """
        Channel event handler.
        """
        pass

    def on_packet(self, packet):
        """ANT packet dispatch.
        """
        if not self.__ready:
            return

        # Dispatch packet.
        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    
    def on_raw_pdu(self, packet):
        """
        Raw PDU processing (ANT_Hdr).
        """
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        """
        Normal PDU processing (???).
        """
        print(packet.metadata)
        packet.show()
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_packet(packet)
        else:
            pass

    def on_event(self, event):
        """ANT event dispatch.
        """
        if not self.__ready:
            return


from whad.ant.connector.sniffer import Sniffer
from whad.ant.connector.master import Master
from whad.ant.connector.slave import Slave
