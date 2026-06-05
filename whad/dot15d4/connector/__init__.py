import logging
from typing import Union, Tuple

# packaging
from packaging.version import Version

# Scapy imports
from scapy.packet import Packet, Raw
from scapy.compat import raw
from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4 as Dot15d4NoFCS
from scapy.layers.dot15d4 import Dot15d4FCS

from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr
from whad.hub.dot15d4 import Dot15d4Metadata
# Main whad imports
from whad.scapy.layers.dot15d4tap import Dot15d4Raw
from whad.hub.discovery import Domain, Capability
from whad.cli.app import CommandLineApp
from whad.device.connector import Connector
from whad.helpers import message_filter, is_message_type
from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.dot15d4.utils.phy import ChannelMap
from whad.dot15d4.utils.tsch import Network, Superframe, Link

# WHAD Protocol hub
from whad.hub.generic.cmdresult import Success, CommandResult
from whad.hub.dot15d4 import NodeAddress, Commands, NodeAddressType, PduReceived, \
    RawPduReceived, EnergyDetectionSample, LinkOptions, LinkType
from whad.hub.events import JammedEvt
logger = logging.getLogger(__name__)

class Dot15d4(Connector):
    """
    802.15.4 protocol connector.

    This connector drives a 802.15.4-capable device with 802.15.4-specific WHAD messages.
    It is required by various role classes to interact with a real device and pre-process
    domain-specific messages.
    """
    domain = "dot15d4"

    def __init__(self, device=None, synchronous=False, scapy_config='zigbee'):
        """
        Initialize the connector, open the device (if not already opened), discover
        the services (if not already discovered).
        """
        self.__ready = False
        super().__init__(device)

        # Capability cache
        self.__can_send = None
        self.__can_send_raw = None

        # TSCH mode cache
        self.__can_use_tsch = None

        # TSCH Links and superframes
        self.__tsch_network = Network()
        
        # Open device and make sure it is compatible
        self.device.open()
        self.device.discover()

        # Display a warning message if ButteRFly version is less than 1.0.2 as
        # a critical bug has been found and fixed in version 1.0.2. FCS values
        # will be wrong if using a version prior to 1.0.2.
        if device.info.fw_url == "https://github.com/whad-team/butterfly":
            if Version(device.info.version_str) < Version("1.0.2"):
                message = ((
                    "You are using a ButteRFly version prior to 1.0.2 that does not correctly compute FCS values, "
                    "this will result in invalid FCS values in packets and PCAP files that may cause errors when "
                    "used with other WHAD tools. Please consider upgrading firmware to the latest version "
                    "(see https://github.com/whad-team/butterfly). "
                    "You can also use `winstall --flash butterfly` to reprogram your USB dongle."
                ))

                # Use application warning method if available
                app = CommandLineApp.get_instance()
                if app is not None:
                    app.warning(message)
                else:
                    # If not available, use basic logging capabilities
                    logger.warning(message)

        # Check if device supports 802.15.4
        if not self.device.has_domain(Domain.Dot15d4):
            raise UnsupportedDomain("IEEE 802.15.4")
        else:
            self.__ready = True
            conf.dot15d4_protocol = scapy_config

        self.enable_synchronous(synchronous)

    def close(self):
        """
        Close the connector and the underlying device.
        """
        self.stop()
        self.device.close()

    def format(self, packet:Union[Dot15d4NoFCS,Dot15d4FCS]) -> Tuple[Dot15d4TAP_Hdr, int]:
        """
        Format a packet using the underlying translator.
        """
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)
        return self.hub.dot15d4.format(packet)

    def can_sniff(self) -> bool:
        """
        Determine if the device implements a sniffer mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.Sniff)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def can_set_node_address(self) -> bool:
        """
        Determine if the device can configure a Node address.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.SetNodeAddress)) > 0
        )

    def can_be_end_device(self) -> bool:
        """
        Determine if the device implements an End Device role mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.EndDeviceMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def can_use_tsch(self) -> bool:
        """
        Determine if the device implements Time-Slotted Channel Hopping.
        """
        if self.__can_use_tsch is None:
            commands = self.device.get_domain_commands(Domain.Dot15d4)

            self.__can_use_tsch = (
                (commands & (1 << Commands.ConfigureTSCH)) > 0 and
                (commands & (1 << Commands.AddLink)) > 0 and
                (commands & (1 << Commands.DeleteLink)) > 0 and
                (commands & (1 << Commands.UpdateSuperframe)) > 0 and
                (commands & (1 << Commands.DeleteSuperframe)) > 0 and
                (commands & (1 << Commands.DeleteSuperframe)) > 0 and
                (commands & (1 << Commands.SetChannelMap)) > 0 and
                (commands & (1 << Commands.SendInSlot)) > 0
            )
        return self.__can_use_tsch

    def can_send(self) -> bool:
        """
        Determine if the device can transmit packets.
        """
        if self.__can_send is None:
            commands = self.device.get_domain_commands(Domain.Dot15d4)
            self.__can_send = ((commands & (1 << Commands.Send)) > 0 or (commands & (1 << Commands.SendRaw)) > 0)
        return self.__can_send

    def can_perform_ed_scan(self) -> bool:
        """
        Determine if the device can perform energy detection scan.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.EnergyDetection)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )

    def support_raw_pdu(self) -> bool:
        """
        Determine if the device supports raw PDU.
        """
        if self.__can_send_raw is None:
            capabilities = self.device.get_domain_capability(Domain.Dot15d4)
            self.__can_send_raw = not (capabilities & Capability.NoRawData)
        return self.__can_send_raw

    def sniff_dot15d4(self, channel:int = 11) -> bool:
        """
        Sniff 802.15.4 packets (on a single channel).
        """
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

        # Create a SniffMode message
        msg = self.hub.dot15d4.create_sniff_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_node_address(self, address:int, mode:NodeAddressType = NodeAddressType.SHORT) -> bool:
        """
        Modify 802.15.4 node address.
        """
        if not self.can_set_node_address():
            raise UnsupportedCapability("SetNodeAddress")

        # Create node address from parameters
        node_addr = NodeAddress(address, mode)

        # Create a SetNodAddress message
        msg = self.hub.dot15d4.create_set_node_address(node_addr)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def set_end_device_mode(self, channel:int = 11) -> bool:
        """
        Acts as a 802.15.4 End Device.
        """
        if not self.can_be_end_device():
            raise UnsupportedCapability("EndDevice")

        # Create EndDeviceMode message
        msg = self.hub.dot15d4.create_end_device_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)


    def can_be_coordinator(self) -> bool:
        """
        Determine if the device implements a Coordinator role mode.
        """
        commands = self.device.get_domain_commands(Domain.Dot15d4)
        return (
            (commands & (1 << Commands.CoordinatorMode)) > 0 and
            (commands & (1 << Commands.Start))>0 and
            (commands & (1 << Commands.Stop))>0
        )


    def set_coordinator_mode(self, channel:int = 11) -> bool:
        """
        Acts as a 802.15.4 Coordinator.
        """
        if not self.can_be_coordinator():
            raise UnsupportedCapability("Coordinator")

        # Create EndDeviceMode message
        msg = self.hub.dot15d4.create_coord_mode(channel)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def send(self, pdu: Union[Packet, bytes, Dot15d4NoFCS, Dot15d4FCS], channel:int = 11) -> bool:
        """
        Send 802.15.4 packets (on a single channel).

        :param pdu: 802.15.4 packet to send
        :type pdu: scapy.layers.dot15d4.Dot15d4, scapy.layers.dot15d4.Dot15d4FCS
        :param channel: Channel on which the packet has to be sent
        :type channel: int
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            metadata = Dot15d4Metadata()
            metadata.raw = False
            metadata.channel = channel

            # If PDU is provided as bytes, wrap it into a Raw packet
            if isinstance(pdu, bytes):
                pdu = Raw(pdu)

            if self.support_raw_pdu():
                metadata.raw = True

                if Dot15d4FCS not in pdu:
                    # Compute FCS if required by the hardware
                    packet = Dot15d4FCS(raw(pdu) + Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu

            elif Dot15d4FCS in pdu:
                # Remove FCS if hardware cannot set it
                packet = Dot15d4NoFCS(raw(pdu)[:-2])
            else:
                packet = pdu

            if hasattr(packet, "reserved"):
                packet.reserved = packet.reserved

            # Set metadata
            packet.metadata = metadata
            # Send packet
            return super().send_packet(packet)
        else:
            return False


    def send_mac(self, pdu: bytes, channel: int = 11, add_fcs: bool = False):
        """
        Send raw 802.15.4 packets (on a single channel).

        :param pdu: 802.15.4 packet to send
        :type pdu: bytes
        :param channel: Channel on which the packet has to be sent
        :type channel: int
        :param add_fcs: Add FCS field if set to `True`
        :type add_fcs: bool
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send():
            # If raw mode is supported by the hardware, handle FCS value
            if self.support_raw_pdu():
                # Enable raw mode
                raw_mode = True

                # Add FCS if required
                if add_fcs:
                    fcs = Dot15d4FCS().compute_fcs(bytes(pdu))
                    packet = Dot15d4Raw(pdu + fcs)
                else:
                    packet = Dot15d4Raw(pdu)
            else:
                # Disable raw mode
                raw_mode = False

                # Cannot add/remove FCS, let hardware generate it
                logger.debug((
                    "[dot15d4::send_mac()] cannot add or remove FCS because HW"
                    "does not support raw packets, rollback to classic 802.15.4"
                    "frames with valid FCS."
                ))
                packet = Dot15d4Raw(pdu)

            # Add Dot15d4 metadata
            packet.metadata = Dot15d4Metadata()
            packet.metadata.raw = raw_mode
            packet.metadata.channel = channel

            # Send packet
            return super().send_packet(packet)

        # Failed at sending packet.
        return False


    def send_in_slot(self, pdu: Union[Packet, bytes, Dot15d4NoFCS, Dot15d4FCS], slot : int = 0xFFFFFFFF, wait_offset : int = 2200) -> bool:
        """
        Send 802.15.4 packet on a given time slot.

        :param pdu: 802.15.4 packet to send
        :type pdu: scapy.layers.dot15d4.Dot15d4, scapy.layers.dot15d4.Dot15d4FCS
        :param slot: Time slot where the packet should be transferred
        :type slot: int
        :param wait_offset: Duration before transmission of the frame (from the start of slot)
        :type wait_offset: int
        :return: `True` if packet has been correctly sent, `False` otherwise.
        :rtype: bool
        """
        if self.can_send() and self.can_use_tsch():
            metadata = Dot15d4Metadata()
            metadata.raw = False
            #metadata.channel = channel

            # If PDU is provided as bytes, wrap it into a Raw packet
            if isinstance(pdu, bytes):
                pdu = Raw(pdu)

            if self.support_raw_pdu():
                metadata.raw = True

                if Dot15d4FCS not in pdu:
                    # Compute FCS if required by the hardware
                    packet = Dot15d4FCS(raw(pdu) + Dot15d4FCS().compute_fcs(raw(pdu)))
                else:
                    packet = pdu

            elif Dot15d4FCS in pdu:
                # Remove FCS if hardware cannot set it
                packet = Dot15d4NoFCS(raw(pdu)[:-2])
            else:
                packet = pdu

            if hasattr(packet, "reserved"):
                packet.reserved = packet.reserved

            # Set metadata
            packet.metadata = metadata
            
            # Create a SendInSlotPdu message
            msg = self.hub.dot15d4.create_send_in_slot_pdu(
                slot=slot, 
                wait_offset=wait_offset,
                pdu=bytes(packet)
            )
            
            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)

        else:
            return False

    def perform_ed_scan(self, channel:int = 11) -> bool:
        """
        Perform an Energy Detection scan.
        """
        if self.can_perform_ed_scan():
            # Create an EnergyDetectionMode message
            msg = self.hub.dot15d4.create_energy_detection_mode(channel)

            resp = self.send_command(msg, message_filter(CommandResult))
            return isinstance(resp, Success)
        else:
            return False

    def start(self) -> bool:
        """
        Start currently enabled mode.
        """
        # Create a Start message
        msg = self.hub.dot15d4.create_start()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def stop(self) -> bool:
        """
        Stop currently enabled mode.
        """
        # Create a Stop message
        msg = self.hub.dot15d4.create_stop()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    def enable_tsch(self) -> bool:
        """
        Enable Time-Slotted Channel Hopping mode.
        
        :return: Boolean indicating if the TSCH mode has been successfully enabled.
        :rtype: `bool`
        """
        
        if not self.can_use_tsch():
            return False


        # Create a ConfigureTSCH message
        msg = self.hub.dot15d4.create_config_tsch(enabled=True)

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)
        
    def disable_tsch(self) -> bool:
        """
        Disable Time-Slotted Channel Hopping mode.
        
        :return: Boolean indicating if the TSCH mode has been successfully disabled.
        :rtype: `bool`
        """
        if not self.can_use_tsch():
            return False

        # Create a ConfigureTSCH message
        msg = self.hub.dot15d4.create_config_tsch(enabled=False)
        
        self.__tsch_network.clear()

        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)
        
    def add_link(self, superframe_id: int, source: int, time_slot: int, \
            channel_offset: int, neighbor: int, options: LinkOptions, \
            link_type : LinkType) -> bool:
        """Add a new TSCH link, associated with an existing superframe.
        If a link already exists, it must be deleted prior to executing this command. 

        :param superframe_id: Identifier of the associated superframe
        :type superframe_id: int
        :param source: Source address associated with the link
        :type source: int
        :param time_slot:Time slot of the link to add
        :type time_slot: int
        :param channel_offset: Channel Offset associated with the link to add
        :type channel_offset: int
        :param neighbor: Neighbor address associated with the link
        :type neighbor: int
        :param options: Options of the link to add
        :type options: `LinkOptions`
        :param link_type: Type of the link to add
        :type link_type: `LinkType`
        :return: Boolean indicating if the link has been successfully added
        :rtype: `bool`
        """
        if not self.can_use_tsch():
            return False
            
        
        # Create a AddLink message
        msg = self.hub.dot15d4.create_add_link(
            superframe_id,
            source,
            time_slot,
            channel_offset,
            neighbor,
            options,
            link_type
        )
        resp = self.send_command(msg, message_filter(CommandResult))

        if isinstance(resp, Success):
            self.__tsch_network.add_link(superframe_id, source, time_slot, channel_offset, neighbor, options, link_type)
            print(self.network)
            return True

        return False

    def delete_link(self, superframe_id: int,time_slot: int, channel_offset: int) -> bool:
        """Delete an existing TSCH link, associated with an existing superframe.

        :param superframe_id: Identifier of the associated superframe
        :type superframe_id: int
        :param time_slot:Time slot of the link to delete
        :type time_slot: int
        :param channel_offset: Channel Offset associated with the link to delete
        :type channel_offset: int
        :return: Boolean indicating if the link has been successfully deleted
        :rtype: `bool`
        """
        if not self.can_use_tsch():
            return False

        # Create a DelLink message
        msg = self.hub.dot15d4.create_del_link(
            superframe_id=superframe_id, 
            channel_offset=channel_offset, 
            time_slot=time_slot
        )
        resp = self.send_command(msg, message_filter(CommandResult))
        if isinstance(resp, Success):
            self.__tsch_network.remove_link(superframe_id, time_slot, channel_offset)
            return True
        return False
        
    def update_superframe(self, superframe_id: int, number_of_slots: int, flags: int, asn: int) -> bool:
        """
        Add or update a TSCH superframe.

        :param superframe_id: Identifier of the superframe
        :type superframe_id: int
        :param number_of_slots: Number of slots available in the superframe
        :type number_of_slots: int
        :param flags: Flags associated with the superframe
        :type flags: int
        :param asn: Absolute Slot Number indicating the superframe addition or update
        :type asn: int
        :return: boolean indicating if the operation was successful
        :rtype: bool
        """
        if not self.can_use_tsch():
            return False

        msg = self.hub.dot15d4.create_update_superframe(
            superframe_id = superframe_id, 
            number_of_slots = number_of_slots, 
            flags = flags,
            asn = asn
        )
        resp = self.send_command(msg, message_filter(CommandResult))
        if isinstance(resp, Success):
            self.__tsch_network.add_or_update_superframe(superframe_id, number_of_slots, flags, asn)
            return True
        return False


    def delete_superframe(self, superframe_id: int) -> bool:
        """
        Delete a TSCH superframe.

        :param superframe_id: Identifier of the superframe
        :type superframe_id: int
        :return: boolean indicating if the operation was successful
        :rtype: bool
        """
        if not self.can_use_tsch():
            return False

        msg = self.hub.dot15d4.create_delete_superframe(
            superframe_id = superframe_id
        )
        resp = self.send_command(msg, message_filter(CommandResult))
        if isinstance(resp, Success):
            self.__tsch_network.remove_superframe(superframe_id)
            return True
            
        return False
        
    def set_channel_map(self, channels : Union[list, int, bytes, ChannelMap] = [11]) -> bool:
        """
        Configure the TSCH channel map.

        :param channels: Channel map to use
        :type channels: Union[list, int, bytes, `ChannelMap`]
        :return: boolean indicating if the operation was successful
        :rtype: bool
        """
        if not self.can_use_tsch():
            return False

        if isinstance(channels, ChannelMap):
            channel_map = channels
        else:
            try:
                channel_map = ChannelMap(channels=channels)
            except ValueError as e:
                # Invalid channel map
                return False
        
        msg = self.hub.dot15d4.create_set_channel_map(
            channel_map = channel_map.value
        )
        resp = self.send_command(msg, message_filter(CommandResult))
        return isinstance(resp, Success)

    @property
    def network(self) -> Network:
        """
        Return a TSCH Network (if available)
        """
        return self.__tsch_network
        
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

        assert domain == "dot15d4"
        if isinstance(message, EnergyDetectionSample):
            self.on_ed_sample(message.timestamp, message.sample)

    def on_packet(self, packet):
        """Dot15d4 packet dispatch.
        """
        if not self.__ready:
            return

        if self.can_use_tsch() and hasattr(packet.metadata, 'asn'):
            self.__tsch_network.asn = packet.metadata.asn
            print("Update: ", self.__tsch_network.asn)

        # Dispatch packet.
        if packet.metadata.raw:
            self.on_raw_pdu(packet)
        else:
            self.on_pdu(packet)

    def on_event(self, event):
        """Dot15d4 event dispatch.
        """
        if not self.__ready:
            return

        if isinstance(event, JammedEvt):
            self.on_jammed(event.timestamp)

    def on_raw_pdu(self, packet):
        """
        Raw PDU processing (Dot15d4FCS).
        """
        # Ugly hack but we need a forced rebuild in specific cases...
        if hasattr(packet, "reserved"):
            packet.reserved = packet.reserved

        pdu = Dot15d4NoFCS(packet.do_build()[:-2])
        pdu.metadata = packet.metadata
        self.on_pdu(pdu)

    def on_pdu(self, packet):
        """
        Normal PDU processing (Dot15d4).
        """
        # Enqueue PDU if in synchronous mode
        if self.is_synchronous():
            self.add_pending_packet(packet)
        else:
            pass

    def on_ed_sample(self, timestamp, sample):
        """
        Energy Detection sample processing.
        """
        pass

    def on_jammed(self, timestamp: int):
        """Jammed event handler.
        """
        pass

from whad.dot15d4.connector.sniffer import Sniffer
from whad.dot15d4.connector.enddevice import EndDevice
from whad.dot15d4.connector.coordinator import Coordinator

__all__ = [
    "Dot15d4",
    "Sniffer",
    "EndDevice",
    "Coordinator"
]
