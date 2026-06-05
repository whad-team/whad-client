"""WHAD Protocol 802.15.4 domain message abstraction layer.
"""
from typing import List
from dataclasses import dataclass, field, fields
from enum import IntEnum

from scapy.config import conf
from scapy.layers.dot15d4 import Dot15d4FCS

from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr,\
    Dot15d4TAP_Received_Signal_Strength, Dot15d4TAP_Channel_Assignment, \
    Dot15d4TAP_Channel_Center_Frequency, Dot15d4TAP_Link_Quality_Indicator, \
    Dot15d4TAP_FCS_Type, Dot15d4TAP_Absolute_Slot_Number, Dot15d4TAP_Start_Of_Slot_Timestamp, \
    Dot15d4TAP_Timeslot_Length, Dot15d4TAP_Channel_Plan

from whad.protocol.dot15d4.dot15d4_pb2 import Dot15d4MitmRole, AddressType, \
    LinkType as Dot15d4LinkType, LinkOptions as Dot15d4LinkOptions
from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub.metadata import Metadata, channel_to_frequency
from whad.hub import ProtocolHub

import logging

logger = logging.getLogger(__name__)

class Commands:
    """Dot15d4 commands
    """
    SetNodeAddress          = 0x00
    Sniff                   = 0x01
    Jam                     = 0x02
    EnergyDetection         = 0x03
    Send                    = 0x04
    SendRaw                 = 0x05
    EndDeviceMode           = 0x06
    CoordinatorMode         = 0x07
    RouterMode              = 0x08
    Start                   = 0x09
    Stop                    = 0x0a
    ManInTheMiddle          = 0x0b
    ConfigureTSCH           = 0x0c
    SendInSlot              = 0x0d
    AddLink                 = 0x0e
    DeleteLink              = 0x0f
    UpdateSuperframe        = 0x10
    DeleteSuperframe        = 0x11
    SetChannelMap           = 0x12
    
class MitmRole:
    """Dot15d4 Mitm role
    """
    REACTIVE=Dot15d4MitmRole.REACTIVE_JAMMER
    CORRECTOR=Dot15d4MitmRole.CORRECTOR

class NodeAddressType:
    """IEEE 802.15.4 Node address type enum.
    """
    SHORT=AddressType.SHORT
    EXTENDED=AddressType.EXTENDED


class LinkOptions(IntEnum):
    """Dot15d4 TSCH Link Options
    """
    UNKNOWN = Dot15d4LinkOptions.UNKNOWN
    SHARED = Dot15d4LinkOptions.SHARED
    RECEIVE = Dot15d4LinkOptions.RECEIVE
    TRANSMIT = Dot15d4LinkOptions.TRANSMIT
    
class LinkType(IntEnum):
    """Dot15d4 TSCH Link Type
    """
    NORMAL = Dot15d4LinkType.NORMAL
    DISCOVERY = Dot15d4LinkType.DISCOVERY
    BROADCAST = Dot15d4LinkType.BROADCAST
    JOIN = Dot15d4LinkType.JOIN


class NodeAddress(object):
    """IEEE 802.15.4 Node address.
    """

    def __init__(self, address: int, addr_type: int):
        self.__address = address
        self.__address_type = addr_type

    @property
    def address(self) -> int:
        """Node address"""
        return self.__address

    @property
    def address_type(self) -> int:
        """Address type"""
        return self.__address_type

class NodeAddressShort(NodeAddress):
    """Dot15d4 short node address

    This class reprensents a short 802.15.4 node address (16 bits)
    """

    def __init__(self, address: int):
        """Initialize a node short address.
        """
        assert address >= 0
        assert address < 0x10000
        super().__init__(address, NodeAddressType.SHORT)

class NodeAddressExt(NodeAddress):
    """Dot15d4 extended node address

    This class represents an extended 802.15.4 node address (64 bits).
    """

    def __init__(self, address: int):
        """Initialize a node extended address.

        :param address: a 64-bit node address
        """
        assert address >= 0
        assert address <= 0x10000000000000000
        super().__init__(address, NodeAddressType.EXTENDED)


@dataclass(repr=False)
class Dot15d4Metadata(Metadata):
    """Dot15d4 meta-data holding class.
    """
    is_fcs_valid : bool = None
    lqi : int = None
    timestamp : int = None

    asn : int = None
    start_of_slot_timestamp : int = None
    time_slot : int = None
    base_channel_frequency : int = None
    number_of_channels : int = None
    channel_spacing : int = None

    def convert_to_header(self) -> Dot15d4TAP_Hdr:
        """Convert stored metadata into a Scapy Dot15d4TAP_Hdr instance.

        :return: Scapy header for 802.15.4 packet
        :rtype: Dot15d4TAP_Hdr
        """
        timestamp = None
        tlv = []
        if self.timestamp is not None:
            timestamp = self.timestamp
        if self.rssi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Received_Signal_Strength(rss = self.rssi))
        if self.lqi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Link_Quality_Indicator(lqi = self.lqi))
        if self.channel is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Assignment(channel_number=self.channel,
                                                                          channel_page=0))
            channel_frequency = channel_to_frequency(self.channel) * 1000
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Center_Frequency(channel_frequency=channel_frequency))

        if self.asn is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Absolute_Slot_Number(absolute_slot_number=self.asn))
        if self.start_of_slot_timestamp is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Start_Of_Slot_Timestamp(timestamp=self.start_of_slot_timestamp))
        if self.time_slot is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Timeslot_Length(timeslot_length=self.time_slot))
        if self.base_channel_frequency is not None and self.number_of_channels is not None and self.channel_spacing is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Plan(base_channel_frequency=self.base_channel_frequency, 
                                                                    number_of_channels=self.number_of_channels, 
                                                                    channel_spacing=self.channel_spacing))
        return Dot15d4TAP_Hdr(data=tlv), timestamp

    @classmethod
    def convert_from_header(cls, pkt) -> "Dot15d4Metadata":
        """Load metadata from packet header into a Dot15d4Metadata structure
        """
        # Default values for DLTs that do not have any metadata.
        rssi = 0
        lqi = 200
        channel = 15

        asn = None
        start_of_slot_timestamp = None
        time_slot  = None
        base_channel_frequency = None
        number_of_channels = None
        channel_spacing = None
        # Packets from PCAP with DLT 283 (IEEE 802.15.4 TAP)
        # Other DLTs don't have any metadata about RSSI, LQI or channel.
        if Dot15d4TAP_Hdr in pkt:
            for layer in pkt[Dot15d4TAP_Hdr].data:
                if Dot15d4TAP_Received_Signal_Strength in layer:
                    rssi = layer.rss
                elif Dot15d4TAP_Link_Quality_Indicator in layer:
                    lqi = layer.lqi
                elif Dot15d4TAP_Channel_Assignment in layer:
                    channel = layer.channel_number
                elif Dot15d4TAP_Absolute_Slot_Number in layer:
                    asn = layer.absolute_slot_number
                elif Dot15d4TAP_Start_Of_Slot_Timestamp in layer:
                    start_of_slot_timestamp = layer.timestamp
                elif Dot15d4TAP_Timeslot_Length in layer:
                    time_slot = layer.timeslot_length
                elif Dot15d4TAP_Channel_Plan in layer:
                    base_channel_frequency =int(layer.base_channel_frequency)
                    number_of_channels = int(layer.number_of_channels)
                    channel_spacing = int(layer.channel_spacing)
                else:
                    pass

        return Dot15d4Metadata(
            rssi = int(rssi),
            lqi = lqi,
            channel = channel,
            timestamp = int(100000 * pkt.time), 
            asn = asn, 
            start_of_slot_timestamp = start_of_slot_timestamp,
            time_slot = time_slot, 
            base_channel_frequency = base_channel_frequency, 
            number_of_channels = number_of_channels, 
            channel_spacing = channel_spacing
        )

def generate_dot15d4_metadata(message: HubMessage) -> Dot15d4Metadata:
    """Generate a Dot15d4Metadata object from a WHAD message.
    """
    metadata = Dot15d4Metadata()
    
    if message.lqi is not None:
        metadata.lqi = message.lqi
    if message.rssi is not None:
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.timestamp is not None:
        metadata.timestamp = message.timestamp
    if message.fcs_validity is not None:
        metadata.is_fcs_valid = message.fcs_validity
    if message.asn is not None:
        metadata.asn = message.asn
    if message.time_slot is not None:
        metadata.time_slot = message.time_slot
    if message.start_of_slot_timestamp is not None:
        metadata.start_of_slot_timestamp = message.start_of_slot_timestamp
    if message.base_channel_frequency is not None:
        metadata.base_channel_frequency = message.base_channel_frequency
    if message.channel_spacing is not None:
        metadata.channel_spacing = message.channel_spacing
    if message.number_of_channels is not None:
        metadata.number_of_channels = message.number_of_channels
    return metadata

@pb_bind(ProtocolHub, name="dot15d4", version=1)
class Dot15d4Domain(Registry):
    """WHAD Dot15d4 domain messages parser/factory.
    """

    NAME = 'dot15d4'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a Dot15d4 domain instance
        """
        self.proto_version = version

    def is_packet_compat(self, packet) -> bool:
        """Determine if a packet is a Dot15d4 packet.
        """
        return isinstance(packet.metadata, Dot15d4Metadata)

    def convert_packet(self, packet) -> HubMessage:
        """Convert a Dot15d4 packet to SendPdu or SendBlePdu message.
        """
        if isinstance(packet.metadata, Dot15d4Metadata):
            if packet.metadata.raw:
                return Dot15d4Domain.bound('send_raw', self.proto_version).from_packet(
                    packet, channel=packet.metadata.channel
                )
            else:
                return Dot15d4Domain.bound('send', self.proto_version).from_packet(
                    packet, channel=packet.metadata.channel
                )
        else:
            # Error
            return None

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
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

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD Dot15d4 Domain message as seen by protobuf
        """
        message_type = message.dot15d4.WhichOneof('msg')
        message_clazz = Dot15d4Domain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)

    def create_set_node_address(self, address: NodeAddress) -> HubMessage:
        """Create a SetNodeAddress message.

        :param address: instance of `Dot15d4Address`
        :type address: NodeAddress
        :return: instance of `SetNodeAddress`
        """
        return Dot15d4Domain.build('set_node_addr', self.proto_version,
            address=address.address,
            addr_type=address.address_type
        )

    def create_sniff_mode(self, channel: int) -> HubMessage:
        """Create a SniffMode message

        :param channel: Channel to sniff
        :type channel: int
        :return: instance of `SniffMode`
        """
        return Dot15d4Domain.build('sniff', self.proto_version,
            channel=channel
        )

    def create_jam_mode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: Channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return Dot15d4Domain.build('jam', self.proto_version,
            channel=channel
        )

    def create_energy_detection_mode(self, channel: int) -> HubMessage:
        """Create a EnergyDetectionMode message

        :param channel: Channel to detect
        :type channel: int
        :return: instance of `EnergyDetectionMode`
        """
        return Dot15d4Domain.build('ed', self.proto_version,
            channel=channel
        )

    def create_end_device_mode(self, channel: int) -> HubMessage:
        """Create a EndDeviceMode message

        :param channel: Channel to use for end device
        :type channel: int
        :return: instance of `EndDeviceMode`
        """
        return Dot15d4Domain.build('end_device', self.proto_version,
            channel=channel
        )

    def create_router_mode(self, channel: int) -> HubMessage:
        """Create a RouterMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `RouterMode`
        """
        return Dot15d4Domain.build('router', self.proto_version,
            channel=channel
        )

    def create_coord_mode(self, channel: int) -> HubMessage:
        """Create a CoordMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `CoordMode`
        """
        return Dot15d4Domain.build('coordinator', self.proto_version,
            channel=channel
        )

    def create_mitm_mode(self, role: int) -> HubMessage:
        """Create a MitmMode message

        :return: instance of `MitmMode`
        """
        return Dot15d4Domain.build('mitm', self.proto_version,
            role=role
        )

    def create_start(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start`
        """
        return Dot15d4Domain.build('start', self.proto_version)

    def create_stop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop`
        """
        return Dot15d4Domain.build('stop', self.proto_version)

    def create_send_pdu(self, channel: int, pdu: bytes) -> HubMessage:
        """Create a SendPdu message

        :param channel: Channel on which the PDU has to be sent
        :type channel: int
        :param pdu: PDU to send
        :type pdu: bytes
        :return: instance of `SendPdu`
        """
        return Dot15d4Domain.build('send', self.proto_version,
            channel=channel,
            pdu=pdu
        )

    def create_send_raw_pdu(self, channel: int, pdu: bytes, fcs: int) -> HubMessage:
        """Create a SendPdu message

        :param channel: Channel on which the PDU has to be sent
        :type channel: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param fcs: Frame check sequence
        :type fcs: int
        :return: instance of `SendPdu`
        """
        return Dot15d4Domain.build('send_raw', self.proto_version,
            channel=channel,
            pdu=pdu,
            fcs=fcs
        )


    def create_send_in_slot_pdu(self, slot: int, wait_offset : int, pdu: bytes) -> HubMessage:
        """Create a SendInSlotPdu message

        :param slot: Slot to use for transmission
        :type slot: int
        :param wait_offset: Offset before PDU transmission after slot start
        :type wait_offset: int
        :param pdu: PDU to send
        :type pdu: bytes
        :return: instance of `SendPdu`
        """
        return Dot15d4Domain.bound('send_in_slot', self.proto_version)(
            slot=slot,
            wait_offset=wait_offset,
            pdu=pdu
        )

    def create_jammed(self, timestamp: int) -> HubMessage:
        """Create a jammed notification.

        :param timestamp: Timestamp when jamming is successful
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return Dot15d4Domain.build('jammed', self.proto_version,
            timestamp=timestamp
        )

    def create_energy_detection_sample(self, timestamp: int, sample: int) -> HubMessage:
        """Create an energy detection sample notification message.

        :param timestamp: Timestamp at wich the sample has been computed
        :type timestamp: int
        :param sample: Computed sample
        :type sample: int
        :return: instance of `EnergyDetectionSample`
        """
        return Dot15d4Domain.build('ed_sample', self.proto_version,
            timestamp=timestamp,
            sample=sample
        )

    def create_raw_pdu_received(self, channel: int, pdu: bytes, fcs: int, rssi: int = None, \
                             timestamp: int = None, fcs_validity: bool = None, \
                             lqi: int = None):
        """Create a received PDU notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param fcs: Frame Check Sequence
        :type fcs: int
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the PDU has been received
        :type timestamp: int, optional
        :param fcs_validity: Specify if the FCS field is valid or not
        :type fcs_validity: bool, optional
        :param lqi: Link Quality indicator
        :type lqi: int, optional
        :return: instance of `RawPduReceived`
        """
        # Create our RawPduReceived message with mandatory fields
        msg = Dot15d4Domain.build('raw_pdu', self.proto_version,
            channel=channel,
            pdu=pdu,
            fcs=fcs
        )

        # Add optional fields if they are provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if fcs_validity is not None:
            msg.fcs_validity = fcs_validity
        if lqi is not None:
            msg.lqi = lqi

        # Return the generated message
        return msg

    def create_pdu_received(self, channel: int, pdu: bytes, rssi: int = None, \
                             timestamp: int = None, fcs_validity: bool = None, \
                             lqi: int = None):
        """Create a received PDU notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the PDU has been received
        :type timestamp: int, optional
        :param fcs_validity: Specify if the FCS field is valid or not
        :type fcs_validity: bool, optional
        :param lqi: Link Quality indicator
        :type lqi: int, optional
        :return: instance of `RawPduReceived`
        """
        # Create our PduReceived message with mandatory fields
        msg = Dot15d4Domain.build('pdu', self.proto_version,
            channel=channel,
            pdu=pdu,
        )

        # Add optional fields if they are provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if fcs_validity is not None:
            msg.fcs_validity = fcs_validity
        if lqi is not None:
            msg.lqi = lqi

        # Return the generated message
        return msg


    def create_config_tsch(self, enabled : bool) -> HubMessage:
        """Create a Configure TSCH message.

        :param enabled: Boolean indicating if TSCH must be enabled
        :type enabled: bool
        :return: instance of `ConfigureTSCH`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")
            
        return Dot15d4Domain.bound('config_tsch', self.proto_version)(
            enabled=enabled
        )


    def create_add_link(self,superframe_id: int, source: int, time_slot: int, \
                             channel_offset: int, neighbor: int, options: LinkOptions, \
                             link_type : LinkType) -> HubMessage:
        """Create a Add Link message.

        :param superframe_id: Identifier of the associated superframe
        :type superframe_id: int
        :param source: Source address of the link
        :type source: int
        :param time_slot: Time slot associated with the link
        :type time_slot: int        
        :param channel_offset: Channel offset associated with the link
        :type channel_offset: int
        :param neighbor: Neighbor address associated with the link
        :type neighbor: int
        :param options: Options of the link
        :type options: `LinkOptions`
        :param link_type: Type of the link
        :type link_type: `LinkType`
        :return: instance of `AddLink`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")
            

        if source < 0 or source > 0xFFFF: 
            logger.error("invalid source address, must be between 0 & 0xFFFF (16-bit short format).")
            raise ValueError()


        if neighbor < 0 or neighbor > 0xFFFF: 
            logger.error("invalid neighbor address, must be between 0 & 0xFFFF (16-bit short format).")
            raise ValueError()

        if not isinstance(link_type, (LinkType,int)):
            logger.error("invalid Link Type provided")
            
        if not isinstance(options,(LinkOptions,int)):
            logger.error("invalid Link Options provided")

        return Dot15d4Domain.bound('add_link', self.proto_version)(
            superframe_id=superframe_id, 
            src=source, 
            time_slot=time_slot, 
            channel_offset=channel_offset, 
            neighbor=neighbor, 
            options=options, 
            link_type=link_type
        )

    def create_del_link(self,superframe_id: int, time_slot: int, channel_offset: int)-> HubMessage:
        """Create a Delete Link message.

        :param superframe_id: Identifier of the associated superframe
        :type superframe_id: int
        :param time_slot: Time slot associated with the link to delete
        :type time_slot: int
        :param channel_offset: Channel offset associated with the link to delete
        :type channel_offset: int
        :return: instance of `DeleteLink`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")


        if neighbor < 0 or neighbor > 0xFFFF: 
            logger.error("invalid neighbor address, must be between 0 & 0xFFFF (16-bit short format).")
            raise ValueError()
  
        return Dot15d4Domain.bound('del_link', self.proto_version)(
            superframe_id=superframe_id, 
            offset=offset, 
            neighbor=neighbor
        )
        

    def create_update_superframe(self,superframe_id: int, number_of_slots: int, \
                             flags: int, asn: int) -> HubMessage:
        """Create an Update Superframe message.

        :param superframe_id: Identifier of the associated superframe
        :type superframe_id: int
        :param number_of_slots: Number of slots available in the superframe
        :type number_of_slots: int
        :param flags: Flags associated with the superframe
        :type flags: int        
        :param asn: Absolute Slot Number starting the superframe update or addition
        :type asn: int
        :return: instance of `UpdateSuperframe`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")
            
        return Dot15d4Domain.bound('update_superframe', self.proto_version)(
            superframe_id=superframe_id, 
            number_of_slots=number_of_slots, 
            flags=flags, 
            asn=asn
        )


    def create_delete_superframe(self,superframe_id: int) -> HubMessage:
        """Create a Delete Superframe message.

        :param superframe_id: Identifier of the superframe to delete
        :type superframe_id: int
        :return: instance of `DeleteSuperframe`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")
            
        return Dot15d4Domain.bound('delete_superframe', self.proto_version)(
            superframe_id=superframe_id
        )

    def create_set_channel_map(self,channel_map: int) -> HubMessage:
        """Create a Set Channel Map message.

        :param channel_map: Bitmap of enabled channels in TSCH mode
        :type channel_map: int
        :return: instance of `SetChannelMap`
        """
        if self.proto_version < 3:
            logger.warning("[core::hub::dot15d4] TSCH mode not supported by this hardware !")
            
        return Dot15d4Domain.bound('set_chm', self.proto_version)(
            channel_map=channel_map
        )
        
@pb_bind(ProtocolHub, name="wihart", version=3)
class WirelessHartDomain(Dot15d4Domain):
    NAME = 'wihart'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a Wireless Hart domain instance
        """
        super().__init__(version)
        conf.dot15d4_protocol = "wihart"

    
    def create_raw_pdu_received(self, channel: int, pdu: bytes, fcs: int, rssi: int = None, \
                             timestamp: int = None, fcs_validity: bool = None, \
                             lqi: int = None, asn: int = None, start_of_slot_timestamp : int = None, \
                             time_slot: int = None, base_channel_frequency : int = None, \
                             number_of_channels : int = None, channel_spacing : int = None):
        """Create a received PDU notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param fcs: Frame Check Sequence
        :type fcs: int
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the PDU has been received
        :type timestamp: int, optional
        :param fcs_validity: Specify if the FCS field is valid or not
        :type fcs_validity: bool, optional
        :param lqi: Link Quality indicator
        :type lqi: int, optional
        :param asn: Absolute Slot Number
        :type asn: int, optional
        :param start_of_slot_timestamp: Timestamp of the slot start
        :type start_of_slot_timestamp: int, optional
        :param time_slot: Duration of a time slot (in us)
        :type time_slot: int, optional
        :param base_channel_frequency: Base channel frequency of the Channel Map
        :type base_channel_frequency: int, optional
        :param number_of_channels: Number of channels in the Channel Map
        :type number_of_channels: int, optional
        :param channel_spacing: Channel spacing, in Hz
        :type channel_spacing: int, optional
        :return: instance of `RawPduReceived`
        """
        # Create our RawPduReceived message with mandatory fields
        msg = Dot15d4Domain.bound('raw_pdu', self.proto_version)(
            channel=channel,
            pdu=pdu,
            fcs=fcs
        )

        # Add optional fields if they are provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if fcs_validity is not None:
            msg.fcs_validity = fcs_validity
        if lqi is not None:
            msg.lqi = lqi
        if asn is not None:
            msg.asn = asn
        if start_of_slot_timestamp is not None:
            msg.start_of_slot_timestamp = start_of_slot_timestamp
        if time_slot is not None:
            msg.time_slot = time_slot
        if base_channel_frequency is not None:
            msg.base_channel_frequency = base_channel_frequency
        if number_of_channels is not None:
            msg.number_of_channels = number_of_channels
        if channel_spacing is not None:
            msg.channel_spacing = channel_spacing
        # Return the generated message
        return msg

    def create_pdu_received(self, channel: int, pdu: bytes, rssi: int = None, \
                             timestamp: int = None, fcs_validity: bool = None, \
                             lqi: int = None, asn: int = None, start_of_slot_timestamp : int = None, \
                             time_slot: int = None, base_channel_frequency : int = None, \
                             number_of_channels : int = None, channel_spacing : int = None):
        """Create a received PDU notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the PDU has been received
        :type timestamp: int, optional
        :param fcs_validity: Specify if the FCS field is valid or not
        :type fcs_validity: bool, optional
        :param lqi: Link Quality indicator
        :type lqi: int, optional
        :return: instance of `RawPduReceived`
        """
        # Create our PduReceived message with mandatory fields
        msg = Dot15d4Domain.bound('pdu', self.proto_version)(
            channel=channel,
            pdu=pdu,
        )

        # Add optional fields if they are provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if fcs_validity is not None:
            msg.fcs_validity = fcs_validity
        if lqi is not None:
            msg.lqi = lqi
        if asn is not None:
            msg.asn = asn
        if start_of_slot_timestamp is not None:
            msg.start_of_slot_timestamp = start_of_slot_timestamp
        if time_slot is not None:
            msg.time_slot = time_slot
        if base_channel_frequency is not None:
            msg.base_channel_frequency = base_channel_frequency
        if number_of_channels is not None:
            msg.number_of_channels = number_of_channels
        if channel_spacing is not None:
            msg.channel_spacing = channel_spacing

        # Return the generated message
        return msg
    
@pb_bind(ProtocolHub, name="rf4ce", version=1)
class RF4CEDomain(Dot15d4Domain):
    NAME = 'rf4ce'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a RF4CE domain instance
        """
        super().__init__(version)
        conf.dot15d4_protocol = "rf4ce"


@pb_bind(ProtocolHub, name="zigbee", version=1)
class ZigBeeDomain(Dot15d4Domain):
    NAME = 'zigbee'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a ZigBee domain instance
        """
        super().__init__(version)
        conf.dot15d4_protocol = "zigbee"


from .address import SetNodeAddress
from .mode import SniffMode, RouterMode, EndDeviceMode, CoordMode, EnergyDetectionMode, \
    JamMode, MitmMode, Start, Stop, Jammed, EnergyDetectionSample
from .tsch import ConfigureTSCH, AddLink, DeleteLink, UpdateSuperframe, DeleteSuperframe, \
    SetChannelMap
from .pdu import SendPdu, SendRawPdu, SendInSlotPdu, PduReceived, RawPduReceived,  \
    DiscoveredCommunication, RawPduReceivedV3, PduReceivedV3

__all__ = [
    'SetNodeAddress',
    'SniffMode',
    'RouterMode',
    'EndDeviceMode',
    'CoordMode',
    'EnergyDetectionMode',
    'JamMode',
    'MitmMode',
    'Start',
    'Stop',
    'SendPdu',
    'SendRawPdu',
    'PduReceived',
    'DiscoveredCommunication',
    'RawPduReceived',
    'SendInSlotPdu',
    'ConfigureTSCH',
    'AddLink',
    'DeleteLink',
    'UpdateSuperframe', 
    'DeleteSuperframe', 
    'SetChannelMap',
    'Jammed',
    'EnergyDetectionSample',
    'Dot15d4Domain',
    'NodeAddress',
    'NodeAddressShort',
    'NodeAddressExt',
    'NodeAddressType',
    'LinkType', 
    'LinkOptions',

    'MitmRole'
]
