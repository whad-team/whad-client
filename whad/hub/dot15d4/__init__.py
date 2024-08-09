"""WHAD Protocol 802.15.4 domain message abstraction layer.
"""
from typing import List
from dataclasses import dataclass, field, fields

from scapy.layers.dot15d4 import Dot15d4FCS
from whad.scapy.layers.rf4ce import RF4CE_Hdr
from scapy.config import conf
from whad.protocol.dot15d4.dot15d4_pb2 import Dot15d4MitmRole, AddressType
from whad.scapy.layers.dot15d4tap import Dot15d4TAP_Hdr, Dot15d4TAP_TLV_Hdr,\
    Dot15d4TAP_Received_Signal_Strength, Dot15d4TAP_Channel_Assignment, \
    Dot15d4TAP_Channel_Center_Frequency, Dot15d4TAP_Link_Quality_Indicator, \
    Dot15d4TAP_FCS_Type
from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.metadata import Metadata, channel_to_frequency

class Commands:
    """Dot15d4 commands
    """
    SetNodeAddress = 0x00
    Sniff = 0x01
    Jam = 0x02
    EnergyDetection = 0x03
    Send = 0x04
    SendRaw = 0x05
    EndDeviceMode = 0x06
    CoordinatorMode = 0x07
    RouterMode = 0x08
    Start = 0x09
    Stop = 0x0a
    ManInTheMiddle = 0x0b

class MitmRole:
    """Dot15d4 Mitm role
    """
    REACTIVE=Dot15d4MitmRole.REACTIVE_JAMMER
    CORRECTOR=Dot15d4MitmRole.CORRECTOR

class NodeAddressType:
    SHORT=AddressType.SHORT
    EXTENDED=AddressType.EXTENDED

class NodeAddress(object):

    def __init__(self, address: int, addr_type: int):
        self.__address = address
        self.__address_type = addr_type

    @property
    def address(self):
        return self.__address

    @property
    def address_type(self):
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
    is_fcs_valid : bool = None
    lqi : int = None
    timestamp : int = None

    def convert_to_header(self):
        timestamp = None
        tlv = []
        if self.timestamp is not None:
            timestamp = self.timestamp
        if self.rssi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Received_Signal_Strength(rss = self.rssi))
        if self.lqi is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Link_Quality_Indicator(lqi = self.lqi))
        if self.channel is not None:
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Assignment(channel_number=self.channel, channel_page=0))
            channel_frequency = channel_to_frequency(self.channel) * 1000
            tlv.append(Dot15d4TAP_TLV_Hdr()/Dot15d4TAP_Channel_Center_Frequency(channel_frequency=channel_frequency))
        return Dot15d4TAP_Hdr(data=tlv), timestamp

    @classmethod
    def convert_from_header(cls, pkt):
        rssi = None
        lqi = None
        channel = None
        for layer in pkt[Dot15d4TAP_Hdr].data:
            if Dot15d4TAP_Received_Signal_Strength in layer:
                rssi = layer.rss
            elif Dot15d4TAP_Link_Quality_Indicator in layer:
                lqi = layer.lqi
            elif Dot15d4TAP_Channel_Assignment in layer:
                channel = layer.channel_number
            else:
                pass
        return Dot15d4Metadata(
            rssi = int(rssi),
            lqi = lqi,
            channel = channel,
            timestamp = int(100000 * pkt.time)
        )

def generate_dot15d4_metadata(message):
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
        return Dot15d4Domain.bound('set_node_addr', self.proto_version)(
            address=address.address,
            addr_type=address.address_type
        )

    def create_sniff_mode(self, channel: int) -> HubMessage:
        """Create a SniffMode message

        :param channel: Channel to sniff
        :type channel: int
        :return: instance of `SniffMode`
        """
        return Dot15d4Domain.bound('sniff', self.proto_version)(
            channel=channel
        )

    def create_jam_mode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: Channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return Dot15d4Domain.bound('jam', self.proto_version)(
            channel=channel
        )

    def create_energy_detection_mode(self, channel: int) -> HubMessage:
        """Create a EnergyDetectionMode message

        :param channel: Channel to detect
        :type channel: int
        :return: instance of `EnergyDetectionMode`
        """
        return Dot15d4Domain.bound('ed', self.proto_version)(
            channel=channel
        )

    def create_end_device_mode(self, channel: int) -> HubMessage:
        """Create a EndDeviceMode message

        :param channel: Channel to use for end device
        :type channel: int
        :return: instance of `EndDeviceMode`
        """
        return Dot15d4Domain.bound('end_device', self.proto_version)(
            channel=channel
        )

    def create_router_mode(self, channel: int) -> HubMessage:
        """Create a RouterMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `RouterMode`
        """
        return Dot15d4Domain.bound('router', self.proto_version)(
            channel=channel
        )

    def create_coord_mode(self, channel: int) -> HubMessage:
        """Create a CoordMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `CoordMode`
        """
        return Dot15d4Domain.bound('coordinator', self.proto_version)(
            channel=channel
        )

    def create_mitm_mode(self, role: int) -> HubMessage:
        """Create a MitmMode message

        :return: instance of `MitmMode`
        """
        return Dot15d4Domain.bound('mitm', self.proto_version)(
            role=role
        )

    def create_start(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start`
        """
        return Dot15d4Domain.bound('start', self.proto_version)()

    def create_stop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop`
        """
        return Dot15d4Domain.bound('stop', self.proto_version)()

    def create_send_pdu(self, channel: int, pdu: bytes) -> HubMessage:
        """Create a SendPdu message

        :param channel: Channel on which the PDU has to be sent
        :type channel: int
        :param pdu: PDU to send
        :type pdu: bytes
        :return: instance of `SendPdu`
        """
        return Dot15d4Domain.bound('send', self.proto_version)(
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
        return Dot15d4Domain.bound('send_raw', self.proto_version)(
            channel=channel,
            pdu=pdu,
            fcs=fcs
        )

    def create_jammed(self, timestamp: int) -> HubMessage:
        """Create a jammed notification.

        :param timestamp: Timestamp when jamming is successful
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return Dot15d4Domain.bound('jammed', self.proto_version)(
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
        return Dot15d4Domain.bound('ed_sample', self.proto_version)(
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
from .pdu import SendPdu, SendRawPdu, PduReceived, RawPduReceived

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
    'RawPduReceived',
    'Jammed',
    'EnergyDetectionSample',
    'Dot15d4Domain',
    'NodeAddress',
    'NodeAddressShort',
    'NodeAddressExt',
    'NodeAddressType',
    'MitmRole'
]
