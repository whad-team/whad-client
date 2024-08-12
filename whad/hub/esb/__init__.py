"""WHAD Protocol ESB domain message abstraction layer.
"""
from typing import List, Union
from dataclasses import dataclass, field, fields

from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, \
    ESB_Pseudo_Packet

from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.metadata import Metadata

class Commands:
    """ESB Commands
    """
    SetNodeAddress = 0x00
    Sniff = 0x01
    Jam = 0x02
    Send = 0x03
    SendRaw = 0x04
    PrimaryReceiverMode = 0x05
    PrimaryTransmitterMode = 0x06
    Start = 0x07
    Stop = 0x08

class EsbNodeAddressError(Exception):
    def __init__(self, message=''):
        super().__init__()
        self.__message = message

    def __repr__(self):
        return f'EsbNodeAddressError({self.__message})'

class EsbNodeAddress(object):
    """ESB node address

    This class is used to represent an ESB node address:

    >>> addr = EsbNodeAddress(0x1122334455, 5)
    >>> print(addr.value)
    >>> addr2 = EsbNodeAddress(bytes(0x11, 0x22, 0x33, 0x44, 0x55))
    >>> print(addr2.value)
    """

    def __init__(self, address: Union[str, bytes, int], address_size: int = 0):
        """Initialize our node address

        :param address: ESB node address
        :type address: bytes, int
        :param address_size: Node address size (1-5)
        :type address_size: int, optional
        """
        self.__address = None
        if isinstance(address, str):
            self.__address = bytes([int(i, 16) for i in address.split(":")])
        elif isinstance(address, bytes):
            if len(address) >= 1 and len(address) <= 5:
                self.__address = address
            else:
                raise EsbNodeAddressError('address size must be between 1 and 5 bytes long')
        elif isinstance(address, int) and address_size >= 1 and address_size <= 5:
            try:
                self.__address = address.to_bytes(address_size, 'big')
            except OverflowError as overflow_err:
                raise EsbNodeAddressError('address size must be big enough to hold address') from overflow_err
        else:
            raise EsbNodeAddressError('address must be provided as an array of bytes or an integer')

    @property
    def value(self) -> bytes:
        """Retrieve the address value (bytes)
        """
        return self.__address


    def __eq__(self, other) -> bool:
        """Compare two ESB node addresses
        """
        return self.value == other.value


@dataclass(repr=False)
class ESBMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None
    timestamp : int = None

    def convert_to_header(self):
        return None, self.timestamp

    @classmethod
    def convert_from_header(cls, pkt):
        metadata = ESBMetadata()
        pkt = ESB_Hdr(bytes(pkt))
        metadata.address = EsbNodeAddress(pkt.address)
        metadata.is_crc_valid = pkt.valid_crc
        metadata.timestamp = int(100000 * pkt.time)
        metadata.channel = 0
        return metadata

def generate_esb_metadata(message):
    metadata = ESBMetadata()

    if message.rssi is not None:
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.timestamp is not None:
        metadata.timestamp = message.timestamp
    if message.crc_validity is not None:
        metadata.is_crc_valid = message.crc_validity
    if message.address is not None:
        metadata.address = ":".join(["{:02x}".format(i) for i in message.address])
    return metadata

@pb_bind(ProtocolHub, name="esb", version=1)
class EsbDomain(Registry):
    """WHAD ESB domain messages parser/factory.
    """

    NAME = 'esb'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a ESB domain instance
        """
        self.proto_version = version
        from whad.scapy.layers.unifying import unbind
        unbind()

    def is_packet_compat(self, packet) -> bool:
        """Determine if a packet is an ESB packet.
        """
        return isinstance(packet.metadata, ESBMetadata)

    def convert_packet(self, packet) -> HubMessage:
        """Convert an ESB packet to SendPdu or SendBlePdu message.
        """
        if isinstance(packet.metadata, ESBMetadata):
            if packet.metadata.raw:
                return EsbDomain.bound('send_raw', self.proto_version).from_packet(
                    packet
                )
            else:
                return EsbDomain.bound('send', self.proto_version).from_packet(
                    packet
                )
        else:
            # Error
            return None

    def format(self, packet):
        """
        Converts a scapy packet with its metadata to a tuple containing a scapy packet with
        the appropriate header and the timestamp in microseconds.
        """
        if ESB_Hdr not in packet:
            if hasattr(packet, "metadata") and hasattr(packet.metadata, "address"):
                address = packet.metadata.address
            else:
                address = "11:22:33:44:55"

            packet = ESB_Hdr(address = address)/packet

        packet.preamble = 0xAA # force a rebuild
        formatted_packet = ESB_Pseudo_Packet(bytes(packet))

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD ESB Domain message as seen by protobuf
        """
        message_type = message.esb.WhichOneof('msg')
        message_clazz = EsbDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)


    def create_set_node_address(self, node_address: EsbNodeAddress) -> HubMessage:
        """Create a SetNodeAddress message

        :param node_address: Node address to set (size must be 1-5 bytes)
        :type node_address: EsbNodeAddress
        :return: instance of `SetNodeAddress`
        """
        return EsbDomain.bound('set_node_addr', self.proto_version)(
            address=node_address.value
        )

    def create_start(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start` message
        """
        return EsbDomain.bound('start', self.proto_version)()


    def create_stop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop` message
        """
        return EsbDomain.bound('stop', self.proto_version)()


    def create_jam_mode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: ESB channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return EsbDomain.bound('jam', self.proto_version)(
            channel=channel
        )

    def create_sniff_mode(self, address: EsbNodeAddress, channel: int = 0xFF, show_acks: bool = False) -> HubMessage:
        """Create a SniffMode message

        :param address: Node address to filter
        :type address: EsbNodeAddress
        :param channel: Channel to sniff
        :type channel: int, optional
        :param show_acks: show acknowledgements
        :type show_acks: bool, optional
        :return: instance of `SniffMode`
        """
        return EsbDomain.bound('sniff', self.proto_version)(
            address=address.value,
            channel=channel,
            show_acks=show_acks
        )

    def create_jammed(self, timestamp: int):
        """Create a Jammed notification message

        :param timestamp: Timestamp at which the jamming has succeeded
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return EsbDomain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )

    def create_prx_mode(self, channel: int) -> HubMessage:
        """Create PrxMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `PrxMode`
        """
        return EsbDomain.bound('prx', self.proto_version)(
            channel=channel
        )

    def create_ptx_mode(self, channel: int) -> HubMessage:
        """Create PtxMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `PtxMode`
        """
        return EsbDomain.bound('ptx', self.proto_version)(
            channel=channel
        )

    def create_send_pdu(self, channel: int, pdu: bytes, retr_count: int = 0):
        """Create a SendPdu message

        :param channel: Channel to use for transmission
        :type channel: int
        :param pdu: Data to send
        :type pdu: bytes
        :param retr_count: Retransmission count
        :type retr_count: int
        :return: instance of `SendPdu`
        """
        return EsbDomain.bound('send', self.proto_version)(
            channel=channel,
            pdu=pdu,
            retr_count=retr_count
        )

    def create_send_raw_pdu(self, channel: int, pdu: bytes, retr_count: int = 0):
        """Create a SendRawPdu message

        :param channel: Channel to use for transmission
        :type channel: int
        :param pdu: Raw data to send
        :type pdu: bytes
        :param retr_count: Retransmission count
        :type retr_count: int
        :return: instance of `SendPdu`
        """
        return EsbDomain.bound('send_raw', self.proto_version)(
            channel=channel,
            pdu=pdu,
            retr_count=retr_count
        )

    def create_pdu_received(self, channel: int, pdu: bytes, rssi: int = None, timestamp: int = None,
                          crc_validity: bool = None, address: EsbNodeAddress = None) -> HubMessage:
        """Create a PduReceived notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Data received (PDU)
        :type pdu: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Reception timestamp
        :type timestamp: int, optional
        :param crc_validity: Indicate CRC validity
        :type crc_validity: bool, optional
        :param address: Sender address
        :type address: EsbNodeAddress, optional
        :return: instance of `PduReceived`
        """
        # Create our base message
        msg = EsbDomain.bound('pdu', self.proto_version)(
            channel=channel,
            pdu=pdu
        )

        # Add optional fields if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if address is not None:
            msg.address = address.value
        if crc_validity is not None:
            msg.crc_validity = crc_validity

        # Return message
        return msg


    def create_raw_pdu_received(self, channel: int, pdu: bytes, rssi: int = None, timestamp: int = None,
                          crc_validity: bool = None, address: EsbNodeAddress = None) -> HubMessage:
        """Create a RawPduReceived notification message.

        :param channel: Channel on which the PDU has been received
        :type channel: int
        :param pdu: Raw data received (PDU)
        :type pdu: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Reception timestamp
        :type timestamp: int, optional
        :param crc_validity: Indicate CRC validity
        :type crc_validity: bool, optional
        :param address: Sender address
        :type address: EsbNodeAddress, optional
        :return: instance of `PduReceived`
        """
        # Create our base message
        msg = EsbDomain.bound('raw_pdu', self.proto_version)(
            channel=channel,
            pdu=pdu
        )

        # Add optional fields if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp
        if address is not None:
            msg.address = address.value
        if crc_validity is not None:
            msg.crc_validity = crc_validity

        # Return message
        return msg

from .address import SetNodeAddress
from .mode import EsbStart, EsbStop, JamMode, SniffMode, Jammed, PrxMode, PtxMode
from .pdu import PduReceived, RawPduReceived, SendPdu, SendRawPdu

__all__ = [
    'EsbDomain',
    'SetNodeAddress',
    'EsbStart',
    'EsbStop',
    'JamMode',
    'SniffMode',
    'Jammed',
    'PrxMode',
    'PtxMode',
    'SendPdu',
    'SendRawPdu',
    'PduReceived',
    'RawPduReceived'
]
