"""WHAD Protocol ESB domain message abstraction layer.
"""
from typing import List, Union
from dataclasses import dataclass, field, fields

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

    def __init__(self, address: Union[bytes, int], address_size: int = 0):
        """Initialize our node address

        :param address: ESB node address
        :type address: bytes, int
        :param address_size: Node address size (1-5)
        :type address_size: int, optional
        """
        self.__address = None
        if isinstance(address, bytes):
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

    def convert_to_header(self):
        return None, self.timestamp


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

    def isPacketCompat(self, packet) -> bool:
        """Determine if a packet is an ESB packet.
        """
        return isinstance(packet.metadata, ESBMetadata)
    
    def convertPacket(self, packet) -> HubMessage:
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

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD ESB Domain message as seen by protobuf
        """
        message_type = message.esb.WhichOneof('msg')
        message_clazz = EsbDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)
    

    def createSetNodeAddress(self, node_address: EsbNodeAddress) -> HubMessage:
        """Create a SetNodeAddress message

        :param node_address: Node address to set (size must be 1-5 bytes)
        :type node_address: EsbNodeAddress
        :return: instance of `SetNodeAddress`
        """
        return EsbDomain.bound('set_node_addr', self.proto_version)(
            address=node_address.value
        )
    
    def createStart(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start` message
        """
        return EsbDomain.bound('start', self.proto_version)()


    def createStop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop` message
        """
        return EsbDomain.bound('stop', self.proto_version)()
    

    def createJamMode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: ESB channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return EsbDomain.bound('jam', self.proto_version)(
            channel=channel
        )

    def createSniffMode(self, address: EsbNodeAddress, channel: int = 0xFF, show_acks: bool = False) -> HubMessage:
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
    
    def createJammed(self, timestamp: int):
        """Create a Jammed notification message

        :param timestamp: Timestamp at which the jamming has succeeded
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return EsbDomain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )
    
    def createPrxMode(self, channel: int) -> HubMessage:
        """Create PrxMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `PrxMode`
        """
        return EsbDomain.bound('prx', self.proto_version)(
            channel=channel
        )

    def createPtxMode(self, channel: int) -> HubMessage:
        """Create PtxMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `PtxMode`
        """
        return EsbDomain.bound('ptx', self.proto_version)(
            channel=channel
        )
    
    def createSendPdu(self, channel: int, pdu: bytes, retr_count: int = 0):
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

    def createSendRawPdu(self, channel: int, pdu: bytes, retr_count: int = 0):
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
    
    def createPduReceived(self, channel: int, pdu: bytes, rssi: int = None, timestamp: int = None,
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


    def createRawPduReceived(self, channel: int, pdu: bytes, rssi: int = None, timestamp: int = None,
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