"""WHAD Protocol Logitech Unifying domain message abstraction layer.
"""
from typing import List, Union
from dataclasses import dataclass, field, fields

from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.esb import EsbNodeAddress
from whad.hub.metadata import Metadata
from whad.scapy.layers.esb import ESB_Hdr, ESB_Payload_Hdr, ESB_Ack_Response, ESB_Pseudo_Packet


class Commands:
    """Unifying commands
    """
    SetNodeAddress = 0x00
    Sniff = 0x01
    Jam = 0x02
    Send = 0x03
    SendRaw = 0x04
    LogitechDongleMode = 0x05
    LogitechKeyboardMode = 0x06
    LogitechMouseMode = 0x07
    Start = 0x08
    Stop = 0x09
    SniffPairing = 0x0a


@dataclass(repr=False)
class UnifyingMetadata(Metadata):
    is_crc_valid : bool = None
    address : str = None

    def convert_to_header(self):
        return None, self.timestamp

    @classmethod
    def convert_from_header(cls, pkt):
        metadata = UnifyingMetadata()
        pkt = ESB_Hdr(bytes(pkt))
        metadata.address = EsbNodeAddress(pkt.address)
        metadata.is_crc_valid = pkt.valid_crc
        metadata.timestamp = int(100000 * pkt.time)
        metadata.channel = 0
        return metadata

def generate_unifying_metadata(message, msg_type):
    metadata = UnifyingMetadata()

    if msg_type == "raw_pdu":
        message = message.raw_pdu
    elif msg_type == "pdu":
        message = message.pdu

    if message.HasField("rssi"):
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.HasField("timestamp"):
        metadata.timestamp = message.timestamp
    if message.HasField("crc_validity"):
        metadata.is_crc_valid = message.crc_validity
    if message.HasField("address"):
        metadata.address = ":".join(["{:02x}".format(i) for i in message.address])
    return metadata

@pb_bind(ProtocolHub, name="unifying", version=1)
class UnifyingDomain(Registry):
    """WHAD Logitech Unifying domain messages parser/factory.
    """

    NAME = 'unifying'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a Logitech Unifying domain instance
        """
        self.proto_version = version
        from whad.scapy.layers.unifying import bind
        bind()

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD ESB Domain message as seen by protobuf
        """
        message_type = message.unifying.WhichOneof('msg')
        message_clazz = UnifyingDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)

    def is_packet_compat(self, packet) -> bool:
        """Determine if a packet is an ESB packet.
        """
        return isinstance(packet.metadata, UnifyingMetadata)

    def convert_packet(self, packet) -> HubMessage:
        """Convert an ESB packet to SendPdu or SendBlePdu message.
        """
        if isinstance(packet.metadata, UnifyingMetadata):
            if packet.metadata.raw:
                return UnifyingDomain.bound('send_raw', self.proto_version).from_packet(
                    packet
                )
            else:
                return UnifyingDomain.bound('send', self.proto_version).from_packet(
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

    def create_set_node_address(self, node_address: EsbNodeAddress) -> HubMessage:
        """Create a SetNodeAddress message

        :param node_address: Node address to set (size must be 1-5 bytes)
        :type node_address: EsbNodeAddress
        :return: instance of `SetNodeAddress`
        """
        return UnifyingDomain.bound('set_node_addr', self.proto_version)(
            address=node_address.value
        )

    def create_start(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start` message
        """
        return UnifyingDomain.bound('start', self.proto_version)()


    def create_stop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop` message
        """
        return UnifyingDomain.bound('stop', self.proto_version)()


    def create_jam_mode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: ESB channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return UnifyingDomain.bound('jam', self.proto_version)(
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
        return UnifyingDomain.bound('sniff', self.proto_version)(
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
        return UnifyingDomain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )

    def create_dongle_mode(self, channel: int) -> HubMessage:
        """Create DongleMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `DongleMode`
        """
        return UnifyingDomain.bound('dongle', self.proto_version)(
            channel=channel
        )

    def create_keyboard_mode(self, channel: int) -> HubMessage:
        """Create KeyboardMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `KeyboardMode`
        """
        return UnifyingDomain.bound('keyboard', self.proto_version)(
            channel=channel
        )

    def create_mouse_mode(self, channel: int) -> HubMessage:
        """Create MouseMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `MouseMode`
        """
        return UnifyingDomain.bound('mouse', self.proto_version)(
            channel=channel
        )

    def create_sniff_pairing(self) -> HubMessage:
        """Create SniffPairing message

        :return: instance of `SniffPairing`
        """
        return UnifyingDomain.bound('sniff_pairing', self.proto_version)()

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
        return UnifyingDomain.bound('send', self.proto_version)(
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
        return UnifyingDomain.bound('send_raw', self.proto_version)(
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
        msg = UnifyingDomain.bound('pdu', self.proto_version)(
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
        msg = UnifyingDomain.bound('raw_pdu', self.proto_version)(
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
from .mode import UnifyingStart, UnifyingStop, JamMode, SniffMode, Jammed, DongleMode, \
    KeyboardMode, MouseMode, SniffPairing
from .pdu import PduReceived, RawPduReceived, SendPdu, SendRawPdu

__all__ = [
    'UnifyingDomain',
    'SetNodeAddress',
    'UnifyingStart',
    'UnifyingStop',
    'JamMode',
    'SniffMode',
    'Jammed',
    'DongleMode',
    'KeyboardMode',
    'MouseMode',
    'SniffPairing',
    'SendPdu',
    'SendRawPdu',
    'PduReceived',
    'RawPduReceived'
]
