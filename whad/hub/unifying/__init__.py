"""WHAD Protocol Logitech Unifying domain message abstraction layer.
"""
from typing import List, Union

from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.esb import EsbNodeAddress


@pb_bind(ProtocolHub, name="unifying", version=1)
class UnifyingDomain(Registry):
    """WHAD Logitech Unifying domain messages parser/factory.
    """

    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a Logitech Unifying domain instance
        """
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD ESB Domain message as seen by protobuf
        """
        message_type = message.unifying.WhichOneof('msg')
        message_clazz = UnifyingDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)
    

    def createSetNodeAddress(self, node_address: EsbNodeAddress) -> HubMessage:
        """Create a SetNodeAddress message

        :param node_address: Node address to set (size must be 1-5 bytes)
        :type node_address: EsbNodeAddress
        :return: instance of `SetNodeAddress`
        """
        return UnifyingDomain.bound('set_node_addr', self.proto_version)(
            address=node_address.value
        )
    
    def createStart(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start` message
        """
        return UnifyingDomain.bound('start', self.proto_version)()


    def createStop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop` message
        """
        return UnifyingDomain.bound('stop', self.proto_version)()
    

    def createJamMode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: ESB channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return UnifyingDomain.bound('jam', self.proto_version)(
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
        return UnifyingDomain.bound('sniff', self.proto_version)(
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
        return UnifyingDomain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )
    
    def createDongleMode(self, channel: int) -> HubMessage:
        """Create DongleMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `DongleMode`
        """
        return UnifyingDomain.bound('dongle', self.proto_version)(
            channel=channel
        )

    def createKeyboardMode(self, channel: int) -> HubMessage:
        """Create KeyboardMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `KeyboardMode`
        """
        return UnifyingDomain.bound('keyboard', self.proto_version)(
            channel=channel
        )
    
    def createMouseMode(self, channel: int) -> HubMessage:
        """Create MouseMode message

        :param channel: Channel to listen on
        :type channel: int
        :return: instance of `MouseMode`
        """
        return UnifyingDomain.bound('mouse', self.proto_version)(
            channel=channel
        )

    def createSniffPairing(self) -> HubMessage:
        """Create SniffPairing message

        :return: instance of `SniffPairing`
        """
        return UnifyingDomain.bound('sniff_pairing', self.proto_version)()

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
        return UnifyingDomain.bound('send', self.proto_version)(
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
        return UnifyingDomain.bound('send_raw', self.proto_version)(
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
    'EsbDomain',
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