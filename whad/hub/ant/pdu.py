"""WHAD Protocol ANT pdu messages abstraction layer.
"""
import logging

from struct import pack, unpack, error as StructError
from whad.scapy.layers.ant import ANT_Hdr
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool, dissect_failsafe
from whad.hub.ant import AntDomain, ANTMetadata

logger = logging.getLogger(__name__)

@pb_bind(AntDomain, 'send', 3)
class SendPdu(PbMessageWrapper):
    """Send ANT PDU message class
    """
    channel_number = PbFieldInt('ant.send.channel_number')
    rf_channel = PbFieldInt('ant.send.rf_channel')
    pdu = PbFieldBytes('ant.send.pdu')

    @dissect_failsafe
    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        return ANT_Hdr(self.pdu)

    @staticmethod
    def from_packet(packet, channel_number : int = 0, rf_channel: int = 57):
        """Convert a scapy packet to a SendPdu message
        """
        if ANT_Hdr in packet:
            pdu = bytes(packet[ANT_Hdr])
        else:
            return None

        msg = SendPdu(
            channel_number=channel_number, 
            rf_channel=rf_channel,
            pdu=pdu
        )
        return msg


@pb_bind(AntDomain, 'send_raw', 3)
class SendRawPdu(PbMessageWrapper):
    """Send Raw ANT PDU message class
    """
    channel_number = PbFieldInt('ant.send_raw.channel_number')
    rf_channel = PbFieldInt('ant.send_raw.rf_channel')
    pdu = PbFieldBytes('ant.send_raw.pdu')

    @dissect_failsafe
    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        return ANT_Hdr(self.pdu)

    @staticmethod
    def from_packet(packet, channel_number : int = 0, rf_channel: int = 57):
        """Convert a scapy packet to a SendPdu message
        """
        if ANT_Hdr in packet:
            pdu = bytes(packet[ANT_Hdr])
        else:
            return None

        msg = SendRawPdu(
            channel_number=channel_number, 
            rf_channel=rf_channel,
            pdu=pdu
        )
        return msg



@pb_bind(AntDomain, 'pdu', 3)
class PduReceived(PbMessageWrapper):
    """ANT PDU received message class
    """
    channel_number = PbFieldInt('ant.pdu.channel_number')
    rf_channel = PbFieldInt('ant.pdu.rf_channel')
    pdu = PbFieldBytes('ant.pdu.pdu')
    rssi = PbFieldInt('ant.pdu.rssi', optional=True)
    timestamp = PbFieldInt('ant.pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('ant.pdu.crc_validity', optional=True)
    
    @dissect_failsafe
    def to_packet(self):
        """Convert message to its scapy packet representation
        """
        # Create packet
        packet = ANT_Hdr(bytes(self.pdu))

        # Set packet metadata
        packet.metadata = ANTMetadata()
        packet.metadata.channel_number = self.channel_number
        packet.metadata.rf_channel = self.rf_channel

        packet.metadata.decrypted = False

        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.crc_validity is not None:
            packet.metadata.is_crc_valid = self.crc_validity

        # Return packet
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert scapy packet to a PduReceived message
        """
        # Create a PduReceived message
        msg = PduReceived(
            channel_number=packet.metadata.channel_number,
            rf_channel=packet.metadata.rf_channel,
            pdu=bytes(packet.getlayer(ANT_Hdr)),
        )
        # Add optional metadata
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid

        # Return metadata
        return msg


@pb_bind(AntDomain, 'raw_pdu', 3)
class RawPduReceived(PbMessageWrapper):
    """ANT PDU received message class
    """
    channel_number = PbFieldInt('ant.raw_pdu.channel_number')
    rf_channel = PbFieldInt('ant.raw_pdu.rf_channel')
    pdu = PbFieldBytes('ant.raw_pdu.pdu')
    crc = PbFieldInt('ant.raw_pdu.crc')
    rssi = PbFieldInt('ant.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('ant.raw_pdu.timestamp', optional=True)
    crc_validity = PbFieldBool('ant.raw_pdu.crc_validity', optional=True)
    
    @dissect_failsafe
    def to_packet(self):
        """Convert message to its scapy packet representation
        """
        # Create packet
        packet = ANT_Hdr(bytes(self.pdu) + pack('<H', self.crc))

        # Set packet metadata
        packet.metadata = ANTMetadata()
        packet.metadata.channel_number = self.channel_number
        packet.metadata.rf_channel = self.rf_channel
        packet.metadata.decrypted = False

        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.crc_validity is not None:
            packet.metadata.is_crc_valid = self.crc_validity

        # Return packet
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert scapy packet to a PduReceived message
        """
        # Create a PduReceived message
        msg = RawPduReceived(
            channel_number=packet.metadata.channel_number,
            rf_channel=packet.metadata.rf_channel,
            pdu=bytes(packet.getlayer(ANT_Hdr))[:-2],
            crc=unpack('<H', bytes(packet.getlayer(ANT_Hdr))[-2:])[0]
        )
        # Add optional metadata
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_crc_valid is not None:
            msg.crc_validity = packet.metadata.is_crc_valid

        # Return metadata
        return msg


