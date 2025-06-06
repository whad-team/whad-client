"""WHAD Protocol Dot15d4 pdu messages abstraction layer.
"""
import logging

from struct import pack, unpack, error as StructError
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.dot15d4tap import Dot15d4Raw
from whad.hub.message import pb_bind, PbFieldInt, PbFieldBytes, PbMessageWrapper, \
    PbFieldBool, dissect_failsafe
from whad.hub.dot15d4 import Dot15d4Domain, Dot15d4Metadata

logger = logging.getLogger(__name__)

@pb_bind(Dot15d4Domain, 'send', 1)
class SendPdu(PbMessageWrapper):
    """Send Dot15d4 PDU message class
    """
    channel = PbFieldInt('dot15d4.send.channel')
    pdu = PbFieldBytes('dot15d4.send.pdu')

    @dissect_failsafe
    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        return Dot15d4(self.pdu)

    @staticmethod
    def from_packet(packet, channel: int = 11):
        """Convert a scapy packet to a SendPdu message
        """
        if Dot15d4 in packet:
            pdu = bytes(packet[Dot15d4])
        elif Dot15d4FCS in packet:
            pdu = bytes(packet[Dot15d4FCS])[:-2]
        else:
            return None

        msg = SendPdu(
            channel=channel,
            pdu=pdu
        )
        return msg

@pb_bind(Dot15d4Domain, 'send_raw', 1)
class SendRawPdu(PbMessageWrapper):
    """Send Dot15d4 raw PDU message class
    """
    channel = PbFieldInt('dot15d4.send_raw.channel')
    pdu = PbFieldBytes('dot15d4.send_raw.pdu')
    fcs = PbFieldInt('dot15d4.send_raw.fcs')

    @dissect_failsafe
    def to_packet(self):
        """Convert message to the corresponding scapy packet
        """
        return Dot15d4FCS(self.pdu + bytes(pack('<H', self.fcs)))
        
    @staticmethod
    def from_packet(packet, channel: int = 11):
        """Convert a scapy packet to a SendPdu message
        """
        if Dot15d4FCS in packet:
            pdu = bytes(packet[Dot15d4FCS])[:-2]

            msg = SendRawPdu(
                channel=channel,
                pdu=pdu,
                fcs=packet.fcs
            )
        elif Dot15d4 in packet:
            # Convert packet to bytes
            pdu = bytes(packet[Dot15d4])

            # If packet len is greater than 2, truncate payload in order to
            # put the remaining 2 bytes in its FCS field
            if len(pdu) > 2:
                fcs = unpack("<H", pdu[-2:])[0]
                pdu = pdu[:-2]
            else:
                fcs = 0

            msg = SendRawPdu(
                channel=channel,
                pdu=pdu,
                fcs=fcs
            )
        elif Dot15d4Raw in packet:
            pdu = bytes(packet)

            # If packet len is greater than 2, truncate payload in order to
            # put the remaining 2 bytes in its FCS field
            if len(pdu) > 2:
                fcs = unpack("<H", pdu[-2:])[0]
                pdu = pdu[:-2]
            else:
                fcs = 0

            msg = SendRawPdu(
                channel=channel,
                pdu=pdu,
                fcs=fcs
            )
        else:
            return None


        return msg

@pb_bind(Dot15d4Domain, 'pdu', 1)
class PduReceived(PbMessageWrapper):
    """Dot15d4 PDU received message class
    """
    channel = PbFieldInt('dot15d4.pdu.channel')
    pdu = PbFieldBytes('dot15d4.pdu.pdu')
    rssi = PbFieldInt('dot15d4.pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.pdu.lqi', optional=True)

    @dissect_failsafe
    def to_packet(self):
        """Convert message to its scapy packet representation
        """
        # Create packet
        packet = Dot15d4(bytes(self.pdu))

        # Set packet metadata
        packet.metadata = Dot15d4Metadata()
        packet.metadata.channel = self.channel

        packet.metadata.decrypted = False

        if self.lqi is not None:
            packet.metadata.lqi = self.lqi
        if self.rssi is not None:
            packet.metadata.rssi = self.rssi
        if self.timestamp is not None:
            packet.metadata.timestamp = self.timestamp
        if self.fcs_validity is not None:
            packet.metadata.is_fcs_valid = self.fcs_validity

        # Return packet
        return packet

    @staticmethod
    def from_packet(packet):
        """Convert scapy packet to a PduReceived message
        """
        # Create a PduReceived message
        msg = PduReceived(
            channel=packet.metadata.channel,
            pdu=bytes(packet.getlayer(Dot15d4)),
        )
        # Add optional metadata

        if packet.metadata.decrypted is not None:
            msg.decrypted = packet.metadata.decrypted
        if packet.metadata.lqi is not None:
            msg.lqi = packet.metadata.lqi
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.rssi = packet.metadata.timestamp
        if packet.metadata.is_fcs_valid is not None:
            msg.fcs_validity = packet.metadata.is_fcs_valid

        # Return metadata
        return msg


@pb_bind(Dot15d4Domain, 'raw_pdu', 1)
class RawPduReceived(PbMessageWrapper):
    """Dot15d4 raw PDU received message class
    """
    channel = PbFieldInt('dot15d4.raw_pdu.channel')
    pdu = PbFieldBytes('dot15d4.raw_pdu.pdu')
    fcs = PbFieldInt('dot15d4.raw_pdu.fcs')
    rssi = PbFieldInt('dot15d4.raw_pdu.rssi', optional=True)
    timestamp = PbFieldInt('dot15d4.raw_pdu.timestamp', optional=True)
    fcs_validity = PbFieldBool('dot15d4.raw_pdu.fcs_validity', optional=True)
    lqi = PbFieldInt('dot15d4.raw_pdu.lqi', optional=True)

    @dissect_failsafe
    def to_packet(self):
        """Convert message to scapy packet.
        """
        try:
            # Create packet
            #print('converting %s' % (self.pdu + bytes(pack(">H", self.fcs))).hex())
            packet = Dot15d4FCS(bytes(self.pdu) + bytes(pack("<H", self.fcs)))

            # Set packet metadata
            packet.metadata = Dot15d4Metadata()
            packet.metadata.channel = self.channel
            packet.metadata.decrypted = False
            if self.lqi is not None:
                packet.metadata.lqi = self.lqi
            if self.rssi is not None:
                packet.metadata.rssi = self.rssi
            if self.timestamp is not None:
                packet.metadata.timestamp = self.timestamp
            if self.fcs_validity is not None:
                packet.metadata.is_fcs_valid = self.fcs_validity

            return packet
        except StructError:
            #logger.debug("[hub::dot15d4] error parsing 802.15.4 frame (%s)",
            #             bytes(self.pdu).hex() + bytes(pack("<H", self.fcs)).hex())
            logger.debug("[hub::dot15d4] considering 802.15.4 as raw frame")

            # Build packet
            packet = Dot15d4Raw(bytes(self.pdu) + pack("<H", self.fcs))

            # Set packet metadata
            packet.metadata = Dot15d4Metadata()
            packet.metadata.channel = self.channel

            packet.metadata.decrypted = False

            if self.lqi is not None:
                packet.metadata.lqi = self.lqi
            if self.rssi is not None:
                packet.metadata.rssi = self.rssi
            if self.timestamp is not None:
                packet.metadata.timestamp = self.timestamp
            if self.fcs_validity is not None:
                packet.metadata.is_fcs_valid = self.fcs_validity

            return packet 

    @staticmethod
    def from_packet(packet):
        """Convert packet to a RawPduReceived message.
        """
        # Create a PduReceived message
        msg = RawPduReceived(
            channel=packet.metadata.channel,
            pdu=bytes(packet.getlayer(Dot15d4FCS))[:-2],
            fcs=packet.fcs
        )

        # Add optional metadata
        if packet.metadata.decrypted is not None:
            msg.decrypted = packet.metadata.decrypted
        if packet.metadata.lqi is not None:
            msg.lqi = packet.metadata.lqi
        if packet.metadata.rssi is not None:
            msg.rssi = packet.metadata.rssi
        if packet.metadata.timestamp is not None:
            msg.timestamp = packet.metadata.timestamp
        if packet.metadata.is_fcs_valid is not None:
            msg.fcs_validity = packet.metadata.is_fcs_valid

        # Return metadata
        return msg
