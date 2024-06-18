"""WHAD Protocol PHY domain message abstraction layer.
"""
from typing import List
from dataclasses import dataclass, field, fields

from whad.protocol.phy.phy_pb2 import LoRaSpreadingFactor, LoRaCodingRate, JammingMode, \
    Endianness as PbEndianness, TXPower, timestamp as whad_timestamp
from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.metadata import Metadata

class Commands:
    """PHY Commands
    """
    SetASKModulation = 0x00
    SetFSKModulation = 0x01
    SetGFSKModulation = 0x02
    SetBPSKModulation = 0x03
    SetQPSKModulation = 0x04
    Set4FSKModulation = 0x05
    SetMSKModulation  = 0x06
    GetSupportedFrequencies = 0x07
    SetFrequency = 0x08
    SetDataRate = 0x09
    SetEndianness = 0x0a
    SetTXPower = 0x0b 
    SetPacketSize = 0x0c
    SetSyncWord = 0x0d
    Sniff = 0x0e
    Send = 0x0f
    SendRaw = 0x10
    Jam = 0x11
    Monitor = 0x12
    Start = 0x13
    Stop = 0x14
    SetLoRaModulation = 0x15
    ScheduleSend = 0x16

class Endianness:
    """PHY Endianness
    """
    BIG = PbEndianness.BIG
    LITTLE = PbEndianness.LITTLE

class SpreadingFactor:
    SF7 = LoRaSpreadingFactor.SF7
    SF8 = LoRaSpreadingFactor.SF8
    SF9 = LoRaSpreadingFactor.SF9
    SF10 = LoRaSpreadingFactor.SF10
    SF11 = LoRaSpreadingFactor.SF11
    SF12 = LoRaSpreadingFactor.SF12


class CodingRate:
    CR45 = LoRaCodingRate.CR45
    CR46 = LoRaCodingRate.CR46
    CR47 = LoRaCodingRate.CR47
    CR48 = LoRaCodingRate.CR48

class Jamming:
    CONTINUOUS = JammingMode.CONTINUOUS
    REACTIVE = JammingMode.REACTIVE

class TxPower:
    LOW = TXPower.LOW
    MEDIUM = TXPower.MEDIUM
    HIGH = TXPower.HIGH

class Timestamp(object):
    """PHY Timestamp class
    """

    def __init__(self, sec: int, usec: int):
        """Initialize a timestamp

        :param sec: number of seconds
        :type sec: int
        :param usec: number of microseconds
        :type usec: int
        """
        self.__sec = sec
        self.__usec = usec

    @property
    def sec(self):
        return self.__sec
    
    @property
    def usec(self):
        return self.__usec

@dataclass(repr=False)
class PhyMetadata(Metadata):
    frequency : int = None
    iq : list = field(default_factory=lambda: [])

    def convert_to_header(self):
        return None, self.timestamp

@pb_bind(ProtocolHub, name="phy", version=1)
class PhyDomain(Registry):
    """WHAD PHY domain messages parser/factory.
    """

    NAME = 'phy'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a Dot15d4 domain instance
        """
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD Dot15d4 Domain message as seen by protobuf
        """
        message_type = message.phy.WhichOneof('msg')
        message_clazz = PhyDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)

    def isPacketCompat(self, packet) -> bool:
        """Determine if a packet is a compatible BLE packet
        """
        return isinstance(packet.metadata, PhyMetadata)

    def convertPacket(self, packet) -> HubMessage:
        """Convert a BLE packet to SendPdu or SendBlePdu message.
        """
        if isinstance(packet.metadata, PhyMetadata):
            if packet.metadata.raw:
                return PhyDomain.bound('send_raw', self.proto_version).from_packet(
                    packet
                )
            else:
                return PhyDomain.bound('send', self.proto_version).from_packet(
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
        return packet, 0

    def createSetAskMod(self, ook: bool = False) -> HubMessage:
        """Create a SetAskMod message

        :param ook: Enable On/Off Keying if set to True
        :type ook: bool
        :return: instance of `SetAskMod`
        """
        return PhyDomain.bound('mod_ask', self.proto_version)(
            ook=ook
        )
    
    def createSetFskMod(self, deviation: int) -> HubMessage:
        """Create a SetFskMod message

        :param deviation: FSK deviation to use, in Hz
        :type deviation: int
        :return: instance of `SetFskMod`
        """
        return PhyDomain.bound('mod_fsk', self.proto_version)(
            deviation=deviation
        )
    
    def createSetGfskMod(self, deviation: int) -> HubMessage:
        """Create a SetGfskMod message

        :param deviation: GFSK deviation to use, in Hz
        :type deviation: int
        :return: instance of `SetGfskMod`
        """
        return PhyDomain.bound('mod_gfsk', self.proto_version)(
            deviation=deviation
        )
    
    def createSetBpskMod(self) -> HubMessage:
        """Create a SetBpskMod message
        :return: instance of `SetBpskMod`
        """
        return PhyDomain.bound('mod_bpsk', self.proto_version)()
    
    def createSetQpskMod(self, offset: bool) -> HubMessage:
        """Create a SetQpskMod message

        :param offset: Use QPSK offset if set to True
        :type offset: bool
        :return: instance of `SetQpskMod`
        """
        return PhyDomain.bound('mod_qpsk', self.proto_version)(
            offset=offset
        )
    
    def createSet4FskMod(self, deviation: int) -> HubMessage:
        """Create a Set4FskMod message
        
        :param deviation: 4FSK deviation to use, in Hz
        :type deviation: int
        :return: instance of `Set4FskMod`
        """
        return PhyDomain.bound('mod_4fsk', self.proto_version)(
            deviation=deviation
        )
    
    def createSetMskMod(self, deviation: int) -> HubMessage:
        """Create a SetMskMod message
        
        :param deviation: MSK deviation to use, in Hz
        :type deviation: int
        :return: instance of `SetMskMod`
        """
        return PhyDomain.bound('mod_msk', self.proto_version)(
            deviation=deviation
        )
    
    def createSetLoRaMod(self, bandwidth: int, sf: int, cr: int, preamble_length: int, \
                         enable_crc:bool = True, explicit_mode: bool = True, \
                         invert_iq: bool = False):
        """Create a SetLoRaMod message

        :param bandwidth: Bandwidth to use, in Hz
        :type bandwidth: int
        :param sf: LoRa spreading factor as defined in `SpreadingFactor`
        :type sf: int
        :param cr: LoRa coding rate as defined in `CodingRate`
        :type cr: int
        :param enable_crc: Include CRC in LoRa frames if set to True
        :type enable_crc: bool, optional
        :param explicit_mode: Enable LoRa explicit mode if set to True
        :type explicit_mode: bool, optional
        :param invert_iq: Invert IQ if set to True (used for downlink transmission)
        :type invert_iq: bool, optional
        :return: instance of `SetLoRaMod`
        """
        return PhyDomain.bound('mod_lora', self.proto_version)(
            bandwidth=bandwidth,
            sf=sf,
            cr=cr,
            preamble_length=preamble_length,
            enable_crc=enable_crc,
            explicit_mode=explicit_mode,
            invert_iq=invert_iq
        )


    def createSetFreq(self, frequency: int) -> HubMessage:
        """Create a SetFreq message

        :param frequency: Frequency to set
        :type frequency: int
        :return: instance of `SetFreq`
        """
        return PhyDomain.bound('set_freq', self.proto_version)(
            frequency=frequency
        )
    
    def createGetSupportedFreqs(self) -> HubMessage:
        """Create a GetSupportedFreqs message

        :return: instance of `GetSupportedFreqs`
        """
        return PhyDomain.bound('get_supported_freq', self.proto_version)()
    
    def createSupportedFreqRanges(self, ranges: List[tuple]) -> HubMessage:
        """Create a SupportedFreqRanges message

        :param ranges: List of tuples containing range start and end frequencies
        :type ranges: list
        :return: instance of `SupportedFreqRanges`
        """
        # Create our supported freq ranges message
        msg: SupportedFreqRanges = PhyDomain.bound('supported_freq', self.proto_version)()

        # Add given ranges
        for start, end in ranges:
            msg.add(start, end)

        # Return created message
        return msg
    
    def createSniffMode(self, iq_stream: bool = False) -> HubMessage:
        """Create a SniffMode message

        :param iq_stream: Sniff I/Q stream if set to True, packets otherwise
        :type iq_stream: bool, optional
        :return: instance of `SniffMode`
        """
        return PhyDomain.bound('sniff', self.proto_version)(iq_stream=iq_stream)
    
    def createJamMode(self, mode: int) -> HubMessage:
        """Create a JamMode message

        :param mode: Jamming mode, as defined in `Jamming` class
        :type mode: int
        :return: instance of `JamMode`
        """
        return PhyDomain.bound('jam', self.proto_version)(mode=mode)
    
    def createMonitorMode(self) -> HubMessage:
        """Create a MonitorMode message.

        :return: instance of `MonitorMode`
        """
        return PhyDomain.bound('monitor', self.proto_version)()
    
    def createStart(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start`
        """ 
        return PhyDomain.bound('start', self.proto_version)()

    def createStop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop`
        """ 
        return PhyDomain.bound('stop', self.proto_version)()
    
    def createJammed(self, timestamp: int) -> HubMessage:
        """Create a Jammed notification

        :param timestamp: Timestamp at which the jamming has succeeded
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return PhyDomain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )
    
    def createMonitoringReport(self, timestamp: int, reports: List[int]) -> HubMessage:
        """Create a MonitoringReport notification message

        :param timestamp: Report timestamp
        :type timestamp: int
        :param reports: List of values contained in the monitoring report
        :type reports: list
        :return: instance of `MonitoringReport`
        """
        # Create our message
        msg = PhyDomain.bound('monitor_report', self.proto_version)(
            timestamp=timestamp
        )

        # Add reports
        for report_value in reports:
            msg.reports.append(report_value)

        # Return message
        return msg
    
    def createSetDatarate(self, datarate: int) -> HubMessage:
        """Create a SetDatarate message

        :param datarate: data rate to use
        :type datarate: int
        :return: instance of `SetDatarate`
        """
        return PhyDomain.bound('datarate', self.proto_version)(
            rate=datarate
        )
    
    def createSetEndianness(self, little: bool = True) -> HubMessage:
        """Create a SetEndianness message

        :param little: Use little-endian if set to True, big-endian otherwise
        :type little: bool
        :return: instance of `SetEndianness`
        """
        return PhyDomain.bound('endianness', self.proto_version)(
            endianness=Endianness.LITTLE if little else Endianness.BIG
        )
    
    def createSetPacketSize(self, size: int) -> HubMessage:
        """Create a SetPacketSize message

        :param size: Desired packet size
        :type size: int
        :return: instance of `SetPacketSize`
        """
        return PhyDomain.bound('packet_size', self.proto_version)(
            packet_size=size
        )
    
    def  createSetTxPower(self, power: int) -> HubMessage:
        """Create a SetTxPower message

        :param power: Specify the TX power, as defined in `TxPower`
        :type power: int
        :return: instance of `SetTxPower`
        """
        return PhyDomain.bound('tx_power', self.proto_version)(
            power=power
        )

    def createSetSyncWord(self, syncword: bytes) -> HubMessage:
        """Create a SetSyncWord message

        :param syncword: Synchronization word to use
        :type syncword: bytes
        :return: instance of `SetSyncWord`
        """
        return PhyDomain.bound('sync_word', self.proto_version)(
            sync_word=syncword
        )
    
    def createSendPacket(self, packet: bytes) -> HubMessage:
        """Create a SendPacket message

        :param packet: Packet data to send
        :type packet: bytes
        :return: instance of `SendPacket`
        """
        return PhyDomain.bound('send', self.proto_version)(
            packet=packet
        )
    
    def createSendRawPacket(self, iq: List[int]) -> HubMessage:
        """Create a SendPacket message

        :param iq: List of I/Q samples to send
        :type iq: list
        :return: instance of `SendRawPacket`
        """
        # Create our message
        msg = PhyDomain.bound('send_raw', self.proto_version)()

        # Add samples
        for sample in iq:
            msg.iq.append(sample)

        # Success
        return msg


    def createPacketReceived(self, frequency: int, packet: bytes, rssi: int = None, \
                             timestamp: Timestamp = None) -> HubMessage:
        """Create a PacketReceived notification message

        :param frequency: Frequency on which the packet has been received
        :type frequency: int
        :param packet: Packet data
        :type packet: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the packet has been received
        :type timestamp: Timestamp, optional
        :return: instance of `PacketReceived`
        """
        msg = PhyDomain.bound('packet', self.proto_version)(
            frequency=frequency,
            packet=packet
        )

        # Add optional fields if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp.sec = timestamp.sec
            msg.timestamp.usec = timestamp.usec
        
        # Success
        return msg
    
    def createRawPacketReceived(self, frequency: int, packet: bytes, rssi: int = None, \
                             timestamp: Timestamp = None, iq: List[int] = None) -> HubMessage:
        """Create a RawPacketReceived notification message

        :param frequency: Frequency on which the packet has been received
        :type frequency: int
        :param packet: Packet data
        :type packet: bytes
        :param rssi: Received signal strength indicator
        :type rssi: int, optional
        :param timestamp: Timestamp at which the packet has been received
        :type timestamp: Timestamp, optional
        :return: instance of `PacketReceived`
        """
        msg = PhyDomain.bound('raw_packet', self.proto_version)(
            frequency=frequency,
            packet=packet
        )

        # Add optional fields if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp.sec = timestamp.sec
            msg.timestamp.usec = timestamp.usec
        if iq is not None:
            for sample in iq:
                msg.iq.append(sample)
        
        # Success
        return msg
    
    def createSchedulePacket(self, packet: bytes, timestamp: Timestamp) -> HubMessage:
        """Create a SchedulePacket message

        :param packet: Packet data
        :type packet: bytes
        :param timestamp: Timestamp at which the packet has to be sent
        :type timestamp: Timestamp
        :return: instance of `SchedulePacket`
        """
        # Create message
        msg = PhyDomain.bound('sched_send', self.proto_version)(
            packet=packet,
        )

        # Set timestamp value
        msg.timestamp.sec = timestamp.sec
        msg.timestamp.usec = timestamp.usec

        # Return message
        return msg
    
    def createSchedulePacketResponse(self, packet_id: int, full: bool = False) -> HubMessage:
        """Create a SchedulePacketResponse message

        :param packet_id: Packet ID
        :type packet_id: int
        :param full: Set to True to indicate the schedule packet queue is full
        :type full: bool, optional
        :return: instance of `SchedulePacketResponse`
        """
        return PhyDomain.bound('sched_pkt_rsp', self.proto_version)(
            id=packet_id,
            full=full
        )
    
    def createSchedulePacketSent(self, packet_id: int) -> HubMessage:
        """Create a SchedulePacketSent notification message

        :param packet_id: Packet id that has been sent
        :type packet_id: int
        :return: instance of SchedulePacketSent
        """
        return PhyDomain.bound('sched_pkt_sent', self.proto_version)(
            id=packet_id
        )

from .mod import SetAskMod, SetBpskMod, SetFskMod, SetGfskMod, SetLoRaMod, \
    SetMskMod, SetQpskMod, Set4FskMod
from .freq import GetSupportedFreqs, SetFreq, SupportedFreqRanges
from .packet import SetDatarate, SetEndianness, SetTxPower, SetPacketSize, SetSyncWord, \
    SendPacket, SendRawPacket, RawPacketReceived, PacketReceived
from .mode import SniffMode, JamMode, MonitorMode, Start, Stop, Jammed, MonitoringReport
from .schedule import SchedulePacket, ScheduledPacketSent, SchedulePacketResponse

__all__ = [
    'SetAskMod',
    'SetBpskMod',
    'SetFskMod',
    'SetGfskMod',
    'SetLoRaMod',
    'SetMskMod',
    'SetQpskMod',
    'Set4FskMod',
    'GetSupportedFreqs',
    'SetFreq',
    'SupportedFreqRanges',
    'SetDatarate',
    'SetEndianness',
    'SetTxPower',
    'SetPacketSize',
    'SetSyncWord',
    'SendPacket',
    'SendRawPacket',
    'PacketReceived',
    'RawPacketReceived',
    'SniffMode',
    'JamMode',
    'Jammed',
    'MonitorMode',
    'MonitoringReport',
    'Start',
    'Stop',
    'SchedulePacket',
    'ScheduledPacketSent',
    'SchedulePacketResponse',
    'PhyDomain',
    'Timestamp',
    'SpreadingFactor',
    'CodingRate',
    'Jamming',
    'TxPower'
]