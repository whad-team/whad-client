"""WHAD Protocol ANT domain message abstraction layer.
"""

from typing import List, Union
from dataclasses import dataclass, field, fields

from whad.scapy.layers.ant import ANT_Hdr

from whad.protocol.ant.ant_pb2 import AntChannelType

from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.metadata import Metadata


class Commands:
    """ANT Commands
    """
    SetDeviceNumber           = 0x00
    SetDeviceType             = 0x01
    SetTransmissionType       = 0x02
    SetChannelPeriod          = 0x03
    SetNetworkKey             = 0x04
    AssignChannel             = 0x05
    UnassignChannel           = 0x06
    OpenChannel               = 0x07
    CloseChannel              = 0x08
    SetFrequency              = 0x09
    Sniff                     = 0x0a
    Jam                       = 0x0b
    Send                      = 0x0c
    SendRaw                   = 0x0d
    MasterMode                = 0x0e
    SlaveMode                 = 0x0f
    Start                     = 0x10
    Stop                      = 0x11




class ChannelType:
    """ANT Channel type
    """
    BIDIRECTIONAL_RECEIVE_CHANNEL = AntChannelType.BIDIRECTIONAL_RECEIVE_CHANNEL
    BIDIRECTIONAL_TRANSMIT_CHANNEL = AntChannelType.BIDIRECTIONAL_TRANSMIT_CHANNEL
    SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL = AntChannelType.SHARED_BIDIRECTIONAL_RECEIVE_CHANNEL
    SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL = AntChannelType.SHARED_BIDIRECTIONAL_TRANSMIT_CHANNEL
    RECEIVE_ONLY_CHANNEL = AntChannelType.RECEIVE_ONLY_CHANNEL
    TRANSMIT_ONLY_CHANNEL = AntChannelType.TRANSMIT_ONLY_CHANNEL


@dataclass(repr=False)
class ANTMetadata(Metadata):
    is_crc_valid : bool = None
    timestamp : int = None
    channel : int = None

    def convert_to_header(self):
        return None, self.timestamp

    @classmethod
    def convert_from_header(cls, pkt):
        metadata = ANTMetadata()
        metadata.is_crc_valid = True # TODO: update this field when we got a way
        metadata.timestamp = int(100000 * pkt.time)
        metadata.channel = 0
        return metadata

def generate_ant_metadata(message):
    metadata = ANTMetadata()

    if message.rssi is not None:
        metadata.rssi = message.rssi
    metadata.channel = message.channel
    if message.timestamp is not None:
        metadata.timestamp = message.timestamp
    if message.crc_validity is not None:
        metadata.is_crc_valid = message.crc_validity
    
    return metadata


@pb_bind(ProtocolHub, name="ant", version=1)
class AntDomain(Registry):
    """WHAD ANT domain messages parser/factory.
    """

    NAME = 'ant'
    VERSIONS = {}

    def __init__(self, version: int):
        """Initializes a ANT domain instance
        """
        self.proto_version = version

    def is_packet_compat(self, packet) -> bool:
        """Determine if a packet is an ANT packet.
        """
        return isinstance(packet.metadata, ANTMetadata)

    def convert_packet(self, packet) -> HubMessage:
        """Convert an ANT packet to SendPdu or SendRawPdu message.
        """
        if isinstance(packet.metadata, ANTMetadata):
            if packet.metadata.raw:
                return AntDomain.bound('send_raw', self.proto_version).from_packet(
                    packet
                )
            else:
                return AntDomain.bound('send', self.proto_version).from_packet(
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
        
        formatted_packet = packet # no transformation for now

        timestamp = None
        if hasattr(packet, "metadata"):
            timestamp = packet.metadata.timestamp

        return formatted_packet, timestamp

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD ANT Domain message as seen by protobuf
        """
        message_type = message.ant.WhichOneof('msg')
        message_clazz = AntDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)



    def create_set_device_number(self, channel_number: int,  device_number: int) -> HubMessage:
        """Create a SetDeviceNumber message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param device_number: Device Number to set (size must be 2 bytes)
        :type device_number: int
        :return: instance of `SetDeviceNumber`
        """
        return AntDomain.bound('set_device_number', self.proto_version)(
            channel_number=channel_number, 
            device_number=device_number
        )



    def create_set_device_type(self, channel_number: int,  device_type: int) -> HubMessage:
        """Create a SetDeviceNumber message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param device_type: Device Type to set (size must be 2 bytes)
        :type device_type: int
        :return: instance of `SetDeviceType`
        """
        return AntDomain.bound('set_device_type', self.proto_version)(
            channel_number=channel_number, 
            device_type=device_type
        )



    def create_set_transmission_type(self, channel_number: int,  transmission_type: int) -> HubMessage:
        """Create a SetTransmissionType message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param transmission_type: Transmission type to set (size must be 2 bytes)
        :type transmission_type: int
        :return: instance of `SetTransmissionType`
        """
        return AntDomain.bound('set_transmission_type', self.proto_version)(
            channel_number=channel_number, 
            transmission_type=transmission_type
        )

    def create_set_channel_period(self, channel_number: int,  channel_period: int) -> HubMessage:
        """Create a SetChannelPeriod message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param channel_period: Transmission type to set (size must be 2 bytes)
        :type channel_period: int
        :return: instance of `SetChannelPeriod`
        """
        return AntDomain.bound('set_channel_period', self.proto_version)(
            channel_number=channel_number, 
            channel_period=channel_period
        )
        

    def create_set_network_key(self, network_number: int,  network_key: bytes) -> HubMessage:
        """Create a SetNetworkKey message

        :param network_number: Network to configure
        :type network_number: int
        :param network_key: Network key to set (size must be 16 bytes)
        :type network_key: bytes
        :return: instance of `SetNetworkKey`
        """
        return AntDomain.bound('set_network_key', self.proto_version)(
            channel_number=channel_number, 
            network_key=network_key
        )
        

    def create_assign_channel(
                                self,
                                channel_number : int,
                                network_number: int,
                                channel_type: ChannelType, 
                                background_scanning : bool = False, 
                                frequency_agility : bool = False, 
                                fast_channel_initiation : bool = False, 
                                asynchronous_transmission : bool = False
        ) -> HubMessage:
        """Create an AssignChannel message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param network_number: Network to associate with the channel
        :type network_number: int
        :param channel_type: channel type assigned to the channel
        :type channel_type: instance of `ChannelType`
        :param background_scanning: indicate if the channel is set with background scanning
        :type background_scanning: bool
        :param frequency_agility: indicate if the channel is set with frequency agility
        :type frequency_agility: bool
        :param fast_channel_initiation: indicate if the channel is set with fast channel initiation
        :type fast_channel_initiation: bool
        :param asynchronous_transmission: indicate if the channel is set with asynchronous transmission
        :type asynchronous_transmission: bool
        :return: instance of `AssignChannel`
        """
        return AntDomain.bound('assign_channel', self.proto_version)(
            channel_number = channel_number, 
            network_number = network_number, 
            channel_type = channel_type, 
            background_scanning = background_scanning, 
            frequency_agility = frequency_agility, 
            fast_channel_initiation = fast_channel_initiation, 
            asynchronous_transmission = asynchronous_transmission
        )




    def create_unassign_channel(self, channel_number : int) -> HubMessage:
        """Create an UnassignChannel message

        :param channel_number: Channel to unassign
        :type channel_number: int
        :return: instance of `UnassignChannel`
        """
        return AntDomain.bound('unassign_channel', self.proto_version)(
            channel_number = channel_number
        )



    def create_open_channel(self, channel_number : int) -> HubMessage:
        """Create an OpenChannel message

        :param channel_number: Channel to open
        :type channel_number: int
        :return: instance of `OpenChannel`
        """
        return AntDomain.bound('open_channel', self.proto_version)(
            channel_number = channel_number
        )

        

    def create_close_channel(self, channel_number : int) -> HubMessage:
        """Create a CloseChannel message

        :param channel_number: Channel to close
        :type channel_number: int
        :return: instance of `CloseChannel`
        """
        return AntDomain.bound('close_channel', self.proto_version)(
            channel_number = channel_number
        )


    def create_set_frequency(self, channel_number : int, frequency : int) -> HubMessage:
        """Create a SetFrequency message

        :param channel_number: Channel to configure
        :type channel_number: int
        :param frequency: Frequency used to configure the channel (in MHz)
        :type frequency: int
        :return: instance of `SetFrequency`
        """
        return AntDomain.bound('set_frequency', self.proto_version)(
            channel_number = channel_number, 
            frequency = frequency
        )
        

    def create_sniff(
                        self,
                        frequency : int,
                        network_key : bytes, 
                        device_number : int, 
                        device_type : int, 
                        transmission_type : int
    ) -> HubMessage:
        """Create a Sniff message

        :param frequency: Frequency to monitor (in MHz)
        :type frequency: int
        :param network_key: Network key to use to decrypt traffic
        :type network_key: bytes
        :param device_number: device number to sniff
        :type device_number: int
        :param device_type: device type to sniff
        :type device_type: int
        :param transmission_type: transmission type to sniff
        :type transmission_type: int
        :return: instance of `Sniff`
        """
        return AntDomain.bound('sniff', self.proto_version)(
            frequency = frequency, 
            network_key = network_key, 
            device_number = device_number, 
            device_type = device_type, 
            transmission_type = transmission_type 
        )
        

    def create_jam(
                        self,
                        frequency : int
    ) -> HubMessage:
        """Create a Jam message

        :param frequency: Frequency to jam (in MHz)
        :type frequency: int
        :return: instance of `Jam`
        """
        return AntDomain.bound('jam', self.proto_version)(
            frequency = frequency 
        )
        

    def create_send(
                        self,
                        frequency : int, 
                        pdu : bytes
    ) -> HubMessage:
        """Create a Send message

        :param frequency: Frequency to use (in MHz)
        :type frequency: int
        :param pdu: PDU to send
        :type pdu: bytes
        :return: instance of `Send`
        """
        return AntDomain.bound('send', self.proto_version)(
            frequency = frequency, 
            pdu = pdu
        )


    def create_send_raw(
                        self,
                        frequency : int, 
                        pdu : bytes
    ) -> HubMessage:
        """Create a SendRaw message

        :param frequency: Frequency to use (in MHz)
        :type frequency: int
        :param pdu: Raw PDU to send
        :type pdu: bytes
        :return: instance of `SendRaw`
        """
        return AntDomain.bound('send_raw', self.proto_version)(
            frequency = frequency, 
            pdu = pdu
        )

    def create_master_mode(
                        self,
                        channel_number : int
    ) -> HubMessage:
        """Create a MasterMode message

        :param channel_number: Channel to use
        :type channel_number: int
        :return: instance of `MasterMode`
        """
        return AntDomain.bound('master_mode', self.proto_version)(
            channel_number = channel_number
        )



    def create_slave_mode(
                        self,
                        channel_number : int
    ) -> HubMessage:
        """Create a SlaveMode message

        :param channel_number: Channel to use
        :type channel_number: int
        :return: instance of `SlaveMode`
        """
        return AntDomain.bound('slave_mode', self.proto_version)(
            channel_number = channel_number
        )



    def create_start(self) -> HubMessage:
        """Create a Start message
        
        :return: instance of `Start`
        """
        return AntDomain.bound('start', self.proto_version)()


    def create_stop(self) -> HubMessage:
        """Create a Stop message
        
        :return: instance of `Stop`
        """
        return AntDomain.bound('stop', self.proto_version)()
        


    def create_jammed(self, timestamp : int = None) -> HubMessage:
        """Create a Jammed notification

        :param timestamp: Timestamp (in us) of Jammed notification
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return AntDomain.bound('jammed', self.proto_version)(
            timestamp = timestamp
        )

    def create_pdu_received(
                        self,
                        channel_number : int, 
                        pdu : bytes, 
                        rssi : int = None, 
                        timestamp : int = None, 
                        crc_validity : bool = True,
    ) -> HubMessage:
        """Create a PduReceived notification

        :param channel_number: Channel to use
        :type channel_number: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param rssi: RSSI of the received packet in dBm (optional)
        :type rssi: int
        :param timestamp: Timestamp (in us) of PDU received notification
        :type timestamp: int
        :param crc_validity: indicate if the CRC of the PDU is valid
        :type crc_validity:bool
        :return: instance of `PduReceived`
        """
        return AntDomain.bound('pdu', self.proto_version)(
            channel_number = channel_number, 
            pdu = pdu, 
            rssi = rssi, 
            timestamp = timestamp, 
            crc_validity = crc_validity
        )

    def create_raw_pdu_received(
                        self,
                        channel_number : int, 
                        pdu : bytes, 
                        crc : int, 
                        rssi : int = None, 
                        timestamp : int = None, 
                        crc_validity : bool = True,
    ) -> HubMessage:
        """Create a RawPduReceived notification

        :param channel_number: Channel to use
        :type channel_number: int
        :param pdu: Received PDU
        :type pdu: bytes
        :param crc: Received PDU's CRC value (2-bytes integer format)
        :type crc: int
        :param rssi: RSSI of the received packet in dBm (optional)
        :type rssi: int
        :param timestamp: Timestamp (in us) of PDU received notification
        :type timestamp: int
        :param crc_validity: indicate if the CRC of the PDU is valid
        :type crc_validity:bool
        :return: instance of `RawPduReceived`
        """
        return AntDomain.bound('raw_pdu', self.proto_version)(
            channel_number = channel_number, 
            pdu = pdu, 
            crc = crc,
            rssi = rssi, 
            timestamp = timestamp, 
            crc_validity = crc_validity, 
        )

