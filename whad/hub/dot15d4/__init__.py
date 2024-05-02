"""WHAD Protocol 802.15.4 domain message abstraction layer.
"""
from typing import List

from whad.protocol.zigbee.zigbee_pb2 import ZigbeeMitmRole, AddressType
from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub

class MitmRole:
    """Dot15d4 Mitm role
    """
    REACTIVE=ZigbeeMitmRole.REACTIVE_JAMMER
    CORRECTOR=ZigbeeMitmRole.CORRECTOR

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

@pb_bind(ProtocolHub, name="zigbee", version=1)
class Dot15d4Domain(Registry):
    """WHAD Dot15d4 domain messages parser/factory.
    """

    def __init__(self, version: int):
        """Initializes a Dot15d4 domain instance
        """
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD Dot15d4 Domain message as seen by protobuf
        """
        message_type = message.zigbee.WhichOneof('msg')
        message_clazz = Dot15d4Domain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)
    
    def createSetNodeAddress(self, address: NodeAddress) -> HubMessage:
        """Create a SetNodeAddress message.

        :param address: instance of `Dot15d4Address`
        :type address: NodeAddress
        :return: instance of `SetNodeAddress`
        """
        return Dot15d4Domain.bound('set_node_addr', self.proto_version)(
            address=address.address,
            addr_type=address.address_type
        )
    
    def createSniffMode(self, channel: int) -> HubMessage:
        """Create a SniffMode message

        :param channel: Channel to sniff
        :type channel: int
        :return: instance of `SniffMode`
        """
        return Dot15d4Domain.bound('sniff', self.proto_version)(
            channel=channel
        )
    
    def createJamMode(self, channel: int) -> HubMessage:
        """Create a JamMode message

        :param channel: Channel to jam
        :type channel: int
        :return: instance of `JamMode`
        """
        return Dot15d4Domain.bound('jam', self.proto_version)(
            channel=channel
        )
    
    def createEnergyDetectionMode(self, channel: int) -> HubMessage:
        """Create a EnergyDetectionMode message

        :param channel: Channel to detect
        :type channel: int
        :return: instance of `EnergyDetectionMode`
        """
        return Dot15d4Domain.bound('ed', self.proto_version)(
            channel=channel
        )
    
    def createEndDeviceMode(self, channel: int) -> HubMessage:
        """Create a EndDeviceMode message

        :param channel: Channel to use for end device
        :type channel: int
        :return: instance of `EndDeviceMode`
        """
        return Dot15d4Domain.bound('end_device', self.proto_version)(
            channel=channel
        )
    
    def createRouterMode(self, channel: int) -> HubMessage:
        """Create a RouterMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `RouterMode`
        """
        return Dot15d4Domain.bound('router', self.proto_version)(
            channel=channel
        )
    
    def createCoordMode(self, channel: int) -> HubMessage:
        """Create a CoordMode message

        :param channel: Channel to use for router
        :type channel: int
        :return: instance of `CoordMode`
        """
        return Dot15d4Domain.bound('coordinator', self.proto_version)(
            channel=channel
        )
    
    def createMitmMode(self, role: int) -> HubMessage:
        """Create a MitmMode message

        :return: instance of `MitmMode`
        """
        return Dot15d4Domain.bound('mitm', self.proto_version)(
            role=role
        )

    def createStart(self) -> HubMessage:
        """Create a Start message

        :return: instance of `Start`
        """
        return Dot15d4Domain.bound('start', self.proto_version)()
    
    def createStop(self) -> HubMessage:
        """Create a Stop message

        :return: instance of `Stop`
        """
        return Dot15d4Domain.bound('stop', self.proto_version)()
    
    def createSendPdu(self, channel: int, pdu: bytes) -> HubMessage:
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
    
    def createSendRawPdu(self, channel: int, pdu: bytes, fcs: int) -> HubMessage:
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
    
    def createJammed(self, timestamp: int) -> HubMessage:
        """Create a jammed notification.

        :param timestamp: Timestamp when jamming is successful
        :type timestamp: int
        :return: instance of `Jammed`
        """
        return Dot15d4Domain.bound('jammed', self.proto_version)(
            timestamp=timestamp
        )

    def createEnergyDetectionSample(self, timestamp: int, sample: int) -> HubMessage:
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
    
    def createRawPduReceived(self, channel: int, pdu: bytes, fcs: int, rssi: int = None, \
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

    def createPduReceived(self, channel: int, pdu: bytes, rssi: int = None, \
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
    'EnergyDetectionSample'
]