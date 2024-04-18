"""WHAD Protocol Bluetooth Low Energy domain message abstraction layer.
"""
from typing import List

from whad.protocol.ble.ble_pb2 import BleDirection, BleAdvType, BleAddrType
from whad.protocol.hub.message import HubMessage
from whad.protocol.hub import pb_bind, Registry, ProtocolHub
from whad.ble.bdaddr import BDAddress
from whad.ble.chanmap import ChannelMap

class Direction:
    """BLE PDU direction
    """
    UNKNOWN = BleDirection.UNKNOWN
    MASTER_TO_SLAVE = BleDirection.MASTER_TO_SLAVE
    SLAVE_TO_MASTER = BleDirection.SLAVE_TO_MASTER
    INJECTION_TO_SLAVE = BleDirection.INJECTION_TO_SLAVE
    INJECTION_TO_MASTER = BleDirection.INJECTION_TO_MASTER

class AdvType:
    ADV_UNKNOWN = BleAdvType.ADV_UNKNOWN
    ADV_IND = BleAdvType.ADV_IND
    ADV_DIRECT_IND = BleAdvType.ADV_DIRECT_IND
    ADV_NONCONN_IND = BleAdvType.ADV_NONCONN_IND
    ADV_SCAN_IND = BleAdvType.ADV_SCAN_IND
    ADV_SCAN_RSP = BleAdvType.ADV_SCAN_RSP

class AddressType:
    PUBLIC = BleAddrType.PUBLIC
    RANDOM = BleAddrType.RANDOM

@pb_bind(ProtocolHub, name="ble", version=1)
class BleDomain(Registry):
    """WHAD BLE domain messages parser/factory.
    """

    def __init__(self, version: int):
        """Initializes a BLE domain instance
        """
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD BleDomain message as seen by protobuf
        """
        message_type = message.ble.WhichOneof('msg')
        message_clazz = BleDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)

    def createSetBdAddress(self, bd_address: BDAddress) -> HubMessage:
        """Create a SetBdAddress message.

        :param bd_address: BD address to set
        :type bd_address: BDAddress
        :return: SetBdAddress message
        :return-type: HubMessage
        """
        return BleDomain.bound('set_bd_addr', self.proto_version)(
            bd_address=bd_address.value,
            addr_type=AddressType.PUBLIC if bd_address.is_public() else AddressType.RANDOM
        )
    
    def createSniffAdv(self, channel: int, bd_address: BDAddress = None,
                       use_ext_adv: bool = False) -> HubMessage:
        """Create a SniffAdv message.

        :param channel: BLE channel to listen on
        :type channel: int
        :param bd_address: BD address to target, if given
        :type bd_address: BDAddress, optional
        :param use_ext_adv: Use extended advertisements
        :type use_ext_adv: bool, optional
        :return: instance of SniffAdv message
        :return-type: HubMessage
        """
        if bd_address is not None:
            target_address = bd_address
        else:
            target_address = BDAddress('FF:FF:FF:FF:FF:FF')
        return BleDomain.bound('sniff_adv', self.proto_version)(
            bd_address=target_address.value,
            channel=channel,
            use_extended_adv=use_ext_adv
        )
    
    def createSniffConnReq(self, channel: int, bd_address: BDAddress = None,
                           show_empty: bool = False, show_adv: bool = False) -> HubMessage:
        """Create a SniffConnReq message.

        :param channel: BLE channel to listen on
        :type channel: int
        :param bd_address: BD address to target, if given
        :type bd_address: BDAddress, optional
        :param show_empty: Report empty PDUs
        :type show_empty: bool, optional
        :param show_adv: Report advertisements
        :type show_adv: bool, optional
        :return-type: HubMessage 
        """
        if bd_address is not None:
            target_address = bd_address
        else:
            target_address = BDAddress('FF:FF:FF:FF:FF:FF')
        return BleDomain.bound('sniff_connreq', self.proto_version)(
            bd_address=target_address.value,
            channel=channel,
            show_empty_packets=show_empty,
            show_advertisements=show_adv
        )
    
    def createSniffAccessAddress(self, channels: List[int]) -> HubMessage:
        """Create a SniffAccessAddress message.

        :param channels: List of channels
        :type channels: list
        :return: an instance of SniffAccessAddress message
        :return-type: HubMessage
        """
        return BleDomain.bound('sniff_aa', self.proto_version)(
            monitored_channels=bytes(channels)
        )
    
    def createSniffActiveConn(self, access_address: int, crc_init: int = None,
                              channel_map: ChannelMap = None, interval: int = None,
                              increment: int = None, channels: List[int] = None):
        """Create a SniffActiveConn message.

        :param access_address: Target connection access address
        :type access_address: int
        :param crc_init: Connection CRC initial seed value
        :type crc_init: int, optional
        :param channel_map: Channel map to use when sniffing connection
        :type channel_map: ChannelMap, optional
        :param interval: Hop interval to use when sniffing connection
        :type interval: int, optional
        :param increment: Hop increment to use when sniffing connection
        :type increment: int, optional
        :param channels: Channels to sniff on when recovering connection parameters
        :type channels: list, optional
        :return: instance of SniffActiveConn message
        :return-type: SniffActiveConn
        """
        # Create default SniffConnReq message
        sniff_connreq = BleDomain.bound('sniff_conn', self.proto_version)(
            access_address=access_address
        )

        # Add optional fields if provided
        if crc_init is not None:
            sniff_connreq.crc_init = crc_init
        if channel_map is not None:
            sniff_connreq.channel_map = channel_map.value
        if interval is not None:
            sniff_connreq.hop_interval = interval
        if increment is not None:
            sniff_connreq.hop_increment = increment
        if channels is not None:
            sniff_connreq.monitored_channels = bytes(channels)

        # Return the created SniffConnReq message
        return sniff_connreq
    
    def createAccessAddressDiscovered(self, access_address: int, rssi: int, timestamp: int) -> HubMessage:
        """Create an AccessAddressDiscovered notification message.

        :param access_address: Discovered access address
        :type access_address: int
        :param rssi: Received Signal Strength Indicator
        :type rssi: int
        :param timestamp: Timestamp at which the access address has been discovered
        :type timestamp: int
        :return: instance of AccessAddressDiscovered
        :return-type: AccessAddressDiscovered
        """
        return BleDomain.bound('aa_disc', self.proto_version)(
            access_address=access_address,
            rssi=rssi,
            timestamp=timestamp
        )
    
    def createJamAdv(self) -> HubMessage:
        """Create a JamAdv message.

        :return: instance of JamAdv message
        :return-type: JamAdv
        """
        return BleDomain.bound('jam_adv', self.proto_version)()
    
    def createJamAdvChan(self, channel: int) -> HubMessage:
        """Create a JamAdvChan message.

        :param channel: Advertising channel to jam
        :type channel: int
        :return: instance of JamAdvChan
        :return-type: JamAdvChan
        """
        return BleDomain.bound('jam_adv_chan', self.proto_version)(
            channel=channel
        )
    
    def createJamConn(self, access_address: int) -> HubMessage:
        """Create a JamConn message.

        :param access_address: Target connection access address
        :type access_address: int
        :return: instance of JamConn message
        :return-type: JamConn
        """
        return BleDomain.bound('jam_conn', self.proto_version)(
            access_address=access_address
        )
    
    def createReactiveJam(self, channel: int, pattern: bytes, position: int) -> HubMessage:
        """Create a ReactiveJam message.

        :param channel: Target channel
        :type channel: int
        :param pattern: Trigger pattern
        :type pattern: bytes
        :param position: Triger pattern position
        :type position: int
        :return: instance of ReactiveJam
        :return-type: ReactiveJam
        """
        return BleDomain.bound('reactive_jam', self.proto_version)(
            channel=channel,
            pattern=pattern,
            position=position
        )


from .address import SetBdAddress
from .sniffing import SniffAdv, SniffConnReq, SniffAccessAddress, SniffActiveConn, \
    AccessAddressDiscovered
from .jamming import JamAdv, JamAdvChan, JamConn, ReactiveJam
from .mode import ScanMode, AdvMode, CentralMode, PeriphMode, Start, Stop
from .pdu import SetAdvData, SendRawPdu, SendPdu, AdvPduReceived, PduReceived, \
    RawPduReceived, Injected
from .connect import ConnectTo, Disconnect, Connected, Disconnected, Synchronized, \
    Desynchronized
from .hijack import HijackMaster, HijackSlave, HijackBoth, Hijacked
from .triggers import PrepareSequenceManual, PrepareSequenceConnEvt, \
    PrepareSequencePattern, PrepareSequence

__all__ = [
    "AdvType",
    "Direction",
    "AddressType",
    "BleDomain",
    "SetBdAddress",
    "SniffAdv",
    "SniffConnReq",
    "SniffAccessAddress",
    "SniffActiveConn",
    "AccessAddressDiscovered",
    "JamAdv",
    "JamAdvChan",
    "JamConn",
    "ReactiveJam",
    "ScanMode",
    "AdvMode",
    "CentralMode",
    "PeriphMode",
    "SetAdvData",
    "SendRawPdu",
    "SendPdu",
    "AdvPduReceived",
    "PduReceived",
    "RawPduReceived",
    "ConnectTo",
    "Disconnect",
    "Connected",
    "Disconnected",
    "Start",
    "Stop",
    "HijackMaster",
    "HijackSlave",
    "HijackBoth",
    "Hijacked",
    "Injected",
    "Synchronized",
    "Desynchronized",
    "PrepareSequenceManual",
    "PrepareSequenceConnEvt",
    "PrepareSequencePattern",
    "PrepareSequence"
]