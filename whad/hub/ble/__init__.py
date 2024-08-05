"""WHAD Protocol Bluetooth Low Energy domain message abstraction layer.
"""
from typing import List
from dataclasses import dataclass, field, fields

from .bdaddr import BDAddress
from .chanmap import ChannelMap

from scapy.layers.bluetooth4LE import BTLE_RF, BTLE, BTLE_ADV, BTLE_DATA

from whad.protocol.ble.ble_pb2 import BleDirection, BleAdvType, BleAddrType
from whad.hub.registry import Registry
from whad.hub.message import HubMessage, pb_bind
from whad.hub import ProtocolHub
from whad.hub.metadata import Metadata

class Commands:
    """BLE Commands
    """
    SetBdAddress = 0x00
    SniffAdv = 0x01
    JamAdv = 0x02
    JamAdvOnChannel = 0x03
    ReactiveJam = 0x04
    SniffConnReq = 0x05
    SniffAccessAddress = 0x06
    SniffActiveConn = 0x07
    JamConn = 0x08
    ScanMode = 0x09
    AdvMode = 0x0a
    SetAdvData = 0x0b
    CentralMode = 0x0c
    ConnectTo = 0x0d
    SendRawPDU = 0x0e
    SendPDU = 0x0f
    Disconnect = 0x10
    PeripheralMode = 0x11
    Start = 0x12
    Stop = 0x13
    SetEncryption = 0x14
    HijackMaster = 0x15
    HijackSlave = 0x16
    HijackBoth = 0x17
    PrepareSequence = 0x18
    TriggerSequence = 0x19
    DeleteSequence = 0x1a


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
    
@dataclass(repr=False)
class BLEMetadata(Metadata):
    direction : BleDirection = None
    connection_handle : int = None
    is_crc_valid : bool = None
    relative_timestamp : int = None
    decrypted : bool = None

    @classmethod
    def convert_from_header(cls, pkt):
        header = pkt[BTLE_RF]
        if header.type == 2:
            direction = BleDirection.MASTER_TO_SLAVE
        elif header.type == 3:
            direction = BleDirection.SLAVE_TO_MASTER
        else:
            direction = BleDirection.UNKNOWN

        channel = header.rf_channel
        is_crc_valid = header.crc_valid == 1
        rssi = header.signal

        return BLEMetadata(
            direction = direction,
            is_crc_valid = is_crc_valid,
            rssi = rssi,
            channel = channel,
            timestamp = int(100000 * pkt.time)
        )

    def convert_to_header(self):
        timestamp = None
        packet_type = 0 # ADV_OR_DATA_UNKNOWN_DIR
        signal = -128
        crc_checked = 0
        crc_valid = 0
        sig_power_valid = 0
        dewhitened = 1
        rf_channel = 0
        if self.direction is not None:
            if self.direction == BleDirection.MASTER_TO_SLAVE:
                packet_type = 2
            elif self.direction == BleDirection.SLAVE_TO_MASTER:
                packet_type = 3
        if self.timestamp is not None:
            timestamp = self.timestamp
        if self.rssi is not None:
            sig_power_valid = 1
            signal = self.rssi
        if self.is_crc_valid is not None:
            crc_checked = 1
            crc_valid = self.is_crc_valid
        if self.channel is not None:
            rf_channel = self.channel

        header = BTLE_RF(
            rf_channel = rf_channel,
            type = packet_type,
            signal = signal,
            crc_checked = crc_checked,
            crc_valid = crc_valid,
            sig_power_valid = sig_power_valid,
            dewhitened = dewhitened
        )
        return header, timestamp

def generate_ble_metadata(message):
    metadata = BLEMetadata()
    if isinstance(message, BleRawPduReceived):
        metadata.direction = message.direction
        if message.rssi is not None:
            metadata.rssi = message.rssi
        metadata.channel = message.channel
        if message.timestamp is not None:
            metadata.timestamp = message.timestamp
        if message.crc_validity is not None:
            metadata.is_crc_valid = message.crc_validity
        if message.relative_timestamp is not None:
            metadata.relative_timestamp = message.relative_timestamp
            metadata.decrypted = message.decrypted

        metadata.connection_handle = message.conn_handle

    elif isinstance(message, BleAdvPduReceived):
        metadata.direction = BleDirection.UNKNOWN
        metadata.rssi = message.rssi

    elif isinstance(message, BlePduReceived):
        metadata.connection_handle = message.conn_handle
        metadata.direction = message.direction
        metadata.decrypted = message.decrypted

    elif isinstance(message, SendBlePdu):
        metadata.connection_handle = message.conn_handle
        metadata.direction = message.direction

    elif isinstance(message, SendBleRawPdu):
        metadata.direction = message.direction
        metadata.crc = message.crc
        metadata.connection_handle = message.conn_handle

    return metadata

@pb_bind(ProtocolHub, name="ble", version=1)
class BleDomain(Registry):
    """WHAD BLE domain messages parser/factory.
    """

    NAME = 'ble'
    VERSIONS = {}

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

    def is_packet_compat(self, packet) -> bool:
        """Determine if a packet is a compatible BLE packet
        """
        return isinstance(packet.metadata, BLEMetadata)

    def convert_packet(self, packet) -> HubMessage:
        """Convert a BLE packet to SendPdu or SendBlePdu message.
        """
        if isinstance(packet.metadata, BLEMetadata):
            if packet.metadata.raw:
                return BleDomain.bound('send_raw_pdu', self.proto_version).from_packet(
                    packet, encrypt=packet.metadata.encrypt
                )
            else:
                return BleDomain.bound('send_pdu', self.proto_version).from_packet(
                    packet, encrypt=packet.metadata.encrypt
                )
        else:
            # Error
            return None

    def format(self, packet):
        """Convert this message to its scapy representation with the
        appropriate header and timestamp in microseconds.
        """
        formatted_packet = packet
        if BTLE not in packet:
            if BTLE_ADV in packet:
                formatted_packet = BTLE(access_addr=0x8e89bed6)/packet
            elif BTLE_DATA in packet:
                # We are forced to use a pseudo access address for connections in this case.
                formatted_packet = BTLE(access_addr=0x11223344) / packet

        timestamp = None
        if hasattr(packet, "metadata"):
            header, timestamp = packet.metadata.convert_to_header()
            formatted_packet = header / formatted_packet
        else:
            header = BTLE_RF()
            formatted_packet = header / formatted_packet

        return formatted_packet, timestamp

    def create_set_bd_address(self, bd_address: BDAddress) -> HubMessage:
        """Create a SetBdAddress message.

        :param bd_address: BD address to set
        :type bd_address: BDAddress
        :return: SetBdAddress message
        :rtype: HubMessage
        """
        return BleDomain.bound('set_bd_addr', self.proto_version)(
            bd_address=bd_address.value,
            addr_type=AddressType.PUBLIC if bd_address.is_public() else AddressType.RANDOM
        )

    def create_sniff_adv(self, channel: int, bd_address: BDAddress = None,
                       use_ext_adv: bool = False) -> HubMessage:
        """Create a SniffAdv message.

        :param channel: BLE channel to listen on
        :type channel: int
        :param bd_address: BD address to target, if given
        :type bd_address: BDAddress, optional
        :param use_ext_adv: Use extended advertisements
        :type use_ext_adv: bool, optional
        :return: instance of SniffAdv message
        :rtype: HubMessage
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

    def create_sniff_connreq(self, channel: int, bd_address: BDAddress = None,
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
        :rtype: HubMessage
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

    def create_sniff_access_address(self, channels: List[int]) -> HubMessage:
        """Create a SniffAccessAddress message.

        :param channels: List of channels
        :type channels: list
        :return: an instance of SniffAccessAddress message
        :rtype: HubMessage
        """
        return BleDomain.bound('sniff_aa', self.proto_version)(
            monitored_channels=ChannelMap(channels).value
        )

    def create_sniff_active_conn(self, access_address: int, crc_init: int = None,
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
        :rtype: SniffActiveConn
        """
        # Create default createSniffActiveConn message
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

    def create_access_address_discovered(self, access_address: int, rssi: int, timestamp: int) -> HubMessage:
        """Create an AccessAddressDiscovered notification message.

        :param access_address: Discovered access address
        :type access_address: int
        :param rssi: Received Signal Strength Indicator
        :type rssi: int
        :param timestamp: Timestamp at which the access address has been discovered
        :type timestamp: int
        :return: instance of AccessAddressDiscovered
        :rtype: AccessAddressDiscovered
        """
        return BleDomain.bound('aa_disc', self.proto_version)(
            access_address=access_address,
            rssi=rssi,
            timestamp=timestamp
        )

    def create_jam_adv(self) -> HubMessage:
        """Create a JamAdv message.

        :return: instance of JamAdv message
        :rtype: JamAdv
        """
        return BleDomain.bound('jam_adv', self.proto_version)()

    def create_jam_adv_chan(self, channel: int) -> HubMessage:
        """Create a JamAdvChan message.

        :param channel: Advertising channel to jam
        :type channel: int
        :return: instance of JamAdvChan
        :rtype: JamAdvChan
        """
        return BleDomain.bound('jam_adv_chan', self.proto_version)(
            channel=channel
        )

    def create_jam_conn(self, access_address: int) -> HubMessage:
        """Create a JamConn message.

        :param access_address: Target connection access address
        :type access_address: int
        :return: instance of JamConn message
        :rtype: JamConn
        """
        return BleDomain.bound('jam_conn', self.proto_version)(
            access_address=access_address
        )

    def create_reactive_jam(self, channel: int, pattern: bytes, position: int) -> HubMessage:
        """Create a ReactiveJam message.

        :param channel: Target channel
        :type channel: int
        :param pattern: Trigger pattern
        :type pattern: bytes
        :param position: Triger pattern position
        :type position: int
        :return: instance of ReactiveJam
        :rtype: ReactiveJam
        """
        return BleDomain.bound('reactive_jam', self.proto_version)(
            channel=channel,
            pattern=pattern,
            position=position
        )

    def create_scan_mode(self, active: bool = False) -> HubMessage:
        """Create a ScanMode message.

        :param active: Enable active scan mode
        :type active: bool
        :return: instance of ScanMode
        :rtype: ScanMode
        """
        return BleDomain.bound('scan_mode', self.proto_version)(
            active=active
        )

    def create_adv_mode(self, adv_data: bytes, scan_rsp: bytes = None) -> HubMessage:
        """Create an AdvMode message.

        :param adv_data: Advertisement data (31 bytes max)
        :type adv_data: bytes
        :param scan_rsp: Scan response data (31 bytes max)
        :type scan_rsp: bytes, optional
        :return: instance of AdvMode message
        :rtype: AdvMode
        """
        message = BleDomain.bound('adv_mode', self.proto_version)(
            scan_data=adv_data
        )
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp
        return message

    def create_central_mode(self) -> HubMessage:
        """Create a CentralMode message.

        :return: instance of CentralMode message
        :rtype: CentralMode
        """
        return BleDomain.bound('central_mode', self.proto_version)()

    def create_periph_mode(self, adv_data: bytes = None, scan_rsp: bytes = None) -> HubMessage:
        """Create an PeriphMode message.

        :param adv_data: Advertisement data (31 bytes max)
        :type adv_data: bytes
        :param scan_rsp: Scan response data (31 bytes max)
        :type scan_rsp: bytes, optional
        :return: instance of PeriphMode message
        :rtype: PeriphMode
        """
        message = BleDomain.bound('periph_mode', self.proto_version)(
        )
        if adv_data is not None:
            message.scan_data = adv_data
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp
        return message

    def create_start(self) -> HubMessage:
        """Create a Start message.

        :return: instance of Start message
        :rtype: Start
        """
        return BleDomain.bound("start", self.proto_version)()

    def create_stop(self) -> HubMessage:
        """Create a Stop message.

        :return: instance of Stop message
        :rtype: Stop
        """
        return BleDomain.bound("stop", self.proto_version)()

    def create_connect_to(self, bd_address: BDAddress = None, access_address: int = None,
                        channel_map: ChannelMap = None, interval: int = None,
                        increment: int = None, crc_init: int = None) ->HubMessage:
        """Create a ConnectTo message.

        :param bd_address: Target BD address
        :type bd_address: BDAddress, optional
        :param access_address: Access address to synchronize with
        :type access_address: int, optional
        :param channel_map: Channel map to use with the connection
        :type channel_map: ChannelMap, optional
        :param interval: Hop interval to use
        :type interval: int, optional
        :param increment: Hop increment to use
        :type increment: int, optional
        :param crc_init: CRC initial value to use
        :type crc_init: int, optional
        :return: instance of ConnectTo message
        :rtype: ConnectTo
        """
        message = BleDomain.bound("connect", self.proto_version)()

        # Set bd address if provided
        if bd_address is not None:
            message.bd_address = bd_address.value
            message.addr_type = AddressType.PUBLIC if bd_address.is_public() else AddressType.RANDOM

        # Set access address if provided
        if access_address is not None:
            message.access_address = access_address

        # Set channel map if provided
        if channel_map is not None:
            message.channel_map = channel_map.value

        # Set hop interval if provided
        if interval is not None:
            message.hop_interval = interval

        # Set hop increment if provided
        if increment is not None:
            message.hop_increment = increment

        # Set crc init
        if crc_init is not None:
            message.crc_init = crc_init

        return message


    def create_disconnect(self, conn_handle: int) -> HubMessage:
        """Create a Disconnect message.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: instance of Disconnect message
        :rtype: Disconnect
        """
        return BleDomain.bound("disconnect", self.proto_version)(
            conn_handle=conn_handle
        )

    def create_synchronized(self, access_address: int, interval: int, increment: int,\
                           channel_map: ChannelMap, crc_init: int) -> HubMessage:
        """Create a Synchronized message.

        :param access_address: Connection access address
        :type access_address: int
        :param interval: Connection hop interval
        :type interval: int
        :param increment: Connection hop increment
        :type increment: int
        :param channel_map: Connection channel map
        :type channel_map: ChannelMap
        :return: instance of Synchronized
        :rtype: Synchronized
        """
        return BleDomain.bound("synchronized", self.proto_version)(
            access_address=access_address,
            crc_init=crc_init,
            hop_interval=interval,
            hop_increment=increment,
            channel_map=channel_map.value
        )

    def create_connected(self, initiator: BDAddress, advertiser: BDAddress, \
                        access_address: int, conn_handle: int) -> HubMessage:
        """Create a Connected message.

        :param initiator: Connection initiator BD address
        :type initiator: BDAddress
        :param advertiser: Connection advertiser BD address
        :type advertiser: BDAddress
        :param access_address: Connection access address
        :type access_address: int
        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: instance of a Connected message
        :rtype: Connected
        """
        return BleDomain.bound("connected", self.proto_version)(
            initiator=initiator.value,
            advertiser=advertiser.value,
            access_address=access_address,
            conn_handle=conn_handle,
            adv_addr_type=AddressType.PUBLIC if advertiser.is_public() else AddressType.RANDOM,
            init_addr_type=AddressType.PUBLIC if initiator.is_public() else AddressType.RANDOM
        )

    def create_disconnected(self, reason: int, conn_handle: int) -> HubMessage:
        """Create a Disconnected message.

        :param reason: Disconnection reason
        :type reason: int
        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: instance of Disconnected
        :rtype: Disconnected
        """
        return BleDomain.bound("disconnected", self.proto_version)(
            reason=reason,
            conn_handle=conn_handle
        )

    def create_desynchronized(self, accesss_address: int) -> HubMessage:
        """Create a Desynchronized message.

        :param access_address: Connection access address
        :type access_address: int
        :return: instance of Desynchronized
        :rtype: Desynchronized
        """
        return BleDomain.bound("desynchronized", self.proto_version)(
            accesss_address=accesss_address
        )

    def create_set_adv_data(self, adv_data: bytes, scan_rsp: bytes = None) -> HubMessage:
        """Create a SetAdvData message.

        :param adv_data: Advertising data
        :type adv_data: bytes
        :param scan_rsp: Scan response data
        :type scan_rsp: bytes, optional
        :return: instance of SetAdvData message
        :rtype: SetAdvData
        """
        message = BleDomain.bound("set_adv_data", self.proto_version)(
            scan_data=adv_data
        )

        # Set scan response data if provided
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp

        return message

    def create_send_raw_pdu(self, direction: int, pdu: bytes, \
                         crc: int = None, encrypt: bool = False, \
                         access_address: int = None, conn_handle: int = None) -> HubMessage:
        """Create a SendRawPdu message.

        :param direction: PDU direction
        :type direction: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param crc: PDU CRC value
        :type crc: int, optional
        :param conn_handle: Connection handle
        :type conn_handle: int, optional
        :param encrypt: Encrypt PDU before sending
        :type encrypt: bool, optional
        :param access_address: Connection access address
        :type access_address: int, optional
        :return: instance of SendRawPdu message
        :rtype: SendRawPdu
        """
        # Create a SendRawPdu message
        message = BleDomain.bound("send_raw_pdu", self.proto_version)(
            direction=direction,
            pdu=pdu
        )

        # Set optional fields
        if conn_handle is not None:
            message.conn_handle = conn_handle
        if crc is not None:
            message.crc = crc
        if access_address is not None:
            message.access_address= access_address
        if encrypt:
            message.encrypt=True
        else:
            message.encrypt=False

        # Return message
        return message

    def create_send_pdu(self, direction: int, pdu: bytes, conn_handle: int, \
                      encrypt: bool = False) -> HubMessage:
        """Create a SendBlePdu message.

        :param direction: PDU direction
        :type direction: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param conn_handle: Connection handle
        :type conn_handle: int, optional
        :param encrypt: Encrypt PDU before sending
        :type encrypt: bool, optional
        :return: instance of SendRawPdu message
        :rtype: SendBleRawPdu
        """
        return BleDomain.bound("send_pdu", self.proto_version)(
            direction=direction,
            conn_handle=conn_handle,
            pdu=pdu,
            encrypt=encrypt
        )

    def create_adv_pdu_received(self, adv_type: AdvType, rssi: int, bd_address: BDAddress, \
                             adv_data: bytes):
        """Create an AdvPduReceived message

        :param adv_type: Advertisement type
        :type adv_type: AdvType
        :param rssi: Received Signal Strength Indicator
        :type rssi: int
        :param bd_address: Advertiser BD address
        :type bd_address: BDAddress
        :param adv_data: Advertisement data
        :type adv_data: bytes
        :return: instance of AdvPduReceived
        :rtype: AdvPduReceived
        """
        return BleDomain.bound("adv_pdu", self.proto_version)(
            adv_type=adv_type,
            rssi=rssi,
            bd_address=bd_address.value,
            adv_data=adv_data,
            addr_type=AddressType.PUBLIC if bd_address.is_public() else AddressType.RANDOM
        )

    def create_pdu_received(self, direction: int, pdu: bytes, conn_handle: int, \
                          processed: bool = False, decrypted: bool = False) -> HubMessage:
        """Create a PduReceived message

        :param direction: PDU direction
        :type direction: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param conn_handle: Connection handle
        :type conn_handle: int, optional
        :param processed: Set to True if PDU has been processed by firmware
        :type processed: bool
        :param decrypted: Set to True if PDU has been decrypted by firmware
        :type decrypted: bool
        :return: instance of PduReceived
        :rtype: PduReceived
        """
        return BleDomain.bound("pdu", self.proto_version)(
            direction=direction,
            pdu=pdu,
            conn_handle=conn_handle,
            processed=processed,
            decrypted=decrypted
        )

    def create_raw_pdu_received(self, direction: int, pdu: bytes, \
                             access_address: int = None, conn_handle: int = None, \
                             rssi: int = None, timestamp: int = None, \
                             rel_timestamp: int = None, crc: int = None, \
                             crc_validity: bool = None, processed: bool = False, \
                             decrypted: bool = False, channel: int = None) -> HubMessage:
        """Create a RawPduReceived message

        :param direction: PDU direction
        :type direction: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param crc: PDU CRC value
        :type crc: int, optional
        :param conn_handle: Connection handle
        :type conn_handle: int, optional
        :param access_address: Connection access address
        :type access_address: int, optional
        :param rssi: Received Signal Strength Indicator
        :type rssi: int, optional
        :param timestamp: Reception timestamp
        :type timestamp: int, optional
        :param rel_timestamp: Reception timestamp relative to last anchor
        :type rel_timestamp: int, optional
        :param crc_validity: CRC validity status
        :param processed: Set to True if PDU has been processed by firmware
        :type processed: bool
        :param decrypted: Set to True if PDU has been decrypted by firmware
        :type decrypted: bool
        :return: instance of RawPduReceived
        :rtype: RawPduReceived
        """
        # Build message with mandatory fields
        message = BleDomain.bound("raw_pdu", self.proto_version)(
            direction=direction,
            pdu=pdu,
            processed=processed,
            decrypted=decrypted
        )

        # Add optional fields if any
        if rssi is not None:
            message.rssi = rssi
        if access_address is not None:
            message.access_address = access_address
        if conn_handle is not None:
            message.conn_handle = conn_handle
        if timestamp is not None:
            message.timestamp = timestamp
        if rel_timestamp is not None:
            message.relative_timestamp = rel_timestamp
        if crc_validity is not None:
            message.crc_validity = crc_validity
        if crc is not None:
            message.crc = crc
        if channel is not None:
            message.channel = channel

        # Return message
        return message

    def create_injected(self, access_address: int, success: bool, attempts: int) -> HubMessage:
        """Create an Injected message

        :param access_address: Target connection access address
        :type access_address: int
        :param success: Set to True if injection succeeded, False otherwise
        :type success: bool
        :param attempts: Number of attempts
        :type attempts: int
        :return: instance of Injected message
        :rtype: Injected
        """
        return BleDomain.bound("injected", self.proto_version)(
            access_address=access_address,
            success=success,
            injection_attempts=attempts
        )

    def create_hijack_master(self, access_address: int) -> HubMessage:
        """Create a HijackMaster message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackMaster
        :rtype: HijackMaster
        """
        return BleDomain.bound("hijack_master", self.proto_version)(
            access_address=access_address
        )

    def create_hijack_slave(self, access_address: int) -> HubMessage:
        """Create a HijackSlave message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackSlave
        :rtype: HijackSlave
        """
        return BleDomain.bound("hijack_slave", self.proto_version)(
            access_address=access_address
        )

    def create_hijack_both(self, access_address: int) -> HubMessage:
        """Create a HijackBoth message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackBoth
        :rtype: HijackBoth
        """
        return BleDomain.bound("hijack_both", self.proto_version)(
            access_address=access_address
        )

    def create_hijacked(self, access_address: int, success: bool) -> HubMessage:
        """Create an Hijacked message

        :param access_address: Target connection access address
        :type access_address: int
        :param success: Set to True if injection succeeded, False otherwise
        :type success: bool
        :return: instance of Hijacked message
        :rtype: Hijacked
        """
        return BleDomain.bound("hijacked", self.proto_version)(
            access_address=access_address,
            success=success
        )

    def create_prepare_sequence_manual(self, seq_id: int, direction: int, packets: List[bytes]) -> HubMessage:
        """Create a PrepareSequenceManual message

        :param seq_id: Sequence identifier (must be unique)
        :type seq_id: int
        :param direction: Direction of the PDU
        :type direction: Direction
        :param packets: List of PDUs to send
        :type packets: list
        :return: instance of PrepareSequenceManual
        :rtype: PrepareSequenceManual
        """
        # Create our PrepareSequenceManual message
        message = BleDomain.bound("prepare_manual", self.proto_version)(
            sequence_id=seq_id,
            direction=direction
        )

        # Add packets
        for packet in packets:
            message.add_packet(packet)

        # Return message
        return message

    def create_prepare_sequence_conn_evt(self, seq_id: int, direction: int, conn_evt: int, \
                                     packets: List[bytes]) -> HubMessage:
        """Create a PrepareSequenceConnEvt message

        :param seq_id: Sequence identifier (must be unique)
        :type seq_id: int
        :param direction: Direction of the PDU
        :type direction: Direction
        :param conn_evt: target connection event
        :type conn_evt: int
        :param packets: List of PDUs to send
        :type packets: list
        :return: instance of PrepareSequenceConnEvt
        :rtype: PrepareSequenceConnEvt
        """
        message = BleDomain.bound("prepare_connevt", self.proto_version)(
            sequence_id=seq_id,
            direction=direction,
            conn_evt=conn_evt
        )

        # Add packets
        for packet in packets:
            message.add_packet(packet)

        # Return message
        return message

    def create_prepare_sequence_pattern(self, seq_id: int, direction: int, pattern: bytes, \
                                     mask: bytes, offset: int, packets: List[bytes]) -> HubMessage:
        """Create a PrepareSequencePattern message

        :param seq_id: Sequence identifier (must be unique)
        :type seq_id: int
        :param direction: Direction of the PDU
        :type direction: Direction
        :param pattern: target pattern
        :type pattern: bytes
        :param mask: target pattern bitmask
        :type mask: bytes
        :param offset: target pattern offset
        :type offset: int
        :param packets: List of PDUs to send
        :type packets: list
        :return: instance of PrepareSequencePattern
        :rtype: PrepareSequencePattern
        """
        message = BleDomain.bound("prepare_pattern", self.proto_version)(
            sequence_id=seq_id,
            direction=direction,
            pattern=pattern,
            mask=mask,
            offset=offset
        )

        # Add packets
        for packet in packets:
            message.add_packet(packet)

        # Return message
        return message

    def create_triggered(self, seq_id: int) -> HubMessage:
        """Create a Triggered message

        :param seq_id: Sequence identifier triggered
        :type seq_id: int
        :return: instance of Triggered
        :rtype: Triggered
        """
        return BleDomain.bound("triggered", self.proto_version)(
            seq_id=seq_id
        )

    def create_trigger(self, seq_id: int) -> HubMessage:
        """Create a Trigger message

        :param seq_id: Sequence identifier to trigger
        :type seq_id: int
        :return: instance of Trigger
        :rtype: Trigger
        """
        return BleDomain.bound("trigger", self.proto_version)(
            sequence_id=seq_id
        )

    def create_delete_sequence(self, seq_id: int) -> HubMessage:
        """Create a DeleteSequence message

        :param seq_id: Sequence identifier to delete
        :type seq_id: int
        :return: instance of DeleteSequence
        :rtype: DeleteSequence
        """
        return BleDomain.bound("delete_seq", self.proto_version)(
            sequence_id=seq_id
        )

    def create_set_encryption(self, conn_handle: int, ll_key: bytes, ll_iv: bytes, \
                            key: bytes, rand: bytes, ediv: bytes, enabled: bool) -> HubMessage:
        """Create a SetEncryption message

        :param conn_handle: Connection handle
        :type conn_handle: int
        :param ll_key: Link-layer encryption key
        :type ll_key: bytes
        :param ll_iv: Link-layer encryption IV
        :type ll_iv: bytes
        :param key: Encryption key
        :type key: bytes
        :param rand: Encryption random value
        :type rand: bytes
        :param ediv: Encryption diversifier
        :type ediv: bytes
        :param enabled: Enable encryption if set to True, disable it otherwise
        :type enabled: bool
        :return: instance of `SetEncryption`
        """
        return BleDomain.bound("encryption", self.proto_version)(
            conn_handle=conn_handle,
            enabled=enabled,
            ll_key=ll_key,
            ll_iv=ll_iv,
            key=key,
            rand=rand,
            ediv=ediv
        )

from .address import SetBdAddress
from .sniffing import SniffAdv, SniffConnReq, SniffAccessAddress, SniffActiveConn, \
    AccessAddressDiscovered
from .jamming import JamAdv, JamAdvChan, JamConn, ReactiveJam
from .mode import ScanMode, AdvMode, CentralMode, PeriphMode, BleStart, BleStop, \
    SetEncryption
from .pdu import SetAdvData, SendBleRawPdu, SendBlePdu, BleAdvPduReceived, BlePduReceived, \
    BleRawPduReceived, Injected
from .connect import ConnectTo, Disconnect, Connected, Disconnected, Synchronized, \
    Desynchronized
from .hijack import HijackMaster, HijackSlave, HijackBoth, Hijacked
from .triggers import PrepareSequenceManual, PrepareSequenceConnEvt, \
    PrepareSequencePattern, PrepareSequence, Triggered, Trigger, DeleteSequence

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
    "SendBleRawPdu",
    "SendBlePdu",
    "BleAdvPduReceived",
    "BlePduReceived",
    "BleRawPduReceived",
    "ConnectTo",
    "Disconnect",
    "Connected",
    "Disconnected",
    "SetEncryption",
    "BleStart",
    "BleStop",
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
    "PrepareSequence",
    "Triggered",
    "Trigger",
    "DeleteSequence"
]
