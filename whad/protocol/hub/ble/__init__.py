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
    
    def createScanMode(self, active: bool = False) -> HubMessage:
        """Create a ScanMode message.

        :param active: Enable active scan mode
        :type active: bool
        :return: instance of ScanMode
        :return-type: ScanMode
        """
        return BleDomain.bound('scan_mode', self.proto_version)(
            active=active
        )
    
    def createAdvMode(self, adv_data: bytes, scan_rsp: bytes = None) -> HubMessage:
        """Create an AdvMode message.

        :param adv_data: Advertisement data (31 bytes max)
        :type adv_data: bytes
        :param scan_rsp: Scan response data (31 bytes max)
        :type scan_rsp: bytes, optional
        :return: instance of AdvMode message
        :return-type: AdvMode
        """
        message = BleDomain.bound('adv_mode', self.proto_version)(
            scan_data=adv_data
        )
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp
        return message
    
    def createCentralMode(self) -> HubMessage:
        """Create a CentralMode message.

        :return: instance of CentralMode message
        :return-type: CentralMode
        """
        return BleDomain.bound('central_mode', self.proto_version)()

    def createPeriphMode(self, adv_data: bytes, scan_rsp: bytes = None) -> HubMessage:
        """Create an PeriphMode message.

        :param adv_data: Advertisement data (31 bytes max)
        :type adv_data: bytes
        :param scan_rsp: Scan response data (31 bytes max)
        :type scan_rsp: bytes, optional
        :return: instance of PeriphMode message
        :return-type: PeriphMode
        """
        message = BleDomain.bound('periph_mode', self.proto_version)(
            scan_data=adv_data
        )
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp
        return message

    def createStart(self) -> HubMessage:
        """Create a Start message.

        :return: instance of Start message
        :return-type: Start
        """
        return BleDomain.bound("start", self.proto_version)()

    def createStop(self) -> HubMessage:
        """Create a Stop message.

        :return: instance of Stop message
        :return-type: Stop
        """
        return BleDomain.bound("stop", self.proto_version)()

    def createConnectTo(self, bd_address: BDAddress = None, access_address: int = None,
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
        :return-type: ConnectTo
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
    

    def createDisconnect(self, conn_handle: int) -> HubMessage:
        """Create a Disconnect message.

        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: instance of Disconnect message
        :return-type: Disconnect
        """
        return BleDomain.bound("disconnect", self.proto_version)(
            conn_handle=conn_handle
        )
    
    def createSynchronized(self, access_address: int, interval: int, increment: int,\
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
        :return-type: Synchronized
        """
        return BleDomain.bound("synchronized", self.proto_version)(
            access_address=access_address,
            crc_init=crc_init,
            hop_interval=interval,
            hop_increment=increment,
            channel_map=channel_map.value
        )

    def createConnected(self, initiator: BDAddress, advertiser: BDAddress, \
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
        :return-type: Connected
        """
        return BleDomain.bound("connected", self.proto_version)(
            initiator=initiator.value,
            advertiser=advertiser.value,
            access_address=access_address,
            conn_handle=conn_handle,
            adv_addr_type=AddressType.PUBLIC if advertiser.is_public() else AddressType.RANDOM,
            init_addr_type=AddressType.PUBLIC if initiator.is_public() else AddressType.RANDOM
        )
    
    def createDisconnected(self, reason: int, conn_handle: int) -> HubMessage:
        """Create a Disconnected message.

        :param reason: Disconnection reason
        :type reason: int
        :param conn_handle: Connection handle
        :type conn_handle: int
        :return: instance of Disconnected
        :return-type: Disconnected
        """
        return BleDomain.bound("disconnected", self.proto_version)(
            reason=reason,
            conn_handle=conn_handle
        )
    
    def createDesynchronized(self, accesss_address: int) -> HubMessage:
        """Create a Desynchronized message.

        :param access_address: Connection access address
        :type access_address: int
        :return: instance of Desynchronized
        :return-type: Desynchronized
        """
        return BleDomain.bound("desynchronized", self.proto_version)(
            accesss_address=accesss_address
        )

    def createSetAdvData(self, adv_data: bytes, scan_rsp: bytes = None) -> HubMessage:
        """Create a SetAdvData message.

        :param adv_data: Advertising data
        :type adv_data: bytes
        :param scan_rsp: Scan response data
        :type scan_rsp: bytes, optional
        :return: instance of SetAdvData message
        :return-type: SetAdvData
        """
        message = BleDomain.bound("set_adv_data", self.proto_version)(
            scan_data=adv_data
        )

        # Set scan response data if provided
        if scan_rsp is not None:
            message.scanrsp_data = scan_rsp

        return message
    
    def createSendRawPdu(self, direction: int, pdu: bytes, \
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
        :return-type: SendRawPdu
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
    
    def createSendPdu(self, direction: int, pdu: bytes, conn_handle: int, \
                      encrypt: bool = False) -> HubMessage:
        """Create a SendPdu message.

        :param direction: PDU direction
        :type direction: int
        :param pdu: PDU to send
        :type pdu: bytes
        :param conn_handle: Connection handle
        :type conn_handle: int, optional
        :param encrypt: Encrypt PDU before sending
        :type encrypt: bool, optional
        :return: instance of SendRawPdu message
        :return-type: SendRawPdu        
        """
        return BleDomain.bound("send_pdu", self.proto_version)(
            direction=direction,
            conn_handle=conn_handle,
            pdu=pdu,
            encrypt=encrypt
        )
    
    def createAdvPduReceived(self, adv_type: AdvType, rssi: int, bd_address: BDAddress, \
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
        :return-type: AdvPduReceived
        """
        return BleDomain.bound("adv_pdu", self.proto_version)(
            adv_type=adv_type,
            rssi=rssi,
            bd_address=bd_address.value,
            adv_data=adv_data,
            addr_type=AddressType.PUBLIC if bd_address.is_public() else AddressType.RANDOM
        )
    
    def createPduReceived(self, direction: int, pdu: bytes, conn_handle: int, \
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
        :return-type: PduReceived
        """
        return BleDomain.bound("pdu", self.proto_version)(
            direction=direction,
            pdu=pdu,
            conn_handle=conn_handle,
            processed=processed,
            decrypted=decrypted
        )
    
    def createRawPduReceived(self, direction: int, pdu: bytes, \
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
        :return-type: RawPduReceived
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
        if channel is not None:
            message.channel = channel

        # Return message
        return message
    
    def createInjected(self, access_address: int, success: bool, attempts: int) -> HubMessage:
        """Create an Injected message

        :param access_address: Target connection access address
        :type access_address: int
        :param success: Set to True if injection succeeded, False otherwise
        :type success: bool
        :param attempts: Number of attempts
        :type attempts: int
        :return: instance of Injected message
        :return-type: Injected
        """
        return BleDomain.bound("injected", self.proto_version)(
            access_address=access_address,
            success=success,
            attempts=attempts
        )

    def createHijackMaster(self, access_address: int) -> HubMessage:
        """Create a HijackMaster message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackMaster
        :return-type: HijackMaster
        """
        return BleDomain.bound("hijack_master", self.proto_version)(
            access_address=access_address
        )

    def createHijackSlave(self, access_address: int) -> HubMessage:
        """Create a HijackSlave message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackSlave
        :return-type: HijackSlave
        """
        return BleDomain.bound("hijack_slave", self.proto_version)(
            access_address=access_address
        )
    
    def createHijackBoth(self, access_address: int) -> HubMessage:
        """Create a HijackBoth message

        :param access_address: Target access address
        :type access_address: int
        :return: instance of HijackBoth
        :return-type: HijackBoth
        """
        return BleDomain.bound("hijack_both", self.proto_version)(
            access_address=access_address
        )
    
    def createHijacked(self, access_address: int, success: bool) -> HubMessage:
        """Create an Hijacked message

        :param access_address: Target connection access address
        :type access_address: int
        :param success: Set to True if injection succeeded, False otherwise
        :type success: bool
        :return: instance of Hijacked message
        :return-type: Hijacked
        """
        return BleDomain.bound("hijacked", self.proto_version)(
            access_address=access_address,
            success=success
        )
    
    def createPrepareSequenceManual(self, seq_id: int, direction: int, packets: List[bytes]) -> HubMessage:
        """Create a PrepareSequenceManual message

        :param seq_id: Sequence identifier (must be unique)
        :type seq_id: int
        :param direction: Direction of the PDU
        :type direction: Direction
        :param packets: List of PDUs to send
        :type packets: list
        :return: instance of PrepareSequenceManual
        :return-type: PrepareSequenceManual
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

    def createPrepareSequenceConnEvt(self, seq_id: int, direction: int, conn_evt: int, \
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
        :return-type: PrepareSequenceConnEvt    
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
    
    def createPrepareSequencePattern(self, seq_id: int, direction: int, pattern: bytes, \
                                     mask: bytes, offset: int, packets: List[bytes]) -> HubMessage:
        """Create a PrepareSequencePattern message

        :param seq_id: Sequence identifier (must be unique)
        :type seq_id: int
        :param direction: Direction of the PDU
        :type direction: Direction
        :param pattern: target pattern
        :type pattern: bytes
        :param mask: target pattern bitmask
        :type pattern: bytes
        :param offset: target pattern offset
        :type offset: int
        :param packets: List of PDUs to send
        :type packets: list
        :return: instance of PrepareSequencePattern
        :return-type: PrepareSequencePattern          
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

    def createTriggered(self, seq_id: int):
        """Create a Triggered message

        :param seq_id: Sequence identifier triggered
        :type seq_id: int
        :return: instance of Triggered
        :return-type: Triggered
        """
        return BleDomain.bound("triggered", self.proto_version)(
            seq_id=seq_id
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
    PrepareSequencePattern, PrepareSequence, Triggered

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
    "PrepareSequence",
    "Triggered"
]