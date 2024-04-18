"""WHAD Protocol Bluetooth Low Energy domain message abstraction layer.
"""
from whad.protocol.ble.ble_pb2 import BleDirection, BleAdvType, BleAddrType
from whad.protocol.hub.message import HubMessage
from whad.protocol.hub import pb_bind, Registry, ProtocolHub

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
        self.proto_version = version

    @staticmethod
    def parse(proto_version: int, message) -> HubMessage:
        """Parses a WHAD BleDomain message as seen by protobuf
        """
        message_type = message.ble.WhichOneof('msg')
        message_clazz = BleDomain.bound(message_type, proto_version)
        return message_clazz.parse(proto_version, message)


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