from whad import WhadCapability
from whad.protocol.ble.ble_pb2 import Start, Stop, AdvMode, SetAdvData, \
    ScanMode, CentralMode, ConnectTo, SendPDU, PeripheralMode, Disconnect
from whad.ble.stack.constants import BT_MANUFACTURERS
from enum import IntEnum

class HCIInternalState(IntEnum):
    NONE = 0
    SCANNING = 1
    CENTRAL = 2
    PERIPHERAL = 3

LE_STATES = {
    0 : ("Non-connectable Advertising State", 0 , [Start, Stop, AdvMode, SetAdvData]),
    1 : ("Scannable Advertising State", 0, [Start, Stop, AdvMode, SetAdvData]),
    2 : ("Connectable Advertising State", WhadCapability.SlaveRole, [Start, Stop, AdvMode, SetAdvData]),
    3 : ("High Duty Cycle Directed Advertising State", 0,  [Start, Stop, AdvMode, SetAdvData]),
    4 : ("Passive Scanning State", WhadCapability.Scan, [Start, Stop, ScanMode]),
    5 : ("Active Scanning State", WhadCapability.Scan,[Start, Stop, ScanMode]),
    6 : ("Initiating State and Connection State (Central Role)", WhadCapability.MasterRole, [Start, Stop, CentralMode, ConnectTo,Disconnect, SendPDU]),
    7 : ("Connection State (Peripheral Role)", WhadCapability.SlaveRole,  [Start, Stop, PeripheralMode, SendPDU, Disconnect])
}

ADDRESS_MODIFICATION_VENDORS = [
    BT_MANUFACTURERS[0].encode("utf-8"),
    BT_MANUFACTURERS[10].encode("utf-8"),
    BT_MANUFACTURERS[13].encode("utf-8"),
    BT_MANUFACTURERS[15].encode("utf-8"),
    BT_MANUFACTURERS[18].encode("utf-8"),
    BT_MANUFACTURERS[48].encode("utf-8"),
    BT_MANUFACTURERS[57].encode("utf-8")
]
