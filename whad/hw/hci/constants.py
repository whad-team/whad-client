"""
Host/Controller interface constants.
"""
from enum import IntEnum

from whad.hub.discovery import Capability
from whad.hub.ble import Commands
from whad.ble.stack.constants import BT_MANUFACTURERS

class HCIInternalState(IntEnum):
    """Host/controller interface state enumeration.
    """
    NONE = 0
    SCANNING = 1
    CENTRAL = 2
    PERIPHERAL = 3

class HCIConnectionState(IntEnum):
    """Host/controller interface connection state
    """
    DISCONNECTED = 0
    INITIATING = 1
    ESTABLISHED = 2

LE_STATES = {
    0 : ("Non-connectable Advertising State", 0 ,
         [Commands.Start, Commands.Stop, Commands.AdvMode, Commands.SetAdvData]
        ),
    1 : ("Scannable Advertising State", 0,
         [Commands.Start, Commands.Stop, Commands.AdvMode, Commands.SetAdvData]
        ),
    2 : ("Connectable Advertising State", Capability.SimulateRole,
         [Commands.Start, Commands.Stop, Commands.AdvMode, Commands.SetAdvData]
        ),
    3 : ("High Duty Cycle Directed Advertising State", 0,
         [Commands.Start, Commands.Stop, Commands.AdvMode, Commands.SetAdvData]
        ),
    4 : ("Passive Scanning State", Capability.Scan,
         [Commands.Start, Commands.Stop, Commands.ScanMode]
        ),
    5 : ("Active Scanning State", Capability.Scan,
         [Commands.Start, Commands.Stop, Commands.ScanMode]
        ),
    6 : ("Initiating State and Connection State (Central Role)", Capability.SimulateRole,
         [
             Commands.Start, Commands.Stop, Commands.CentralMode, Commands.ConnectTo,
             Commands.Disconnect, Commands.SendPDU, Commands.SetEncryption
         ]
        ),
    7 : ("Connection State (Peripheral Role)", Capability.SimulateRole,
         [
            Commands.Start, Commands.Stop, Commands.PeripheralMode, Commands.SendPDU,
            Commands.Disconnect, Commands.SetEncryption
         ]
        )
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
