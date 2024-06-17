from whad import WhadDomain, WhadCapability
from whad.hub.ble import Commands as BleCommands
from whad.hub.dot15d4 import Commands as Dot15d4Commands
from whad.hub.esb import Commands as EsbCommands


DLT_BLUETOOTH_LE_LL_WITH_PHDR   = 256
DLT_IEEE802_15_4_TAP            = 283
DLT_RESERVED_02                 = 148

CAPABILITIES = {
    DLT_BLUETOOTH_LE_LL_WITH_PHDR : (
        {
            WhadDomain.BtLE : (
                (WhadCapability.Sniff),
                [BleCommands.Sniff, BleCommands.Start, BleCommands.Stop]
            )
        },
        {
            WhadDomain.BtLE : (
                (WhadCapability.Inject),
                [BleCommands.SendPDU, BleCommands.Start, BleCommands.Stop]
            )
        }
    ),
    DLT_IEEE802_15_4_TAP : (
        {
            WhadDomain.Dot15d4 : (
                (WhadCapability.Sniff),
                [Dot15d4Commands.Sniff, Dot15d4Commands.Start, Dot15d4Commands.Stop]
            )
        },
        {
            WhadDomain.Dot15d4 : (
                (WhadCapability.Inject),
                [Dot15d4Commands.Send,Dot15d4Commands.Start, Dot15d4Commands.Stop]
            )
        }
    ),
    DLT_RESERVED_02 : (

    )
}
