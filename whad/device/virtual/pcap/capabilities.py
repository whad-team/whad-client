from whad import WhadDomain, WhadCapability
from whad.hub.ble import Commands as BleCommands
from whad.hub.dot15d4 import Commands as Dot15d4Commands
from whad.hub.esb import Commands as EsbCommands
from whad.hub.unifying import Commands as UnifyingCommands
from whad.hub.phy import Commands as PhyCommands

DLT_BLUETOOTH_LE_LL_WITH_PHDR   = 256
DLT_IEEE802_15_4_TAP            = 283
DLT_RESERVED_02                 = 148
DLT_RESERVED_03                 = 149
DLT_RESERVED_06                 = 152

CAPABILITIES = {
    DLT_BLUETOOTH_LE_LL_WITH_PHDR : (
        {
            WhadDomain.BtLE : (
                (WhadCapability.Sniff),
                [BleCommands.SniffConnReq, BleCommands.SniffAdv, BleCommands.Start, BleCommands.Stop]
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
        {
            WhadDomain.Esb : (
                (WhadCapability.Sniff),
                [EsbCommands.Sniff, EsbCommands.Start, EsbCommands.Stop]
            ),
            WhadDomain.LogitechUnifying : (
                (WhadCapability.Sniff),
                [UnifyingCommands.Sniff, UnifyingCommands.Start, UnifyingCommands.Stop]
            )
        },
        {
            WhadDomain.Esb : (
                (WhadCapability.Inject),
                [EsbCommands.Send,EsbCommands.Start, EsbCommands.Stop]
            ),
            WhadDomain.LogitechUnifying : (
                (WhadCapability.Inject),
                [UnifyingCommands.Send,UnifyingCommands.Start, UnifyingCommands.Stop]
            )
        }
    ),
    DLT_RESERVED_06 : (
        {
            WhadDomain.Phy : (
                (WhadCapability.Sniff | WhadCapability.NoRawData),
                [PhyCommands.Sniff, PhyCommands.Start, PhyCommands.Stop, PhyCommands.SetFrequency, PhyCommands.GetSupportedFrequencies, PhyCommands.SetPacketSize, PhyCommands.SetDataRate, PhyCommands.SetEndianness, PhyCommands.SetSyncWord, PhyCommands.SetASKModulation, PhyCommands.SetFSKModulation, PhyCommands.SetGFSKModulation, PhyCommands.SetBPSKModulation, PhyCommands.SetQPSKModulation, PhyCommands.SetLoRaModulation]
            )
        },
        {
            WhadDomain.Phy : (
                (WhadCapability.Inject | WhadCapability.NoRawData),
                [PhyCommands.Send,PhyCommands.Start, PhyCommands.Stop, PhyCommands.SetFrequency, PhyCommands.GetSupportedFrequencies, PhyCommands.SetPacketSize, PhyCommands.SetDataRate, PhyCommands.SetEndianness, PhyCommands.SetSyncWord, PhyCommands.SetASKModulation, PhyCommands.SetFSKModulation, PhyCommands.SetGFSKModulation, PhyCommands.SetBPSKModulation, PhyCommands.SetQPSKModulation, PhyCommands.SetLoRaModulation]
            )
        }
    )
}
