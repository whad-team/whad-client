from whad.hub.discovery import Domain, Capability
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
            Domain.BtLE : (
                (Capability.Sniff),
                [BleCommands.SniffConnReq, BleCommands.SniffAdv, BleCommands.Start, BleCommands.Stop]
            )
        },
        {
            Domain.BtLE : (
                (Capability.Inject),
                [BleCommands.SendPDU, BleCommands.Start, BleCommands.Stop]
            )
        }
    ),
    DLT_IEEE802_15_4_TAP : (
        {
            Domain.Dot15d4 : (
                (Capability.Sniff),
                [Dot15d4Commands.Sniff, Dot15d4Commands.Start, Dot15d4Commands.Stop]
            )
        },
        {
            Domain.Dot15d4 : (
                (Capability.Inject),
                [Dot15d4Commands.Send,Dot15d4Commands.Start, Dot15d4Commands.Stop]
            )
        }
    ),
    DLT_RESERVED_02 : (
        {
            Domain.Esb : (
                (Capability.Sniff),
                [EsbCommands.Sniff, EsbCommands.Start, EsbCommands.Stop]
            ),
            Domain.LogitechUnifying : (
                (Capability.Sniff),
                [UnifyingCommands.Sniff, UnifyingCommands.Start, UnifyingCommands.Stop]
            )
        },
        {
            Domain.Esb : (
                (Capability.Inject),
                [EsbCommands.Send,EsbCommands.Start, EsbCommands.Stop]
            ),
            Domain.LogitechUnifying : (
                (Capability.Inject),
                [UnifyingCommands.Send,UnifyingCommands.Start, UnifyingCommands.Stop]
            )
        }
    ),
    DLT_RESERVED_06 : (
        {
            Domain.Phy : (
                (Capability.Sniff | Capability.NoRawData),
                [PhyCommands.Sniff, PhyCommands.Start, PhyCommands.Stop, PhyCommands.SetFrequency, PhyCommands.GetSupportedFrequencies, PhyCommands.SetPacketSize, PhyCommands.SetDataRate, PhyCommands.SetEndianness, PhyCommands.SetSyncWord, PhyCommands.SetASKModulation, PhyCommands.SetFSKModulation, PhyCommands.SetGFSKModulation, PhyCommands.SetBPSKModulation, PhyCommands.SetQPSKModulation, PhyCommands.SetLoRaModulation]
            )
        },
        {
            Domain.Phy : (
                (Capability.Inject | Capability.NoRawData),
                [PhyCommands.Send,PhyCommands.Start, PhyCommands.Stop, PhyCommands.SetFrequency, PhyCommands.GetSupportedFrequencies, PhyCommands.SetPacketSize, PhyCommands.SetDataRate, PhyCommands.SetEndianness, PhyCommands.SetSyncWord, PhyCommands.SetASKModulation, PhyCommands.SetFSKModulation, PhyCommands.SetGFSKModulation, PhyCommands.SetBPSKModulation, PhyCommands.SetQPSKModulation, PhyCommands.SetLoRaModulation]
            )
        }
    )
}
