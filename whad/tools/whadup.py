"""
Whad up ?
"""
import sys
from html import escape
from typing import List

# Helpers
from prompt_toolkit import print_formatted_text, HTML


# Whad device
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.device import Device

# Whad hub
from whad.hub.ble import Commands as BleCommands
from whad.hub.dot15d4 import Commands as Dot15d4Commands
from whad.hub.esb import Commands as ESBCommands
from whad.hub.unifying import Commands as UnifyingCommands
from whad.hub.phy import Commands as PhyCommands
from whad.hub.discovery import Domain, Capability


DOMAINS = {
    Domain.Phy: "Physical Layer",
    Domain.ANT: "ANT",
    Domain.ANT_FS: "ANT FS",
    Domain.ANT_Plus: "ANT+",
    Domain.BtClassic: "Bluetooth Classic",
    Domain.BtLE: "Bluetooth LE",
    Domain.Esb: "Enhanced ShockBurst",
    Domain.LogitechUnifying: "Logitech Unifying",
    Domain.Mosart: "Mosart",
    Domain.SixLowPan: "6LowPan",
    Domain.Dot15d4: "802.15.4"
}

CAPABILITIES = {
    Capability.Scan: "can scan devices",
    Capability.Hijack: "can hijack communication",
    Capability.Hook: "can hook packets",
    Capability.Inject: "can inject packets",
    Capability.Jam: "can jam communications",
    Capability.SimulateRole: "can simulate a role in a communication",
    Capability.Sniff: "can sniff data",
    Capability.NoRawData: "can not read/write raw packet"
}

BLE_COMMANDS = {
    BleCommands.SetBdAddress: "SetBdAddress: can set BD address",
    BleCommands.SniffAdv: "SniffAdv: can sniff advertising PDUs",
    BleCommands.JamAdv: "JamAdv: can jam advertising PDUs",
    BleCommands.JamAdvOnChannel: "JamAdvOnChannel: can jam advertising PDUs on a single channel",
    BleCommands.ReactiveJam: "ReactiveJam: can reactively jam PDU on a single channel",
    BleCommands.SniffConnReq: "SniffConnReq: can sniff a new connection",
    BleCommands.SniffAccessAddress: "SniffAccessAddress: can detect active connections",
    BleCommands.SniffActiveConn: "SniffActiveConn: can sniff an active connection",
    BleCommands.JamConn: "JamConn: can jam an active connection",
    BleCommands.ScanMode: "ScanMode: can scan devices",
    BleCommands.AdvMode: "AdvMode: can advertise as a BLE device",
    BleCommands.SetAdvData: "SetAdvData: can set advertising PDU details",
    BleCommands.CentralMode: "CentralMode: can act as a Central device",
    BleCommands.ConnectTo: "ConnectTo: can initiate a BLE connection",
    BleCommands.SendRawPDU: "SendRawPDU: can send a raw PDU",
    BleCommands.SendPDU: "SendPDU: can send a PDU",
    BleCommands.Disconnect: "Disconnect: can terminate an active connection (in Central mode)",
    BleCommands.PeripheralMode: "PeripheralMode: can act as a peripheral",
    BleCommands.Start: "Start: can start depending on the current mode",
    BleCommands.Stop: "Stop: can stop depending on the current mode",
    BleCommands.SetEncryption: "SetEncryption: can enable encryption during a connection",
    BleCommands.HijackMaster: "HijackMaster: can hijack the Master role in an active connection",
    BleCommands.HijackSlave: "HijackSlave: can hijack the Slave role in an active connection",
    BleCommands.HijackBoth: (
        "HijackBoth: can hijack the Master and the Slave role in an active connection"
    ),
    BleCommands.PrepareSequence: (
        "PrepareSequence: can prepare a sequence of packets and associate a trigger"
    ),
    BleCommands.TriggerSequence: (
        "TriggerSequence: can manually trigger the transmission of a sequence of packets"
    ),
    BleCommands.DeleteSequence: "DeleteSequence: can delete a prepared sequence of packets"

}

DOT15D4_COMMANDS = {
    Dot15d4Commands.SetNodeAddress: "SetNodeAddress: can set Node address",
    Dot15d4Commands.Sniff: "Sniff: can sniff 802.15.4 packets",
    Dot15d4Commands.EnergyDetection: "EnergyDetection: can perform energy detection scans",
    Dot15d4Commands.Jam: "Jam: can jam 802.15.4 packets",
    Dot15d4Commands.Send: "Send: can transmit 802.15.4 packets",
    Dot15d4Commands.EndDeviceMode: "EndDeviceMode: can act as an End Device",
    Dot15d4Commands.CoordinatorMode: "CoordinatorMode: can act as a Coordinator",
    Dot15d4Commands.RouterMode: "RouterMode: can act as a Router",
    Dot15d4Commands.Start: "Start: can start depending on the current mode",
    Dot15d4Commands.Stop: "Stop: can stop depending on the current mode",
    Dot15d4Commands.ManInTheMiddle: "ManInTheMiddle: can perform a Man-in-the-Middle attack",
}

ESB_COMMANDS = {
    ESBCommands.SetNodeAddress: "SetNodeAddress: can set Node address",
    ESBCommands.Sniff: "Sniff: can sniff Enhanced ShockBurst packets",
    ESBCommands.Jam: "Jam: can jam Enhanced ShockBurst packets",
    ESBCommands.Send: "Send: can transmit Enhanced ShockBurst packets",
    ESBCommands.PrimaryReceiverMode: "PrimaryReceiverMode: can act as a Primary Receiver (PRX)",
    ESBCommands.PrimaryTransmitterMode: "PrimaryReceiverMode: can act as a Primary Receiver (PTX)",
    ESBCommands.Start: "Start: can start depending on the current mode",
    ESBCommands.Stop: "Stop: can stop depending on the current mode"
}

UNIFYING_COMMANDS = {
    UnifyingCommands.SetNodeAddress: "SetNodeAddress: can set Node address",
    UnifyingCommands.Sniff: "Sniff: can sniff Logitech Unifying packets",
    UnifyingCommands.Jam: "Jam: can jam Logitech Unifying packets",
    UnifyingCommands.Send: "Send: can transmit Logitech Unifying packets",
    UnifyingCommands.LogitechDongleMode: (
        "PrimaryReceiverMode: can act as a Logitech Dongle (ESB PRX)"
    ),
    UnifyingCommands.LogitechKeyboardMode: (
        "PrimaryReceiverMode: can act as a Logitech Keyboard (ESB PTX)"
    ),
    UnifyingCommands.LogitechMouseMode: (
        "LogitechMouseMode: can act as a Logitech Mouse (ESB PTX)"
    ),
    UnifyingCommands.Start: "Start: can start depending on the current mode",
    UnifyingCommands.Stop: "Stop: can stop depending on the current mode",
    UnifyingCommands.SniffPairing: "SniffPairing: can sniff a pairing process"
}

PHY_COMMANDS = {
    PhyCommands.SetASKModulation: (
        "SetASKModulation: can use Amplitude Shift Keying modulation scheme"
    ),
    PhyCommands.SetFSKModulation: (
        "SetFSKModulation: can use Frequency Shift Keying modulation scheme"
    ),
    PhyCommands.SetGFSKModulation: (
        "SetGFSKModulation: can use Gaussian Frequency Shift Keying modulation scheme"
    ),
    PhyCommands.SetBPSKModulation: (
        "SetBPSKModulation: can use Binary Phase Shift Keying modulation scheme"
    ),
    PhyCommands.SetQPSKModulation: (
        "SetQPSKModulation: can use Quadrature Phase Shift Keying modulation scheme"
    ),
    PhyCommands.SetLoRaModulation: (
        "SetLoRaModulation: can use LoRa modulation scheme"
    ),
    PhyCommands.GetSupportedFrequencies: (
        "GetSupportedFrequencies: can return a list of supported frequency ranges"
    ),
    PhyCommands.SetFrequency: "SetFrequency: can configure a given frequency",
    PhyCommands.SetDataRate: "SetDataRate: can configure the datarate",
    PhyCommands.SetEndianness: "SetEndianness: can configure the endianness",
    PhyCommands.SetTXPower: "SetTXPower: can configure the transmission power level",
    PhyCommands.SetPacketSize: "SetPacketSize: can configure the packet size",
    PhyCommands.SetSyncWord: "SetSyncWord: can configure the synchronization word",
    PhyCommands.Sniff: "Sniff: can receive arbitrary packets",
    PhyCommands.Send: "Send: can transmit arbitrary packets",
    PhyCommands.SendRaw: "SendRaw: can transmit arbitrary IQ streams" ,
    PhyCommands.ScheduleSend: "ScheduleSend: can schedule a packet to be sent at a specific time",
    PhyCommands.Jam: "Jam: can jam a physical medium",
    PhyCommands.Monitor: "Monitor: can monitor a physical medium",
    PhyCommands.Start: "Start: can start depending on the current mode",
    PhyCommands.Stop: "Stop: can stop depending on the current mode",
}

COMMANDS = {
    Domain.BtLE: BLE_COMMANDS,
    Domain.Esb: ESB_COMMANDS,
    Domain.Dot15d4: DOT15D4_COMMANDS,
    Domain.LogitechUnifying: UNIFYING_COMMANDS,
    Domain.Phy: PHY_COMMANDS

}


def get_readable_capabilities(caps: int) -> List[str]:
    """Turn device capabilities into a readable string.

    :param caps: Capabilities
    :type caps: int
    :rtype: list
    :return: A list of readable capabilities.
    """
    capabilities = []
    for i in range(24):
        if caps & (1 << i):
            capabilities.append(CAPABILITIES[caps & (1 << i)])
    return capabilities

def get_commands_desc(domain: str, commands: int) -> List[str]:
    """Turn a domain supported commands integer into a list of
    readable command names.

    :param domain: Domain name
    :type domain: str
    :param commands: Supported commands for the specified domain
    :type commands: int
    :rtype: list
    :return: A list of readable commands supported for the specified domain.
    """
    supp_commands = []
    if domain in COMMANDS:
        for i in COMMANDS[domain].keys():
            if commands & (1 << i):
                supp_commands.append(COMMANDS[domain][i])
    return supp_commands

def info(message: str):
    """Show an escaped informative message.

    :param message: Message to show.
    :type message: str
    """
    print_formatted_text(HTML("<ansicyan>[i]</ansicyan> " + escape(message)))

def error(message):
    """Show an escaped error message.

    :param message: Message to show.
    :type message: str
    """
    print_formatted_text(HTML("<ansired>[e]</ansired> " + escape(message)))

def main():
    """Main whadup/wup function.
    """
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery

        try:
            dev = Device.create(interface)

            info("Connecting to device ...")
            dev.open()
            dev.discover()

            info("Device details")
            print('')
            print_formatted_text(
                HTML("<b> Device ID:</b> " + ":".join(
                    [f"{i:02x}" for i in dev.device_id.encode()])
                )
            )
            print_formatted_text(HTML("<b> Firmware info:</b> "))
            if len(dev.info.fw_author) > 0:
                print_formatted_text(
                    HTML(f"<b> - Author :</b> {escape(dev.info.fw_author)}")
                )
            if len(dev.info.fw_url) > 0:
                print_formatted_text(
                    HTML(f"<b> - URL :</b> {escape(dev.info.fw_url)}")
                )
            print_formatted_text(
                HTML(f"<b> - Version :</b> {escape(dev.info.version_str)}")
            )
            print('')
            try:
                info("Discovering domains ...")
                domains = {}
                for domain in dev.get_domains():
                    if domain in DOMAINS:
                        caps_val = dev.get_domain_capability(domain)
                        domains[domain] = get_readable_capabilities(caps_val)
                info("Domains discovered.")
                print('')

                for domain, caps in domains.items():
                    print_formatted_text(HTML(f" <b>This device supports {DOMAINS[domain]}:</b>"))
                    for cap in caps:
                        print(f" - {cap}")
                    print('')
                    print_formatted_text(HTML(" <b>List of supported commands:</b>"))
                    for cmd in get_commands_desc(domain, dev.get_domain_commands(domain)):
                        try:
                            command_name, command_desc = cmd.split(":")
                            print_formatted_text(
                                HTML(f"  - <b>{command_name}</b>: {command_desc[1:]}")
                            )
                        except ValueError:
                            pass

                    print('')
            except Exception:
                error("[e] An error occurred while requesting this device." +
                      "We were not able to retrieve the supported domains.")

            dev.close()
        except WhadDeviceNotFound:
            error("Device not found")
            sys.exit(1)
        except WhadDeviceNotReady:
            error("Cannot communicate with the device. Make sure it is a " +
                  "WHAD compatible device and reset it.")
        except PermissionError:
            error("Cannot access the requested device (permission error).")
    else:
        info("Available devices")
        for device in Device.list(): #print("Usage: %s [device]" % sys.argv[0])
            print_formatted_text(HTML(f"- <b>{device.interface}</b>"))
            print_formatted_text(HTML(f"  <b>Type</b>: {device.type}"))
            print_formatted_text(HTML(f"  <b>Index</b>: {device.index}"))
            print_formatted_text(HTML(f"  <b>Identifier</b>: {device.identifier}"))
            print()

if __name__ == "__main__":
    # whadup/wup launcher.
    main()
