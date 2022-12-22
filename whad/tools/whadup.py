"""
Whad up ?
"""
import sys
from whad.exceptions import WhadDeviceNotFound
from whad.device import WhadDevice
from whad.protocol.ble.ble_pb2 import BleCommand
from whad.protocol.zigbee.zigbee_pb2 import ZigbeeCommand
from whad.protocol.esb.esb_pb2 import ESBCommand
from whad.protocol.unifying.unifying_pb2 import UnifyingCommand
from whad.protocol.phy.phy_pb2 import PhyCommand
from whad import WhadDomain, WhadCapability

DOMAINS = {
    WhadDomain.Phy: 'Physical Layer',
    WhadDomain.ANT: 'ANT',
    WhadDomain.ANT_FS: 'ANT FS',
    WhadDomain.ANT_Plus: 'ANT+',
    WhadDomain.BtClassic: 'Bluetooth Classic',
    WhadDomain.BtLE: 'Bluetooth LE',
    WhadDomain.Esb: 'Enhanced ShockBurst',
    WhadDomain.LogitechUnifying: 'Logitech Unifying',
    WhadDomain.Mosart: 'Mosart',
    WhadDomain.SixLowPan: '6LowPan',
    WhadDomain.Zigbee: 'ZigBee'
}

CAPABILITIES = {
    WhadCapability.Scan: 'can scan devices',
    WhadCapability.Hijack: 'can hijack communication',
    WhadCapability.Hook: 'can hook packets',
    WhadCapability.Inject: 'can inject packets',
    WhadCapability.Jam: 'can jam communications',
    WhadCapability.SimulateRole: 'can simulate a role in a communication',
    WhadCapability.Sniff: 'can sniff data',
    WhadCapability.NoRawData: 'can not read/write raw packet'
}

BLE_COMMANDS = {
    BleCommand.SetBdAddress: 'SetBdAddress: can set BD address',
    BleCommand.SniffAdv: 'SniffAdv: can sniff advertising PDUs',
    BleCommand.JamAdv: 'JamAdv: can jam advertising PDUs',
    BleCommand.SniffConnReq: 'SniffConnReq: can sniff a new connection',
    BleCommand.SniffAccessAddress: 'SniffAccessAddress: can detect active connections',
    BleCommand.SniffActiveConn: 'SniffActiveConn: can sniff an active connection',
    BleCommand.JamConn: 'JamConn: can jam an active connection',
    BleCommand.ScanMode: 'ScanMode: can scan devices',
    BleCommand.AdvMode: 'AdvMode: can advertise as a BLE device',
    BleCommand.SetAdvData: 'SetAdvData: can set advertising PDU details',
    BleCommand.CentralMode: 'CentralMode: can act as a Central device',
    BleCommand.ConnectTo: 'ConnectTo: can initiate a BLE connection',
    BleCommand.SendPDU: 'SendPDU: can send a raw PDU',
    BleCommand.Disconnect: 'Disconnect: can terminate an active connection (in Central mode)',
    BleCommand.PeripheralMode: 'PeripheralMode: can act as a peripheral',
    BleCommand.Start: 'Start: can start depending on the current mode',
    BleCommand.Stop: 'Stop: can stop depending on the current mode',
    BleCommand.HijackMaster: 'HijackMaster: can hijack the Master role in an active connection',
    BleCommand.HijackSlave: 'HijackSlave: can hijack the Slave role in an active connection',
    BleCommand.PrepareSequence: 'PrepareSequence: can prepare a sequence of packets and associate a trigger',
    BleCommand.TriggerSequence: 'TriggerSequence: can manually trigger the transmission of a sequence of packets',
    BleCommand.DeleteSequence: 'DeleteSequence: can delete a prepared sequence of packets'

}

ZIGBEE_COMMANDS = {
    ZigbeeCommand.SetNodeAddress: "SetNodeAddress: can set Node address",
    ZigbeeCommand.Sniff: "Sniff: can sniff Zigbee packets",
    ZigbeeCommand.EnergyDetection: "EnergyDetection: can perform energy detection scans",
    ZigbeeCommand.Jam: "Jam: can jam Zigbee packets",
    ZigbeeCommand.Send: "Send: can transmit Zigbee packets",
    ZigbeeCommand.EndDeviceMode: "EndDeviceMode: can act as an End Device",
    ZigbeeCommand.CoordinatorMode: "CoordinatorMode: can act as a Coordinator",
    ZigbeeCommand.RouterMode: "RouterMode: can act as a Router",
    ZigbeeCommand.Start: "Start: can start depending on the current mode",
    ZigbeeCommand.Stop: "Stop: can stop depending on the current mode",
    ZigbeeCommand.ManInTheMiddle: "ManInTheMiddle: can perform a Man-in-the-Middle attack",
}

ESB_COMMANDS = {
    ESBCommand.SetNodeAddress: "SetNodeAddress: can set Node address",
    ESBCommand.Sniff: "Sniff: can sniff Enhanced ShockBurst packets",
    ESBCommand.Jam: "Jam: can jam Enhanced ShockBurst packets",
    ESBCommand.Send: "Send: can transmit Enhanced ShockBurst packets",
    ESBCommand.PrimaryReceiverMode: "PrimaryReceiverMode: can act as a Primary Receiver (PRX)",
    ESBCommand.PrimaryTransmitterMode: "PrimaryReceiverMode: can act as a Primary Receiver (PTX)",
    ESBCommand.Start: "Start: can start depending on the current mode",
    ESBCommand.Stop: "Stop: can stop depending on the current mode"
}

UNIFYING_COMMANDS = {
    UnifyingCommand.SetNodeAddress: "SetNodeAddress: can set Node address",
    UnifyingCommand.Sniff: "Sniff: can sniff Logitech Unifying packets",
    UnifyingCommand.Jam: "Jam: can jam Logitech Unifying packets",
    UnifyingCommand.Send: "Send: can transmit Logitech Unifying packets",
    UnifyingCommand.LogitechDongleMode: "PrimaryReceiverMode: can act as a Logitech Dongle (ESB PRX)",
    UnifyingCommand.LogitechKeyboardMode: "PrimaryReceiverMode: can act as a Logitech Keyboard (ESB PTX)",
    UnifyingCommand.LogitechMouseMode: "LogitechMouseMode: can act as a Logitech Mouse (ESB PTX)",
    UnifyingCommand.Start: "Start: can start depending on the current mode",
    UnifyingCommand.Stop: "Stop: can stop depending on the current mode",
    UnifyingCommand.SniffPairing: "SniffPairing: can sniff a pairing process"
}

PHY_COMMANDS = {
    PhyCommand.SetASKModulation: "SetASKModulation: can use Amplitude Shift Keying modulation scheme",
    PhyCommand.SetFSKModulation: "SetFSKModulation: can use Frequency Shift Keying modulation scheme",
    PhyCommand.SetGFSKModulation: "SetGFSKModulation: can use Gaussian Frequency Shift Keying modulation scheme",
    PhyCommand.SetBPSKModulation: "SetBPSKModulation: can use Binary Phase Shift Keying modulation scheme",
    PhyCommand.SetQPSKModulation: "SetQPSKModulation: can use Quadrature Phase Shift Keying modulation scheme",
    PhyCommand.SetSubGhzFrequency: "SetSubGhzFrequency: can interact with SubGHz frequency bands",
    PhyCommand.SetTwoDotFourGhzFrequency: "SetTwoDotFourGhzFrequency: can interact with 2.4 GHz ISM frequency band",
    PhyCommand.SetFiveGhzFrequency: "SetFiveGhzFrequency: can interact with 5 GHz frequency band",
    PhyCommand.SetDataRate: "SetDataRate: can configure the datarate",
    PhyCommand.SetEndianness: "SetEndianness: can configure the endianness",
    PhyCommand.SetTXPower: "SetTXPower: can configure the transmission power level",
    PhyCommand.SetPacketSize: "SetPacketSize: can configure the packet size",
    PhyCommand.SetSyncWord: "SetSyncWord: can configure the synchronization word",
    PhyCommand.Sniff: "Sniff: can receive arbitrary packets",
    PhyCommand.Send: "Send: can transmit arbitrary packets",
    PhyCommand.SendRaw: "SendRaw: can transmit arbitrary IQ streams" ,
    PhyCommand.Jam: "Jam: can jam a physical medium",
    PhyCommand.Monitor: "Monitor: can monitor a physical medium",
    PhyCommand.Start: "Start: can start depending on the current mode",
    PhyCommand.Stop: "Stop: can stop depending on the current mode"
}
COMMANDS = {
    WhadDomain.BtLE: BLE_COMMANDS,
    WhadDomain.Esb: ESB_COMMANDS,
    WhadDomain.Zigbee: ZIGBEE_COMMANDS,
    WhadDomain.LogitechUnifying: UNIFYING_COMMANDS,
    WhadDomain.Phy: PHY_COMMANDS

}


def get_readable_capabilities(caps):
    capabilities = []
    for i in range(24):
        if caps & (1 << i):
            capabilities.append(CAPABILITIES[caps & (1 << i)])
    return capabilities

def get_domain_supported_commands(domain, commands):
    supp_commands = []
    if domain in COMMANDS:
        for i in COMMANDS[domain].keys():
            if commands & (1 << i):
                supp_commands.append(COMMANDS[domain][i])
    return supp_commands

def main():
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery

        try:
            dev = WhadDevice.create(interface)

            print('[i] Connecting to device ...')
            dev.open()
            dev.discover()

            print('[i] Device details')
            print('')
            print(' Device ID: %s' % ":".join(["{:02x}".format(i) for i in dev.device_id.encode()]))
            print(' Firmware info: ')
            if len(dev.info.fw_author) > 0:
                print(' - Author : %s' % dev.info.fw_author)
            if len(dev.info.fw_url) > 0:
                print(' - URL    : %s' % dev.info.fw_url)
            print(' - Version: %s' % dev.info.version_str)
            print('')
            print('[i] Discovering domains ...')
            domains = {}
            for domain in dev.get_domains():
                if domain in DOMAINS:
                    caps_val = dev.get_domain_capability(domain)
                    domains[domain] = get_readable_capabilities(caps_val)
            print('[i] Domains discovered.')
            print('')

            for domain in domains:
                print('This device supports %s:' % DOMAINS[domain])
                for cap in domains[domain]:
                    print(' - %s' % cap)
                print('')
                print(' List of supported commands:')
                for cmd in get_domain_supported_commands(domain, dev.get_domain_commands(domain)):
                    print('  - %s' % cmd)
                print('')

            dev.close()
        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)

        #except Exception as err:
        #    print(err)
        #    print('oops')
        #    print(type(err))

    else:
        print("[i] Available devices")
        for device in WhadDevice.list(): #print('Usage: %s [device]' % sys.argv[0])
            print("-",device.interface)
            print("  Type:",device.type)
            print("  Index:", device.index)
            print("  Identifier:", device.identifier)
            print()

if __name__ == '__main__':
    main()