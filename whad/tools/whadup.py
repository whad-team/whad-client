"""
Whad up ?
"""
import sys
from whad.exceptions import WhadDeviceNotFound
from whad.device import WhadDevice
from whad.protocol.ble.ble_pb2 import BleCommand
from whad.protocol.zigbee.zigbee_pb2 import ZigbeeCommand
from whad import WhadDomain, WhadCapability

DOMAINS = {
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
    WhadCapability.Hijack: 'can hijack connections',
    WhadCapability.Hook: 'can hook packets',
    WhadCapability.Inject: 'can inject packets',
    WhadCapability.Jam: 'can jam connections',
    WhadCapability.MasterRole: 'can act as a master',
    WhadCapability.SlaveRole: 'can act as a slave',
    WhadCapability.EndDeviceRole: 'can act as an end device',
    WhadCapability.RouterRole: 'can act as a router',
    WhadCapability.CoordinatorRole: 'can act as a coordinator',
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
    BleCommand.HijackSlave: 'HijackSlave: can hijack the Slave role in an active connection'
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

def get_readable_capabilities(caps):
    capabilities = []
    for i in range(24):
        if caps & (1 << i):
            capabilities.append(CAPABILITIES[caps & (1 << i)])
    return capabilities

def get_ble_supported_commands(commands):
    supp_commands = []
    for i in BLE_COMMANDS.keys():
        if commands & (1 << i):
            supp_commands.append(BLE_COMMANDS[i])
    return supp_commands

def get_zigbee_supported_commands(commands):
    supp_commands = []
    for i in ZIGBEE_COMMANDS.keys():
        if commands & (1 << i):
            supp_commands.append(ZIGBEE_COMMANDS[i])
    return supp_commands

def get_domain_supported_commands(domain, commands):
    if domain == WhadDomain.BtLE:
        return get_ble_supported_commands(commands)
    elif domain == WhadDomain.Zigbee:
        return get_zigbee_supported_commands(commands)
    return []

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
