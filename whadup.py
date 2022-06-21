"""
Whad up ?
"""
import sys

from whad.device.uart import UartDevice
from whad.protocol.ble.ble_pb2 import BleCommand
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
    BleCommand.PeripheralMode: 'PeripharlMode: can act as a peripheral',
    BleCommand.Start: 'Start: can start depending on the current mode',
    BleCommand.Stop: 'Stop: can stop depending on the current mode',
    BleCommand.Hijack: 'Hijack: can hijack an active connection'
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


def get_domain_supported_commands(domain, commands):
    if domain == WhadDomain.BtLE:
        return get_ble_supported_commands(commands)
    return []

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target device
        device = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            print('[i] Connecting to device ...')
            dev = UartDevice(device, 115200)
            dev.open()
            print('[i] Discovering domains ...')
            dev.discover()

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

            dev.close()


        except Exception as err:
            print('oops')
            print(type(err))

    else:
        print('Usage: %s [device]' % sys.argv[0])