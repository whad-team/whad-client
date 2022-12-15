"""Bluetooth Low Energy utility for WHAD

This utility is exposed in WHAD as `whad-ble` and provides the following
features:

- BLE scanning
- GATT client
- Device emulation

$ whad-ble scan    -> find the first usable BLE-capable device
$ whad-ble -i uart scan
$ whad-ble connect <bd address> <random/public>
 -> gatttool like, spawns a shell
$ whad-ble -> spawns a shell
$ whad-ble emulate myfile.json
$ whad-ble sniff <bd address> -> capture connections to this device and save to a pcap

"""
from argparse import ArgumentParser
from os.path import exists, isfile
from whad.device import WhadDevice
from whad.ble.cli.utility.shell import BleUtilityShell
from .interpreter import interpret_pcap

def ble_tool_main():

    parser = ArgumentParser()
    parser.add_argument(
        '--interactive',
        '-I',
        dest='interactive',
        action='store_true',
        default=False,
        help='Enable interactive mode'
    )
    parser.add_argument(
        '--interface',
        '-i',
        dest='interface',
        help='WHAD interface to use'
    )
    parser.add_argument(
        '--bdaddr',
        '-b',
        dest='bdaddr',
        help='Specify target BD address'
    )
    parser.add_argument(
        'command',
        metavar='COMMAND',
        nargs='?',
        help="command to execute, use 'help' for a list of supported commands"
    )
    parser.add_argument(
        'command_args',
        metavar='COMMAND_ARG',
        nargs='*',
        help="command arguments"
    )

    args = parser.parse_args()
    if args.interactive:
        if args.interface is not None:
            interface = WhadDevice.create(args.interface)
            BleUtilityShell(interface).cmdloop()
        else:
            print('You must specify an interface when running interactive mode.')
    elif args.command is not None:
        # Parse command
        command = args.command.lower()
        if command == 'help':
            # Show command list
            print('command list')
        elif command == 'interpret' and len(args.command_args)>0:
            pcap_file = args.command_args[0]
            print(pcap_file)
            if exists(pcap_file) and isfile(pcap_file):
                # Allright, launch the interpeter
                interpret_pcap(pcap_file)
            else:
                print('Cannot access provided PCAP file.')
            
    else:
        parser.print_help()