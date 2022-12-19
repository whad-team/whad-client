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
from whad.ble.cli.utility.shell import BleUtilityShell

from whad.cli.app import CommandLineApp
from .commands import *

class BleUtilityApp(CommandLineApp):

    def __init__(self):
        super().__init__(self,'whad-ble', description='WHAD Bluetooth Low Energy utility')
        
        self.add_argument(
            '--bdaddr',
            '-b',
            dest='bdaddr',
            help='Specify target BD address'
        )

        self.add_argument(
            '--file',
            '-f',
            dest='script',
            help='Specify a script to run'
        )

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()

        if self.args.script is not None:
            # We need to have an interface specified
            if self.interface is not None:
                # Launch an interactive shell (well, driven by our script)
                myshell = BleUtilityShell(self.interface)
                myshell.run_script(self.args.script)
            else:
                self.error('You need to specify an interface with option --interface.')
        else:
            super().run()

        # Launch post-run tasks
        self.post_run()

def ble_tool_main():
    app = BleUtilityApp()
    app.run()