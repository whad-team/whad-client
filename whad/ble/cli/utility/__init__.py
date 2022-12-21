"""Bluetooth Low Energy utility for WHAD

This utility is exposed in WHAD as `ble-central` and provides the following
features:

- BLE scanning
- GATT client
- Device emulation

$ ble-central scan    -> find the first usable BLE-capable device
$ ble-central -i uart scan
$ ble-central connect <bd address> <random/public>
 -> gatttool like, spawns a shell
$ ble-central -> spawns a shell
$ ble-central emulate myfile.json
$ ble-central sniff <bd address> -> capture connections to this device and save to a pcap

"""
from whad.ble.cli.utility.shell import BleUtilityShell

from whad.cli.app import CommandLineApp
from .commands import *

class BleUtilityApp(CommandLineApp):

    def __init__(self):
        super().__init__(self,'ble-central', description='WHAD Bluetooth Low Energy central utility')
        
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

def ble_central_main():
    app = BleUtilityApp()
    app.run()