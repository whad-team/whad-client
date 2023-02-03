"""Bluetooth Low Energy peripheral utility for WHAD
"""
from time import time
from binascii import hexlify, unhexlify
from os.path import exists, isfile
from prompt_toolkit import print_formatted_text, HTML
from json import loads, dumps
from hexdump import hexdump

from whad.cli.app import CommandLineApp
from whad.ble import AdvDataFieldList
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.profile.characteristic import CharacteristicProperties
#from whad.ble.cli.central.helpers import show_att_error
from whad.ble.cli.peripheral.shell import BlePeriphShell

from .commands import *

class BlePeriphApp(CommandLineApp):

    def __init__(self):
        super().__init__(
            description='WHAD Bluetooth Low Energy peripheral utility',
            commands = True,
            interface = True
        )

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

        # Advertising Data fields
        self.adv_fields = AdvDataFieldList()


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()

        if self.args.script is not None:
            # We need to have an interface specified
            if self.interface is not None:
                # Launch an interactive shell (well, driven by our script)
                myshell = BlePeriphShell(self.interface)
                myshell.run_script(self.args.script)
            else:
                self.error('You need to specify an interface with option --interface.')
        else:
            super().run()

        # Launch post-run tasks
        self.post_run()

def ble_periph_main():
    app = BlePeriphApp()
    app.run()