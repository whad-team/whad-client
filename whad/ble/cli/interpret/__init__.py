"""Bluetooth Low Energy interpret utility for WHAD

This utility is exposed in WHAD as `ble-interpret` and provides the following
features:

- PCAP interpretation
"""
from os.path import exists, isfile
from whad.cli.app import CommandLineApp, ApplicationError
from whad.ble.cli.interpret.interpreter import interpret_pcap

class BleInterpretApp(CommandLineApp):

    def __init__(self):
        super().__init__(
            description='WHAD Bluetooth Low Energy central utility',
            commands = False,
            interface = False
        )
        self.add_argument('pcap', metavar='PCAP', help='PCAP file to analyze')

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()
        print(self.args)
        if self.args.pcap is not None:
            if exists(self.args.pcap) and isfile(self.args.pcap):
                interpret_pcap(self.args.pcap)
            else:
                self.error('Cannot open pcap file.')
        else:
            super().run()

        # Launch post-run tasks
        self.post_run()

def ble_interpret_main():
    try:
        app = BleInterpretApp()
        app.run()
    except ApplicationError as err:
        err.show()