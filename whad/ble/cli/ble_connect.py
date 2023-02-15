"""Bluetooth Low Energy connect tool

This utility will configure a compatible whad device to connect to a given
BLE device, and chain this with another tool.

"""
from whad.cli.app import CommandLineApp
from whad.ble.connector import Central
from whad.device.unix import UnixSocketProxy

import logging
logger = logging.getLogger(__name__)


class BleConnectApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy connect tool',
            interface=True,
            commands=False
        )

        self.add_argument('bdaddr', metavar='BDADDR', help='Target device BD address')
        # Add an optional random type argument
        self.add_argument(
            '-r',
            '--random',
            dest='random',
            action='store_true',
            default=False,
            help='Use a random connection type'
        )
    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()

        # We need to have an interface specified
        if self.interface is not None:
            # Make sure we are piped to another tool
            if self.is_stdout_piped():
                # Connect to the target device
                self.connect_target(self.args.bdaddr, self.args.random)
            else:
                self.error('Tool must be piped to another WHAD tool.')
        else:
            self.error('You need to specify an interface with option --interface.')

        # Launch post-run tasks
        self.post_run()

    def connect_target(self, bdaddr, random_connection_type=False):
        """Connect to our target device
        """
        # Configure our interface
        central = Central(self.interface)

        # Connect to our target device
        periph = central.connect(bdaddr, random_connection_type)
        if periph is None:
            # Could not connect
            self.error('Cannot connect to %s' % bdaddr)
        else:
            # Get peers
            logger.info('local_peer: %s' % central.local_peer)

            # Connected, starts a Unix socket proxy that will relay the underlying
            # device WHAD messages to the next tool.
            proxy = UnixSocketProxy(self.interface, {
                'conn_handle':periph.conn_handle,
                'initiator_bdaddr':str(central.local_peer),
                'initiator_addrtype':str(central.local_peer.type),
                'target_bdaddr':str(central.target_peer),
                'target_addrtype': str(central.target_peer.type)
            })
            proxy.start()
            proxy.join()
            central.stop()


def ble_connect_main():
    app = BleConnectApp()
    app.run()
