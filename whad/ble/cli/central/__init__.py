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
import logging
from whad.cli.app import CommandLineApp, ApplicationError

from .shell import BleCentralShell
from .commands import *

logger = logging.getLogger(__name__)

class BleCentralApp(CommandLineApp):
    """BLE Central-role application.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy central utility',
            interface=True,
            commands=True,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            '--bdaddr',
            '-b',
            dest='bdaddr',
            help='Specify target BD address'
        )

        self.add_argument(
            '--spoof-public',
            '-s',
            dest='bdaddr_pub_src',
            help='Specify a public BD address to spoof'
        )

        self.add_argument(
            '--spoof-random',
            dest='bdaddr_rand_src',
            help='Specify a random BD address to spoof'
        )

        self.add_argument(
            '--file',
            '-f',
            dest='script',
            help='Specify a script to run'
        )

        self.add_argument(
            '--profile',
            '-p',
            dest='profile',
            help='Use a saved device profile'
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        logger.debug("Executing pre-run hook")
        self.pre_run()

        logger.debug("Executing main code")
        if self.args.script is not None:
            logger.debug("Checking is input interface is piped")
            if self.is_piped_interface():
                # Make sure we have all the required parameters
                failed = False
                for param in ['initiator_bdaddr', 'initiator_addrtype', 'target_bdaddr', 'target_addrtype', 'conn_handle']:
                    if not hasattr(self.args, param):
                        self.error('Source interface does not provide a BLE connection')
                        failed = True
                        break

                if not failed:
                    # Create central device
                    central, _ = create_central(self, piped=True)

                    if central is not None:
                        myshell = BleCentralShell(
                            self.input_interface,
                            connector=central,
                            bd_address=self.args.target_bdaddr
                        )
                        myshell.run_script(self.args.script)
                    else:
                        self.error("Failed to open piped interface.")

            # We need to have an interface specified
            elif self.interface is not None:
                # Launch an interactive shell (well, driven by our script)
                logger.debug("Launching interactive shell with interface %s", self.interface)
                myshell = BleCentralShell(self.interface)
                myshell.run_script(self.args.script)
        else:
            super().run(pre=False, post=False)

        # Launch post-run tasks
        logger.debug("Executing post-run hook")
        self.post_run()

def ble_central_main():
    """BLE Central application main routine.
    """
    try:
        # Run our central app
        app = BleCentralApp()
        app.run()
    except ApplicationError as err:
        # If an error occured, display it.
        err.show()
