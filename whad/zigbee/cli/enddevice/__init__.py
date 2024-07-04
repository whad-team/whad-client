"""Zigbee utility for WHAD

This utility is exposed in WHAD as `zigbee-enddevice` and provides the following
features:

- Network scanning
- Network association
- Device emulation

$ zigbee-enddevice scan -> find the first usable BLE-capable device
$ zigbee-enddevice -i uart scan
$ zigbee-enddevice associate <network pan id>
$ zigbee-enddevice -> spawns a shell

"""
from whad.cli.app import CommandLineApp, run_app

from .helpers import create_enddevice
from .shell import ZigbeeEndDeviceShell
from .commands import *


class ZigbeeEndDeviceApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD ZigBee End device utility',
            interface=True,
            commands=True
        )

        self.add_argument(
            '--network-panid',
            '-t',
            dest='network_panid',
            help='Specify target network extended Pan ID'
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
            if self.is_piped_interface():
                # Make sure we have all the required parameters
                failed = False
                for param in []:
                    if not hasattr(self.args, param):
                        self.error('Source interface does not provide a Zigbee connection')
                        failed = True
                        break

                if not failed:
                    # Create central device
                    enddevice, _ = create_enddevice(self, piped=True)

                    if enddevice is not None:
                        myshell = ZigbeeEndDeviceShell(
                            self.input_interface,
                            connector=enddevice,
                            extended_address=self.args.network_panid
                        )
                        myshell.run_script(self.args.script)
                    else:
                        self.error('Failed to open piped interface.')

            # We need to have an interface specified
            elif self.interface is not None:
                # Launch an interactive shell (well, driven by our script)
                myshell = ZigbeeEndDeviceShell(self.interface)
                myshell.run_script(self.args.script)
            else:
                self.error('You need to specify an interface with option --interface.')
        else:
            super().run(pre=False, post=False)

        # Launch post-run tasks
        self.post_run()

def zigbee_enddevice_main():
    app = ZigbeeEndDeviceApp()
    run_app(app)
