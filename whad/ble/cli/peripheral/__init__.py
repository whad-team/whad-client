"""Bluetooth Low Energy peripheral utility for WHAD
"""
import json

from whad.cli.app import CommandLineApp, run_app
from whad.ble.cli.peripheral.shell import BlePeriphShell
from whad.ble.utils.clues import CluesDb

from .commands.shell import interactive_handler, check_profile

class BlePeriphApp(CommandLineApp):
    """Bluetooth Low Energy Peripheral emulation app
    """

    def __init__(self):
        """Initialize our application: we need a WHAD interface (adapter) to be
        specified and we support custom commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy peripheral utility',
            commands = True,
            interface = True
        )

        # Add an option to specify the target Bluetooth Device address
        self.add_argument(
            '--bdaddr',
            '-b',
            dest='bdaddr',
            help='Specify target BD address'
        )

        # Add an option to provide an existing device profile
        self.add_argument(
            '--profile',
            '-p',
            dest='profile',
            help='Use a saved device profile'
        )

        # Add an option to allow scripting through a file
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

        # Preload CluesDb
        if not CluesDb.load_data():
            self.error("CLUES database could not be loaded, did you use `--recurse-submodules` when cloning the repository ?")

        if self.args.script is not None:
            # If a profile has been provided, load it
            if self.args.profile is not None:
                # Read profile
                with open(self.args.profile,'rb') as f:
                    profile_json = f.read()
                try:
                    if not check_profile(json.loads(profile_json)):
                        self.error("Invalid JSON file (does not contain a valid GATT profile).")
                        profile_json = None
                except json.decoder.JSONDecodeError as parsing_err:
                    self.error((f"Invalid JSON file, parsing error line {parsing_err.lineno}: "
                            f"{parsing_err.msg}"))
                    self.exit()
            else:
                profile_json = None

            # Launch an interactive shell (well, driven by our script)
            myshell = BlePeriphShell(self.interface, profile_json)
            myshell.run_script(self.args.script)
        else:
            # Run the application through WHAD's main app routine
            super().run()

        # Launch post-run tasks
        self.post_run()

def ble_periph_main():
    """Bluetooth Low Energy peripheral emulation main routine.
    """
    app = BlePeriphApp()
    run_app(app)
