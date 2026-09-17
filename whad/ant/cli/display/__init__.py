"""ANT+ Display utility for WHAD

This utility is exposed in WHAD as `wantplus-display` and provides the following
features:

- ANT+ device scanning (list supported device types)
- Connect to ANT+ sensors (Heart Rate Monitor, Speed & Cadence, etc.)
- Receive and display ANT+ data in real-time

$ wantplus-display scan -> list available ANT+ device types
$ wantplus-display -i uart connect 0x78
$ wantplus-display -> spawns an interactive shell

"""
import logging

from whad.cli.app import CommandLineApp, run_app

from .shell import AntPlusDisplayShell

logger = logging.getLogger(__name__)

class AntPlusDisplayApp(CommandLineApp):
    """ANT+ Display application.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD ANT+ Display utility',
            interface=True,
            commands=True,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            "--device-type",
            "-t",
            dest="device_type",
            help="Specify target ANT+ device type (e.g. 120, 0x78)"
        )

        self.add_argument(
            "--file",
            "-f",
            dest="script",
            help="Specify a script to run"
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        logger.debug("Executing pre-run hook")
        self.pre_run()

        logger.debug("Executing main code")
        if self.args.script is not None:
            if self.is_piped_interface():
                # Make sure we have all the required parameters
                failed = False
                for param in []:
                    if not hasattr(self.args, param):
                        self.error('Source interface does not provide an ANT+ connection')
                        failed = True
                        break

                if not failed:
                    myshell = AntPlusDisplayShell(
                        self.input_interface,
                        connector=None
                    )
                    myshell.run_script(self.args.script)
                else:
                    self.error('Failed to open piped interface.')

            # We need to have an interface specified
            elif self.interface is not None:
                myshell = AntPlusDisplayShell(self.interface)
                myshell.run()
            else:
                self.error('You need to specify an interface with option --interface.')
        else:
            if self.interface is not None:
                myshell = AntPlusDisplayShell(self.interface)
                myshell.run()
            else:
                super().run(pre=False, post=False)

        # Launch post-run tasks
        logger.debug("Executing post-run hook")
        self.post_run()

def antplus_display_main():
    """ANT+ Display application main routine.
    """
    # Run our app
    app = AntPlusDisplayApp()
    run_app(app)
