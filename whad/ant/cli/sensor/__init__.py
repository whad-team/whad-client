"""
ANT+ Sensor utility for WHAD.

This utility is exposed in WHAD as `wantplus-sensor` and provides the following
features:

- Create an ANT+ sensor according to a device type
- Configure sensor profile attributes
- Start and stop ANT+ sensor transmission
- Inspect profile attributes and data pages
- Monitor profile attributes in real-time
- Send specific ANT+ data pages
- Monitor packets using Wireshark

Examples:

$ wantplus-sensor -i uart -t 120
$ wantplus-sensor -i uart -t 120
"""

import logging

from whad.cli.app import CommandLineApp, run_app

from .shell import AntPlusSensorShell

logger = logging.getLogger(__name__)


class AntPlusSensorApp(CommandLineApp):
    """
    ANT+ Sensor application.
    """

    def __init__(self):
        super().__init__(
            description="WHAD ANT+ Sensor utility",
            interface=True,
            commands=True,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            "--device-type",
            "-t",
            default=120,
            dest="device_type",
            type=lambda x: int(x, 0),
            help="ANT+ device type (e.g. 120, 0x78)"
        )

        self.add_argument(
            "--device-number",
            "-n",
            dest="device_number",
            default=1234,
            type=lambda x: int(x, 0),
            help="ANT+ device number (default: 1234)"
        )

        self.add_argument(
            "--transmission-type",
            dest="transmission_type",
            default=1,
            type=lambda x: int(x, 0),
            help="ANT+ transmission type (default: 1)"
        )

        self.add_argument(
            "--file",
            "-f",
            dest="script",
            help="Specify a script to run"
        )

    def run(self):
        """
        Run the ANT+ Sensor application.
        """

        logger.debug("Executing pre-run hook")
        self.pre_run()

        logger.debug("Executing main code")

        try:
            shell = AntPlusSensorShell(
                self.interface,
                device_type=self.args.device_type,
                device_number=self.args.device_number,
                transmission_type=self.args.transmission_type
            )

            if self.args.script is not None:
                shell.run_script(self.args.script)
            else:
                shell.run()

        except ValueError:
            self.error(
                f"Invalid device type: {self.args.device_type}"
            )

        finally:
            super().run(pre=False, post=False)

        logger.debug("Executing post-run hook")
        self.post_run()


def antplus_sensor_main():
    """
    ANT+ Sensor application main routine.
    """

    app = AntPlusSensorApp()
    run_app(app)