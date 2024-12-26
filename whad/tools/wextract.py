"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import sys
import time
import logging
from typing import List, Tuple

from scapy.packet import Packet
from scapy.config import conf
from scapy.themes import BrightTheme

from whad.cli.app import CommandLineApp, run_app
from whad.device.unix import  UnixSocketConnector
from whad.hub import ProtocolHub

logger = logging.getLogger(__name__)

class WhadExtractApp(CommandLineApp):
    """
    Main `wextract` CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD filter tool',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            'extractor',
            help='extractor to evaluate',
            nargs='*'
        )

        self.add_argument(
            '-d',
            '-D',
            '--delimiter',
            dest='delimiter',
            default=" ",
            help='delimiter between extractor'
        )

        self.add_argument(
            '-l',
            '--load',
            dest='loadables',
            default=None,
            action="append",
            help='load Scapy packet definitions from external Python file'
        )

    def build_extractors(self):
        """Build extracors based on provided arguments.
        """
        extractor_template = "lambda p : %s"
        extractors = []
        for extractor in self.args.extractor:
            if "packet." in extractor:
                extractor.replace("packet.", "p.")
            elif "pkt." in extractor:
                extractor.replace("pkt.", "p.")
            extractors.append((extractor, eval(extractor_template % extractor)))

        return extractors

    def on_packet(self, pkt) -> Packet:
        """
        Packet processing callback

        :param pkt: Packet to process
        :type pkt: Packet
        :return: Processed packet
        :rtype: Packet
        """
        extractors = self.build_extractors()
        output = []
        for extractor,processor in extractors:
            try:
                output.append(str(processor(pkt)))
            except Exception:
                sys.stderr.write(f"Exception raised when evaluating {extractor}\n")
                sys.stderr.flush()
                return pkt

        print(self.args.delimiter.join(output))
        sys.stdout.flush()
        return pkt


    def run(self):
        # Launch pre-run tasks
        self.pre_run()

        # Load any Scapy definition files if provided
        for loadable in self.args.loadables:
            l = __import__(loadable)
            for obj in dir(l):
                o = getattr(l, obj)
                try:
                    if issubclass(o, Packet) and o != Packet:
                        globals()[obj] = o
                except TypeError:
                    pass
        try:
            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                parameters = self.args.__dict__

                connector = UnixSocketConnector(interface)
                for parameter_name, parameter_value in parameters.items():
                    connector.add_parameter(parameter_name, parameter_value)

                connector.domain = self.args.domain
                hub = ProtocolHub(2)
                connector.format = hub.get(self.args.domain).format
                connector.on_packet = self.on_packet

                while interface.opened:
                    time.sleep(.1)

        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wextract_main():
    """Launcher for `wextract` CLI application.
    """
    app = WhadExtractApp()
    run_app(app)
