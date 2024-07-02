"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineApp, ApplicationError
from scapy.all import *
#from whad.common.ipc import IPCPacket
from whad.device.unix import UnixSocketProxy, UnixSocketCallbacksConnector
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet

import logging
import time
import sys

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadExtractApp(CommandLineApp):

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
            '--delimiter',
            dest='delimiter',
            default=" ",
            help='delimiter between extractor'
        )

    def build_extractors(self):
        extractor_template = "lambda p : %s"
        extractors = []
        for extractor in self.args.extractor:
            if "packet." in extractor:
                extractor.replace("packet.", "p.")
            elif "pkt." in extractor:
                extractor.replace("pkt.", "p.")
            extractors.append(eval(extractor_template % extractor))

        return extractors

    def on_rx_packet(self, pkt):
        extractors = self.build_extractors()
        output = []
        try:
            for extractor in extractors:
                output.append(str(extractor(pkt)))
            print(self.args.delimiter.join(output))
            sys.stdout.flush()
            return pkt
        except:
            return pkt

    def on_tx_packet(self, pkt):
        extractors = self.build_extractors()
        output = []
        try:
            for extractor in extractors:
                output.append(str(extractor(pkt)))

            print(self.args.delimiter.join(output))
            sys.stdout.flush()
            return pkt
        except:
            return pkt

    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                parameters = self.args.__dict__

                parameters.update({
                    "on_tx_packet_cb" : self.on_tx_packet,
                    "on_rx_packet_cb" : self.on_rx_packet,
                })
                interface.open()

                proxy = UnixSocketProxy(
                    interface,
                    params=parameters,
                    connector=UnixSocketCallbacksConnector
                )
                if self.is_stdout_piped():
                    proxy.start()
                    proxy.join()

                while True:
                    time.sleep(1)

        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wextract_main():
    try:
        app = WhadExtractApp()
        app.run()
    except ApplicationError as err:
        err.show()
