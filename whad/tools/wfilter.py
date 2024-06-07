"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineDevicePipe, CommandLineApp
from scapy.all import *
#from whad.common.ipc import IPCPacket
from whad.device.unix import UnixSocketProxy, UnixSocketCallbacksConnector
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet

import logging
import time

logger = logging.getLogger(__name__)

class WhadFilterApp(CommandLineApp):

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
            'filter',
            help='filter to evaluate',
            default='True'
        )

        self.add_argument(
            '-t',
            '--transform',
            dest='transform',
            type=str,
            default=None,
            help='apply a transformation'
        )

        self.add_argument(
            '-e',
            '--invert',
            dest='invert',
            action="store_true",
            default=False,
            help='invert filter'
        )

        self.add_argument(
            '-f',
            '--forward',
            dest='forward',
            action="store_true",
            default=False,
            help='forward packets not matched by the filter (dropped by default)'
        )
    def build_filter(self):
        filter_template = "lambda p : not %s" if self.args.invert else "lambda p : %s"

        if "packet." in self.args.filter:
            self.args.filter.replace("packet.", "p.")
        elif "pkt." in self.args.filter:
            self.args.filter.replace("pkt.", "p.")

        return eval(filter_template % (self.args.filter))

    def on_rx_packet(self, pkt):
        filter = self.build_filter()
        try:
            if filter(pkt):
                if self.args.transform is not None:
                    p = packet = pkt
                    exec(self.args.transform)
                print(self.args.forward)
                if not self.is_stdout_piped():
                    display_packet(pkt)
                return pkt
            else:

                if self.args.forward:
                    display_packet(pkt)
                    return pkt
                return None
        except:
            print(self.args.forward)

            if self.args.forward:
                display_packet(pkt)
                return pkt
            return None

    def on_tx_packet(self, pkt):
        filter = self.build_filter()
        try:
            if filter(pkt):
                if self.args.transform is not None:
                    p = packet = pkt
                    exec(self.args.transform)
                if not self.is_stdout_piped():
                    display_packet(pkt)
                return pkt
            else:
                if self.args.forward:
                    display_packet(pkt)
                    return pkt
                return None
        except:
            print(self.args.forward)
            if self.args.forward:
                display_packet(pkt)
                return pkt
            return None



    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            if self.is_piped_interface():
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                parameters = self.args.__dict__

                parameters.update({
                    "on_tx_packet_cb" : self.on_tx_packet,
                    "on_rx_packet_cb" : self.on_rx_packet,
                })
                proxy = UnixSocketProxy(
                    self.input_interface,
                    params=parameters,
                    connector=UnixSocketCallbacksConnector
                )
                proxy.start()
                proxy.join()

                while True:
                    time.sleep(1)

        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wfilter_main():
    app = WhadFilterApp()
    app.run()
