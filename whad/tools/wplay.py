"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time
from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLinePipe, CommandLineApp
from scapy.all import *
from whad.common.pcap import extract_pcap_metadata
import sys, os, stat
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.tools.wsniff import list_implemented_sniffers

logger = logging.getLogger(__name__)

class WhadPlayApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD play tool',
            interface=False,
            commands=False
        )

        self.add_argument(
            '--hide_metadata',
            dest='metadata',
            action="store_false",
            help='Hide packets metadata'
        )
        self.add_argument(
            '--format',
            dest='format',
            action="store",
            default='repr',
            choices=['repr', 'show', 'raw', 'hexdump'],
            help='Indicate format to display packet'
        )

        self.add_argument(
            'pcap',
            help='pcap to play'
        )

    def run(self):
        self.pre_run()
        if self.args.pcap is not None:
            self.interface = WhadDevice.create("pcap:" + self.args.pcap)
            self.domain = extract_pcap_metadata(self.args.pcap)
            print(list_implemented_sniffers())



        self.post_run()


def wplay_main():
    app = WhadPlayApp()
    app.run()
