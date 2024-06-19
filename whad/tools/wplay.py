"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time
from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLinePipe
from scapy.all import *
from whad.common.ipc import IPCConverter
import sys, os, stat
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.tools.wsniff import WhadSniffApp

logger = logging.getLogger(__name__)

class WhadPlayApp(WhadSniffApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD play tool',
            interface=False
        )

        self.add_argument(
            'pcap',
            help='pcap to play'
        )

    def pre_run(self):
        super().pre_run()
        if self.args.pcap is not None:
            self.interface = WhadDevice.create("pcap:" + self.args.pcap)
        else:
            exit(1)
            
    def run(self):
        super().run()


def wplay_main():
    app = WhadPlayApp()
    app.run()

wplay_main()
