"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time
from whad.tools.whadsniff import display_packet

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLinePipe
from scapy.all import *
from whad.common.ipc import IPCPacket
import sys
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
logger = logging.getLogger(__name__)

class WhadDumpApp(CommandLinePipe):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD dump tool',
            interface=True,
            commands=False
        )

        self.add_argument(
            '-p',
            '--pcap',
            dest="pcap",
            help='PCAP file'
        )

    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            if self.is_stdin_piped():
                pcap = None
                if self.args.pcap:
                    pcap = PcapWriterMonitor(self.args.pcap)
                    pcap.start()

                while True:
                    dump = sys.stdin.readline()
                    pkt = IPCPacket.from_dump(dump.replace("\n", ""))
                    if pcap is not None:
                        print("[i] Dumping ", repr(pkt))
                        pcap.process_packet(pkt)
            else:
                self.error("This tool must be piped.")
        except KeyboardInterrupt:
            if pcap is not None:
                pcap.stop()
                pcap.close()

        # Launch post-run tasks
        self.post_run()


def whaddump_main():
    app = WhadDumpApp()
    app.run()
