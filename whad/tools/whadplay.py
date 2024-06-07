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
from whad.common.ipc import IPCConverter
import sys, os, stat
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
logger = logging.getLogger(__name__)

class WhadPlayApp(CommandLinePipe):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD play tool',
            interface=True,
            commands=False
        )


        self.add_argument(
            'pcap',
            help='pcap to play',
            nargs = "*"
        )



    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        mode = os.fstat(0).st_mode
        pcap_list = self.args.pcap

        if self.is_stdin_piped():
            if not stat.S_ISREG(mode):
                print("Hello from whadplay (piped)")
            else:
                #print("Hello from whadplay (redirected)")
                pcap_list += ["/dev/stdin"]
        else:
            pass#print("Hello from whadplay")

        if self.is_stdout_piped():
            if not stat.S_ISREG(mode):
                for pcap in pcap_list:
                    for pkt in rdpcap(pcap):
                        sys.stdout.write(IPCConverter(pkt[1:]).to_dump()+"\n")
                        sys.stdout.flush()
            else:
                for pcap in pcap_list:
                    for pkt in rdpcap(pcap):
                        wrpcap("/dev/stdout", pkt, append=True)
        else:
                for pcap in pcap_list:
                    for pkt in rdpcap(pcap):
                        print("here")
                        display_packet(pkt[1:], format="show", show_metadata=True)
            # Launch post-run tasks
        self.post_run()


def whadplay_main():
    app = WhadPlayApp()
    app.run()
