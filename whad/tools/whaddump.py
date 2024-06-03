"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time
from whad.tools.whadsniff import display_packet
from whad.ble.connector import BLE
from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineDevicePipe, CommandLineApp
from scapy.all import *
from whad.common.ipc import IPCPacket
import sys
from importlib import import_module
from whad.device.unix import UnixSocketProxy, UnixSocketConnector
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
logger = logging.getLogger(__name__)

class WhadDumpApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD dump tool',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            '-p',
            '--pcap',
            dest="pcap",
            help='PCAP file'
        )

    def show(self, p):
        print(repr(p))
    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            class UnixSocketModifyConnector(UnixSocketConnector):
                def send_message(self, msg):
                    # up
                    sys.stderr.write("<< " + repr(msg) + "\n")
                    sys.stderr.flush()
                    return super().send_message(msg)

                def on_any_msg(self, msg):
                    # down
                    if hasattr(msg, "fw_author"):
                        msg.fw_author = b"Roro"
                    sys.stderr.write(">> " + repr(msg) + "\n")
                    m = import_module("whad." + str(self.get_parameter("domain"))+".connector.translator")
                    sys.stderr.write(">> " + repr(m) + "\n")
                    sys.stderr.flush()
                    return super().on_any_msg(msg)


            if self.is_piped_interface():

                if self.args.pcap:
                    c = BLE(self.input_interface)

                    while True:
                        c.stop()
                        time.sleep(1)
                        c.start()
                        time.sleep(1)

                else:
                    failed = False
                    for param in ["domain"]:
                        if not hasattr(self.args, param):
                            self.error("No domain provided.")
                            failed = True
                            break

                    if not failed:
                        proxy = UnixSocketProxy(
                            self.input_interface,
                            params=self.args.__dict__,
                            connector=UnixSocketModifyConnector
                        )
                        proxy.start()
                        proxy.join()

                    while True:
                        time.sleep(1)
            else:
                print(":()")

        except KeyboardInterrupt:
            '''
            if pcap is not None:
                pcap.stop()
                pcap.close()
            '''
        # Launch post-run tasks
        self.post_run()


def whaddump_main():
    app = WhadDumpApp()
    app.run()
