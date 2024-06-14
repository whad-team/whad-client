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
from whad.common.monitors import WiresharkMonitor
import logging
import time
import sys

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadWiresharkApp(CommandLineApp):
    connector = None
    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD wireshark',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

    def on_rx_packet(self, pkt):
        if self.connector is not None:
            self.connector.monitor_packet_rx(pkt)
        return pkt

    def on_tx_packet(self, pkt):
        if self.connector is not None:
            self.connector.monitor_packet_tx(pkt)
        return pkt

    def run(self):
        # Launch pre-run tasks
        monitor = None
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
                print(parameters)
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

                self.connector = proxy.connector
                self.connector.domain = self.args.domain
                monitor = WiresharkMonitor()
                monitor.attach(self.connector)

                monitor.start()
                if self.is_stdout_piped():
                    proxy.start()
                    proxy.join()

                while True:
                    time.sleep(1)

        except KeyboardInterrupt:
            # Launch post-run tasks
            if monitor is not None:
                monitor.stop()
            self.post_run()


def wshark_main():
    app = WhadWiresharkApp()
    app.run()
