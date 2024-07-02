"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineDevicePipe, CommandLineApp, ApplicationError
from scapy.all import *
from whad.device.unix import UnixSocketProxy, UnixSocketCallbacksConnector
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet
from whad.common.monitors import WiresharkMonitor
import logging
import time
import sys
from pkgutil import iter_modules
from importlib import import_module
import whad
from scapy.config import conf
logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

def get_translator(protocol):
    """Get a translator according to a specific domain.
    """
    translator = None
    # Iterate over modules
    for _, candidate_protocol,_ in iter_modules(whad.__path__):
        # If the module contains a sniffer connector,
        # store the associated translator in translator variable
        try:
            module = import_module("whad.{}.connector.sniffer".format(candidate_protocol))
            if candidate_protocol == protocol:
                translator = module.Sniffer.translator
                break
        except ModuleNotFoundError:
            pass
    # return the environment dictionary
    return translator

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
                self.connector.translator = get_translator(self.args.domain)(self.connector.hub)
                self.connector.format = self.connector.translator.format
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
                monitor.close()
            self.post_run()


def wshark_main():
    try:
        app = WhadWiresharkApp()
        app.run()
    except ApplicationError as err:
        err.show()