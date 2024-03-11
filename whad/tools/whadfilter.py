"""Bluetooth Low Energy wireshark monitoring tool

This utility must be chained between two command-line tools to
monitor BLE packets going back and forth.
"""
import logging
import struct
from time import sleep
from threading import Thread
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_DATA, BTLE_ADV_IND, \
    BTLE_ADV_NONCONN_IND, BTLE_ADV_DIRECT_IND, BTLE_ADV_SCAN_IND, BTLE_SCAN_RSP, \
    BTLE_RF, BTLE_CTRL

from whad.cli.app import CommandLineApp
from whad.common.monitors import WiresharkMonitor
from whad.device.unix import UnixSocketProxy, UnixSocketConnector
from whad.tools.whadsniff import get_sniffer_parameters, build_configuration_from_args,\
    list_implemented_sniffers, display_packet
from importlib import import_module
logger = logging.getLogger(__name__)

class WhadFilterApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD filter utility',
            interface=True,
            commands=False
        )
        self.add_argument(
            'pattern',
            default=None,
            type=str,
            help='Pattern to match'
        )
        self.proxy = None


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            if self.args.pattern is not None:
            # We need to have an interface specified
                if self.input_interface is not None:
                    # Make sure we are placed between two piped tools
                    if self.is_stdin_piped():
                        self.create_proxy()
                        # Start packet processing
                        environment = list_implemented_sniffers()

                        for domain_name in environment:
                            environment[self.args.domain]["parameters"] = get_sniffer_parameters(
                                environment[self.args.domain]["configuration_class"]
                            )

                        configuration = build_configuration_from_args(environment, self.args)

                        self.proxy.connector.configuration = configuration

                        for p in self.proxy.connector.sniff():
                            success = eval("lambda p:"+self.args.pattern)(p)
                            if success is not None and success:
                                display_packet(p, show_metadata=self.args.metadata, format=self.args.format)
                else:
                    self.error('Tool must be piped to another WHAD tool.')
            else:
                self.error('You must provide a pattern.'+ str(self.proxy))
                exit()
        except KeyboardInterrupt as keybd:
            self.warning('whadfilter stopped (CTL-C)')
            if self.proxy is not None:
                self.proxy.stop()

        # Launch post-run tasks
        self.post_run()

    def create_proxy(self):
        """Start a new Unix socket server and forward all messages
        """
        try:
            module = import_module("whad.{}.connector.sniffer".format(self.args.domain))

            class ProxySniffer(UnixSocketConnector, module.Sniffer):
                pass
            # Create our proxy
            self.proxy = UnixSocketProxy(self.input_interface, self.args.__dict__, ProxySniffer)
            self.proxy.start()
            self.proxy.join()
        except ModuleNotFoundError:
            self.proxy = None

def whadfilter_main():
    app = WhadFilterApp()
    app.run()
