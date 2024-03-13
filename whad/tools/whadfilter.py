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

from scapy.config import conf
from scapy.all import BrightTheme, Packet

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
            # If no color is not selected, configure scapy color theme
            if not self.args.nocolor:
                conf.color_theme = BrightTheme()

            if self.args.pattern is not None:
            # We need to have an interface specified
                if self.input_interface is not None:
                    # Make sure we are placed between two piped tools
                    if self.is_stdin_piped():
                        # Start packet processing
                        environment = list_implemented_sniffers()
                        for argname in vars(self.args):
                            serialized_value = getattr(self.args, argname)
                            if argname != "pattern" and isinstance(serialized_value, str) and  ":" in serialized_value:
                                argtype, argvalue = serialized_value.split(":", 1)
                                if argtype == "NoneType" and argvalue == "None":
                                    setattr(self.args, argname, None)
                                elif argtype == "str":
                                    print(argtype, argname, argvalue)
                                    setattr(self.args, argname, argvalue)
                                else:
                                    try:
                                        setattr(self.args, argname, eval(argvalue))
                                    except (SyntaxError, NameError):
                                        setattr(self.args, argname, argvalue)

                        #print(self.args)

                        for domain_name in environment:
                            environment[self.args.domain]["parameters"] = get_sniffer_parameters(
                                environment[self.args.domain]["configuration_class"]
                            )

                        configuration = build_configuration_from_args(environment, self.args)
                        self.create_proxy(configuration)

                        #self.proxy.connector.stop()
                        #self.proxy.connector.start()

                        for p in self.proxy.connector.sniff():
                            try:
                                success = eval("lambda p:"+self.args.pattern)(p)
                            except AttributeError:
                                success = False
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

    def create_proxy(self, configuration):
        """Start a new Unix socket server and forward all messages
        """
        try:
            module = import_module("whad.{}.connector.sniffer".format(self.args.domain))

            class ProxySniffer(UnixSocketConnector, module.Sniffer):
                pass
            # Create our proxy
            print(self.args.__dict__)
            self.proxy = UnixSocketProxy(self.input_interface, {"configuration":configuration}, ProxySniffer)
            self.proxy.start()
            self.proxy.join()
        except ModuleNotFoundError:
            self.proxy = None

def whadfilter_main():
    app = WhadFilterApp()
    app.run()
