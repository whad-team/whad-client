"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import os
import logging
import time
import traceback
import string
from argparse import ArgumentParser, Namespace

from whad.exceptions import RequiredImplementation, UnsupportedDomain, UnsupportedCapability
from whad.cli.ui import wait, warning, error, success, info, display_packet
from whad.cli.app import CommandLineApp, run_app
from whad.device import Bridge, ProtocolHub
from scapy.all import *
from whad.scapy.layers.rf4ce import *
from whad.scapy.layers.phy import *
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from whad.device.unix import UnixConnector, UnixSocketServerDevice
from whad.tools.utils import list_implemented_injectors, get_injector_parameters, gen_option_name, build_configuration_from_args
#from whad.unifying import Injector
from whad.phy.connector.injector import Injector

from queue import Queue
logger = logging.getLogger(__name__)



class WhadDomainSubParser(ArgumentParser):
    """
    Implements a Whad Domain subparser.
    """
    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        warning(message)

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        error(message)
        #exit(1)

class WhadInjectApp(CommandLineApp):
    connector = None
    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD generic injection tool',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

        self.add_argument(
            '-r',
            '--repeat',
            dest='repeat',
            action='store_true',
            default=False,
            help="Repeat the transmission of packets"
        )


        self.add_argument(
            '-d',
            '--delay',
            dest='delay',
            default=0,
            help="Delay between the transmission of two consecutive packets"
        )

        self._input_queue = Queue()
        self._repeat_queue = Queue()

        # Don't build yet if piped
        if not self.is_stdin_piped():
            self.subparsers = self.add_subparsers(
                required=True,
                dest="domain",
                parser_class=WhadDomainSubParser,
                help='Domain in use'
            )

            self.build_subparsers(self.subparsers)
        else:
            self.subparsers = None

    def build_subparsers(self, subparsers):
        """
        Generate the subparsers argument according to the environment.
        """
        # List every domain implementing an injector
        self.environment = list_implemented_injectors()

        # Iterate over domain, and get the associated sniffer parameters
        for domain_name in self.environment:
            self.environment[domain_name]["parameters"] = get_injector_parameters(
                self.environment[domain_name]["configuration_class"]
            )


            self.environment[domain_name]["subparser"] = subparsers.add_parser(
                domain_name,
                description="WHAD {} Injection tool".format(domain_name.capitalize())
            )

            # Iterate over every parameters, and add arguments to subparsers
            for (
                    parameter_name,
                    (parameter_type, parameter_default, parameter_base_class, parameter_help)
                ) in self.environment[domain_name]["parameters"].items():

                dest = parameter_name

                # If parameter is based on a dataclass, process a subparameter
                if parameter_base_class is not None:
                    parameter_base, parameter_name = parameter_name.split(".")

                parameter_name = gen_option_name(parameter_name)

                # Process parameter help and shortname
                if parameter_help is not None and "(" in parameter_help:
                    parameter_shortnames = [
                        "-{}".format(i) for i in
                        parameter_help.split("(")[1].replace(")","").split(",")
                    ]
                    parameter_help = parameter_help.split("(")[0]
                else:
                    parameter_shortnames = []


                # Process parameter type
                if parameter_type != bool:
                    choices = []
                    # If we got an int
                    if parameter_type == int:
                        # allow to provide hex arguments
                        parameter_type = lambda x: int(x,0)
                    # If we got a list, it is a list of string
                    if parameter_type == list:
                        parameter_default=[]
                        parameter_type=str
                        action = "append"
                    elif parameter_type == bytes:
                        parameter_type = bytes.fromhex
                        action = "store"
                    else:
                        action = "store"
                    # Add non-boolean argument to corresponding subparser
                    self.environment[domain_name]["subparser"].add_argument(
                        "--"+parameter_name,
                        *parameter_shortnames,
                        default=parameter_default,
                        action=action,
                        type=parameter_type,
                        dest=dest,
                        help=parameter_help
                    )
                else:
                    # Add boolean argument to corresponding subparser
                    self.environment[domain_name]["subparser"].add_argument(
                        "--"+parameter_name,
                        *parameter_shortnames,
                        action='store_true',
                        dest=dest,
                        help=parameter_help
                    )

            self.environment[domain_name]["subparser"].add_argument(
                dest='packet',
                nargs="*",
                help='packet to inject'
            )

    def on_incoming_packet(self, packet):
        self._input_queue.put(packet)

    def generate_packets(self):
        self.provided_count = 0
        if hasattr(self.args, "packet"):
            for p in self.args.packet:
                try:
                    pkt = eval(p)
                    self._input_queue.put(pkt)
                    self.provided_count += 1
                except Exception as e:
                    # If hexadecimal only, try to interpret as bytes
                    if all(c in string.hexdigits for c in p):
                        try:
                            pkt = bytes.fromhex(p)
                            self._input_queue.put(pkt)
                            self.provided_count += 1
                        except Exception as e:
                            error("Failure during packet interpretation: " + str(p) + " -> " + str(e))
                    else:
                        error("Failure during packet interpretation: " + str(p) + " -> " + str(e))

    def pre_run(self):
        """Pre-run operations: rewrite arguments to allow skipping domain name when a pipe is configured.
        """

        try:
            try:
                index = sys.argv.index("--interface")
            except ValueError:
                index = sys.argv.index("-i")
        except ValueError:
            if "-h" in sys.argv or "--help" in sys.argv:
                self.print_help()
                exit(1)
            error("You need to provide an interface.")
            exit(1)

        start_argv = sys.argv[:index + 2]
        end_argv =  sys.argv[index + 2:]

        if len(sys.argv) == 1 or "-h" in start_argv or "--help" in start_argv:
            self.print_help()
            exit(1)


        error_func = self.error
        if self.subparsers is None:
            self.error  = lambda m : None
        super().pre_run()
        try:
            domain = self.args.domain
        except AttributeError:
            self.error("You have to provide a domain.")
            exit(1)

        if self.subparsers is None:
            self.error  = error_func

        if self.subparsers is None:
            sys.argv = start_argv

            self.subparsers = self.add_subparsers(
                required=True,
                dest="domain",
                parser_class=WhadDomainSubParser,
                help='Domain in use'
            )

            self.build_subparsers(self.subparsers)

            if domain not in start_argv and domain not in end_argv:
                sys.argv = start_argv + [domain] + end_argv
            else:
                sys.argv = start_argv + end_argv

            for k, v in self.parse_args().__dict__.items():
                setattr(self.args, k, v)

        # If no color is not selected, configure scapy color theme
        if not self.args.nocolor:
            conf.color_theme = BrightTheme()

        self.generate_packets()

    def run(self):
        monitors = []
        injector = None
        # Launch pre-run tasks
        self.pre_run()

        try:
            # We need to have an interface specified
            if self.interface is not None:
                # We need to have a domain specified
                if self.args.domain is not None:
                    # Parse the arguments to populate a injector configuration
                    configuration = build_configuration_from_args(self.environment, self.args)

                    # Generate an injector based on the selected domain
                    injector = self.environment[self.args.domain]["injector_class"](self.interface)


                    if self.is_piped_interface():

                        connector = UnixConnector(self.input_interface)

                        connector.domain = self.args.domain
                        hub = ProtocolHub(2)
                        connector.format = hub.get(self.args.domain).format
                        connector.on_packet = self.on_incoming_packet

                    try:
                        injector.configuration = configuration
                    except Exception as e:
                        self.error("Error during configuration: " +repr(e))

                    while True:
                        while (self.input_interface is not None and self.input_interface.opened) or self.provided_count > 0 or not self._input_queue.empty():
                            if not self._input_queue.empty():
                                packet = self._input_queue.get()
                                try:
                                    if isinstance(packet, bytes):
                                        packet = injector.format(packet)[0]
                                        # patch for BLE only
                                        if BTLE_RF in packet:
                                            packet = packet[BTLE]
                                    info("Transmitting: ")
                                    display_packet(packet)
                                    injector.inject(packet)
                                    if float(self.args.delay) > 0:
                                        time.sleep(float(self.args.delay))
                                    if self.args.repeat:
                                        self._repeat_queue.put(packet)
                                except Exception as e:
                                    self.error("Error during injection: " + repr(e))
                                    traceback.print_exc()
                                self.provided_count-=1

                        if not self.args.repeat:
                            break

                        while not self._repeat_queue.empty():
                            self._input_queue.put(self._repeat_queue.get())
                            self.provided_count += 1
                else:
                    self.error("You need to specify a domain.")
            else:
                self.error('You need to specify an interface with option --interface.')

        except UnsupportedDomain as unsupported_domain:
            self.error('WHAD device doesn\'t support selected domain ({})'.format(self.args.domain))

        except UnsupportedCapability as unsupported_capability:
            self.error('WHAD device doesn\'t support selected capability ({})'.format(unsupported_capability.capability))

        except KeyboardInterrupt as keybd:
            self.warning('injector stopped (CTRL-C)')
            injector.stop()
            injector.close()
            exit()


def winject_main():
    app = WhadInjectApp()
    run_app(app)
