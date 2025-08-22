"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import sys
import logging
import time
import traceback
import string
from queue import Queue
from argparse import ArgumentParser

# Import every possible scapy layer for packet crafting
# pylint: disable-next=wildcard-import
from scapy.layers.all import *

# Import scapy helpers
from scapy.packet import Packet, Raw
from scapy.config import conf
from scapy.themes import BrightTheme

from whad.exceptions import UnsupportedDomain, UnsupportedCapability
from whad.cli.ui import warning, error, info, display_packet
from whad.cli.app import CommandLineApp, run_app
from whad.hub import ProtocolHub

# Import custom scapy layers required for packet crafting.
from whad.scapy.layers.rf4ce import *       # pylint: disable=wildcard-import,unused-wildcard-import
from whad.scapy.layers.phy import *         # pylint: disable=wildcard-import,unused-wildcard-import
from whad.scapy.layers.esb import *         # pylint: disable=wildcard-import,unused-wildcard-import
from whad.scapy.layers.unifying import *    # pylint: disable=wildcard-import,unused-wildcard-import
from whad.device.unix import UnixConnector
from whad.tools.utils import list_implemented_injectors, get_injector_parameters, \
    gen_option_name, build_configuration_from_args

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
    """winject main application class.
    """

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
            type=float,
            default='1.0',
            dest='delay',
            help="Delay between the transmission of two consecutive packets"
        )

        self.provided_count = 0
        self._input_queue = Queue()
        self._repeat_queue = Queue()

        # Load implemented injectors (introspection)
        self.environment = None

        # Build subparsers if stdin is not piped, when piped we will do
        # it in the pre_run() method.
        if not self.is_stdin_piped():
            self.subparsers = self.add_subparsers(
                required=True,
                dest="domain",
                parser_class=WhadDomainSubParser,
                help='Domain in use'
            )
            self.environment = list_implemented_injectors()
            self.build_subparsers(self.subparsers)
        else:
            self.subparsers = None

    def build_subparsers(self, subparsers):
        """
        Generate the subparsers argument according to the environment.
        """

        # Iterate over domain, and get the associated sniffer parameters
        for domain_name, domain in self.environment.items():
            domain["parameters"] = get_injector_parameters(
                domain["configuration_class"]
            )

            domain["subparser"] = subparsers.add_parser(
                domain_name,
                description=f"WHAD {domain_name.capitalize()} Injection tool"
            )

            # Iterate over every parameters, and add arguments to subparsers
            for (
                    parameter_name,
                    (parameter_type, parameter_default, parameter_base_class, parameter_help)
                ) in domain["parameters"].items():

                dest = parameter_name

                # If parameter is based on a dataclass, process a subparameter
                if parameter_base_class is not None:
                    _, parameter_name = parameter_name.split(".")

                parameter_name = gen_option_name(parameter_name)

                # Process parameter help and shortname
                if parameter_help is not None and "(" in parameter_help:
                    parameter_shortnames = [
                        f"-{i}" for i in
                        parameter_help.split("(")[1].replace(")","").split(",")
                    ]
                    parameter_help = parameter_help.split("(")[0]
                else:
                    parameter_shortnames = []

                # Process parameter type
                if parameter_type is not bool:
                    # If we got an int
                    if parameter_type is int:
                        # allow to provide hex arguments
                        # pylint: disable-next=unnecessary-lambda-assignment
                        parameter_type = lambda x: int(x,0)
                    # If we got a list, it is a list of string
                    if parameter_type is list:
                        parameter_default=[]
                        parameter_type=str
                        action = "append"
                    elif parameter_type is bytes:
                        parameter_type = bytes.fromhex
                        action = "store"
                    else:
                        action = "store"
                    # Add non-boolean argument to corresponding subparser
                    domain["subparser"].add_argument(
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
                    domain["subparser"].add_argument(
                        "--"+parameter_name,
                        *parameter_shortnames,
                        action='store_true',
                        dest=dest,
                        help=parameter_help
                    )

            domain["subparser"].add_argument(
                dest='packet',
                nargs="*",
                help='packet to inject'
            )

    def on_incoming_packet(self, packet: Packet):
        """Incoming packet callback method, adds packet to input queue.
        """
        self._input_queue.put(packet)

    def generate_packets(self):
        """Convert packets provided by the user through command-line into scapy
        packets to inject.
        """
        self.provided_count = 0
        if hasattr(self.args, "packet"):
            for p in self.args.packet:
                # Is it some hex
                if all(c in string.hexdigits for c in p):
                    if len(p) % 2 == 0:
                        try:
                            pkt = bytes.fromhex(p)
                            self._input_queue.put(pkt)
                            self.provided_count += 1
                        except Exception as err:
                            error(f"Failure during raw packet decoding: {p} -> {err}")
                    else:
                        error("Raw packets must be provided in valid hexadecimal form")
                else:
                    try:
                        # pylint: disable-next=eval-used
                        pkt = eval(p)
                        self._input_queue.put(pkt)
                        self.provided_count += 1
                    except SyntaxError:
                        error(f"Invalid syntax: `{p}`")
                    except Exception as err:
                        error(f"Failure during packet interpretation: {p} -> {err}")

    def pre_run(self):
        """Pre-run operations: rewrite arguments to allow skipping domain name
        when a pipe is configured.
        """

        try:
            try:
                index = sys.argv.index("--interface")
            except ValueError:
                index = sys.argv.index("-i")
        except ValueError:
            if "-h" in sys.argv or "--help" in sys.argv:
                self.print_help()
                sys.exit(1)
            error("You need to provide an interface.")
            sys.exit(1)

        start_argv = sys.argv[:index + 2]
        end_argv =  sys.argv[index + 2:]

        if len(sys.argv) == 1 or "-h" in start_argv or "--help" in start_argv:
            self.print_help()
            sys.exit(1)

        error_func = self.error
        if self.subparsers is None:
            self.error  = lambda m : None

        # Load implemented injectors *before* calling super().__init__()
        # drastically improves performances... and I have no clue why o_o
        if self.environment is None:
            self.environment = list_implemented_injectors()

        # Call CLI app pre-run: it will initialize our source interface
        super().pre_run()

        try:
            domain = self.args.domain
        except AttributeError:
            self.error("You have to provide a domain.")
            sys.exit(1)

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

            # We build subparsers.
            self.build_subparsers(self.subparsers)

            # And we inject the domain parameter retrieved from the parameters
            # given by the input tool through the Unix socket URI.
            if domain not in start_argv and domain not in end_argv:
                sys.argv = start_argv + [domain] + end_argv
            else:
                sys.argv = start_argv + end_argv

            # Parse winject arguments and propagate into the `self.args` namespace.
            for k, v in self.parse_args().__dict__.items():
                setattr(self.args, k, v)

        # If no color is not selected, configure scapy color theme
        if not self.args.nocolor:
            conf.color_theme = BrightTheme()

        # Generate packets if provided through commandline
        self.generate_packets()


    def is_input_alive(self) -> bool:
        """Determine if the input interface is providing packets to inject.

        :return: `True` if input interface is alive, `False` otherwise.
        :rtype: bool
        """
        return self.input_interface is not None and self.input_interface.opened

    def has_pending_packets(self) -> bool:
        """Determine if we still have some packets to inject.

        :return: `True` if we have pending packets to inject, `False` otherwise.
        :rtype: bool
        """
        return self.provided_count > 0 or not self._input_queue.empty()

    def run(self):
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
                        connector.unlock()

                    try:
                        injector.configuration = configuration
                    except Exception as e:
                        self.error("Error during configuration: " +repr(e))

                    # Main loop
                    while True:

                        # Inject while input interface is alive or we have pending packets
                        while self.is_input_alive() or self.has_pending_packets():
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

                        # Break if no packets to repeat
                        if not self.args.repeat:
                            break

                        # Move packets to repeat into input queue (pending packets).
                        while not self._repeat_queue.empty():
                            self._input_queue.put(self._repeat_queue.get())
                            self.provided_count += 1
                else:
                    self.error("You need to specify a domain.")
            else:
                self.error("You need to specify an interface with option --interface.")

        except UnsupportedDomain:
            self.error(f"WHAD device doesn\'t support selected domain ({self.args.domain})")

        except UnsupportedCapability as unsupported_capability:
            self.error((f"WHAD device doesn't support selected capability "
                        f"({unsupported_capability.capability})"))

        except KeyboardInterrupt:
            self.warning("injector stopped (CTRL-C)")
            injector.stop()
            injector.close()
            sys.exit(1)


def winject_main():
    """Launcher for winject CLI application.
    """
    app = WhadInjectApp()
    run_app(app)
