"""WHAD general sniffing tool

This utility implements a generic sniffer module, automatically adapted to every domain.
"""
import logging
from argparse import ArgumentParser
from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import CommandLineApp, ApplicationError
from whad.cli.ui import error, warning, success, info, display_event, display_packet
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, UnsupportedDomain, UnsupportedCapability
from whad.common.monitors import WiresharkMonitor, PcapWriterMonitor
from whad.device.unix import UnixSocketServerDevice, UnixConnector
from whad.tools.utils import list_implemented_sniffers, get_sniffer_parameters, build_configuration_from_args
from whad.device import Bridge
from scapy.config import conf
from html import escape
from hexdump import hexdump
from scapy.all import BrightTheme, Packet
from time import sleep

import whad
import sys
import os, stat

logger = logging.getLogger(__name__)


class WhadSniffOutputPipe(Bridge):
    """Whad sniff output pipe

    When wsniff is chained with another whad tool, it spawns a device
    based on the specified profile using the specified WHAD adapter and forward
    it to the chained tool. The chained tool will then forward packets back and forth.
    """
    def __init__(self, input_connector, output_connector):
        super().__init__(input_connector, output_connector)


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


class WhadSniffApp(CommandLineApp):

    def __init__(self, interface=True, description='WHAD generic sniffing tool', pcap_argument=False):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description=description,
            interface=interface,
            commands=False
        )

        self.add_argument(
            '--hide_metadata',
            dest='metadata',
            action="store_false",
            help='Hide packets metadata'
        )
        self.add_argument(
            '--format',
            dest='format',
            action="store",
            default='repr',
            choices=['repr', 'show', 'raw', 'hexdump'],
            help='Indicate format to display packet'
        )

        self.add_argument(
            '-o',
            '--output',
            dest='output',
            default=None,
            type=str,
            help='Output PCAP file'
        )

        self.add_argument(
            '-w',
            '--wireshark',
            dest='wireshark',
            action='store_true',
            help='Enable wireshark monitoring'
        )

        if pcap_argument:
            self.add_argument(
                dest='pcap',
                help='PCAP file'
            )


        subparsers = self.add_subparsers(
            required=True,
            dest="domain",
            parser_class=WhadDomainSubParser,
            help='Domain in use'
        )

        self.build_subparsers(subparsers)



    def pre_run(self):
        """Pre-run operations: configure scapy theme.
        """
        super().pre_run()

        # If no color is not selected, configure scapy color theme
        if not self.args.nocolor:
            conf.color_theme = BrightTheme()

    def run(self):
        monitors = []
        sniffer = None
        # Launch pre-run tasks
        self.pre_run()

        try:

            # We need to have an interface specified
            if self.interface is not None:
                # We need to have a domain specified
                if self.args.domain is not None:
                    # Parse the arguments to populate a sniffer configuration
                    configuration = build_configuration_from_args(self.environment, self.args)

                    # Generate a sniffer based on the selected domain
                    sniffer = self.environment[self.args.domain]["sniffer_class"](self.interface)

                    # Add an event listener to display incoming events
                    sniffer.add_event_listener(display_event)
                    try:
                        sniffer.configuration = configuration
                    except Exception as e:
                        self.error("Error during configuration: " +repr(e))
                        raise KeyboardInterrupt
                    # If output parameter is selected, add a PCAP Writer monitor
                    if self.args.output is not None:
                        monitor_pcap = PcapWriterMonitor(self.args.output)
                        monitor_pcap.attach(sniffer)
                        monitor_pcap.start()
                        monitors.append(monitor_pcap)

                    # If wireshark parameter is selected, add a WiresharkMonitor
                    if self.args.wireshark:
                        monitor_wireshark = WiresharkMonitor()
                        monitor_wireshark.attach(sniffer)
                        monitor_wireshark.start()
                        monitors.append(monitor_wireshark)



                    sniffer.domain = self.args.domain
                    if self.is_stdout_piped():
                        # Create output proxy
                        #proxy = UnixSocketProxy(self.interface, params={"domain":self.args.domain})

                        # Create our unix socket server
                        unix_server = UnixConnector(UnixSocketServerDevice(parameters={
                            'format': self.args.format,
                            'metadata':self.args.metadata,
                            'domain': self.args.domain
                        }))
                        # Create our packet bridge
                        # logger.info("[ble-spawn] Starting our output pipe")
                        output_pipe = WhadSniffOutputPipe(sniffer, unix_server)
                        # Start the sniffer
                        sniffer.start()
                        # Loop until the user hits CTL-C
                        while True:
                            sleep(1)
                    else:
                        # Start the sniffer
                        sniffer.start()
                        # Iterates over the packet stream and display packets
                        for pkt in sniffer.sniff():
                            display_packet(
                                pkt,
                                show_metadata = self.args.metadata,
                                format = self.args.format
                            )


                else:
                    self.error("You need to specify a domain.")
            else:
                self.error('You need to specify an interface with option --interface.')

        except UnsupportedDomain as unsupported_domain:
            self.error('WHAD device doesn\'t support selected domain ({})'.format(self.args.domain))

        except UnsupportedCapability as unsupported_capability:
            self.error('WHAD device doesn\'t support selected capability ({})'.format(unsupported_capability.capability))

        except KeyboardInterrupt as keybd:
            self.warning('sniffer stopped (CTRL-C)')
            sniffer.stop()
            sniffer.close()
            for monitor in monitors:
                monitor.close()
            exit()

    def build_subparsers(self, subparsers):
        """
        Generate the subparsers argument according to the environment.
        """
        # List every domain implementing a sniffer
        self.environment = list_implemented_sniffers()

        # Iterate over domain, and get the associated sniffer parameters
        for domain_name in self.environment:
            self.environment[domain_name]["parameters"] = get_sniffer_parameters(
                self.environment[domain_name]["configuration_class"]
            )


            self.environment[domain_name]["subparser"] = subparsers.add_parser(
                domain_name,
                description="WHAD {} Sniffing tool".format(domain_name.capitalize())
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

def wsniff_main():
    """Main WHAD Sniffer routine.
    """
    try:
        app = WhadSniffApp()
        app.run()
    except ApplicationError as err:
        err.show()
