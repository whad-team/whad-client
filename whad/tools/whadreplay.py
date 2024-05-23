"""Whad general replay tool

This tool implements a generic replay feature that can be used with compatible
domains. It takes a PCAP file in input, read packets and replay them through
a compatible WHAD device.
"""
import logging
from argparse import ArgumentParser
from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import CommandLineSink
from importlib import import_module
from whad.common.replay import ReplayRole
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, UnsupportedDomain, UnsupportedCapability
from whad.common.monitors import WiresharkMonitor, PcapWriterMonitor, WhadMonitor
from whad.common.pcap import PCAPReader
from dataclasses import fields, is_dataclass
from pkgutil import iter_modules
from inspect import getdoc
from scapy.config import conf
from html import escape
from hexdump import hexdump
from scapy.all import BrightTheme, Packet
import whad

from time import sleep

logger = logging.getLogger(__name__)

#logging.basicConfig(level=logging.DEBUG)

def list_implemented_replays():
    """Build a dictionnary of replays connector and configuration, by domain.
    """
    environment = {}

    # Iterate over modules
    for _, candidate_protocol,_ in iter_modules(whad.__path__):
        # If the module contains a replay connector and configuration,
        # store the associated classes in the environment dictionary
        try:
            module = import_module("whad.{}.connector.replay".format(candidate_protocol))
            environment[candidate_protocol] = {
                "replay_class":module.Replay,
                "configuration_class":module.ReplayConfiguration
            }
        except ModuleNotFoundError:
            pass
    # return the environment dictionary
    return environment

def get_replay_parameters(configuration_class):
    """
    Extract all parameters from a replay configuration class, with their name and associated documentation.

    :param configuration_class: replay configuration class
    :return: dict containing parameters for a given configuration class
    """
    parameters = {}
    # Extract documentation of every field in the configuration class
    fields_configuration_documentation = {
        i.replace(":param ","").split(":")[0] : i.replace(":param ","").split(":")[1]
        for i in getdoc(configuration_class).split("\n")
        if i.startswith(":param ")
    }

    # Iterate over the fields of the configuration class
    for field in fields(configuration_class):

        # If the field is a dataclass, process subfields
        if is_dataclass(field.type):
            # Extract documentation of every subfields
            subfields_configuration_documentation = {
                i.replace(":param ","").split(":")[0] : i.replace(":param ","").split(":")[1]
                for i in getdoc(field.type).split("\n")
                if i.startswith(":param ")
            }

            # Populate parameters dict with subfields configuration
            for subfield in fields(field.type):
                parameters["{}.{}".format(field.name,subfield.name)] = (
                    subfield.type,
                    subfield.default,
                    field.type,
                    (
                        subfields_configuration_documentation[subfield.name]
                        if subfield.name in subfields_configuration_documentation
                        else None
                    )
                )
        # if the field is not a dataclass, process it
        else:
            # Populate parameters dict with field configuration
            parameters[field.name] = (
                field.type,
                field.default,
                None,
                (
                    fields_configuration_documentation[field.name]
                    if field.name in fields_configuration_documentation
                    else None
                )
            )
    return parameters


def build_configuration_from_args(environment, args):
    """
    Build replay configuration from arguments provided via argparse.

    :param environment: environment
    :type environment: dict
    :param args: arguments provided by user
    :type args: :class:`argparse.ArgumentParser`
    """
    configuration = environment[args.domain]["configuration_class"]()
    subfields = {}
    for parameter in environment[args.domain]["parameters"]:
        base_class = None

        base_class = environment[args.domain]["parameters"][parameter][2]

        if base_class is None:
            setattr(configuration,parameter,getattr(args,parameter))
        else:
            main, sub = parameter.split(".")
            if main not in subfields:
                subfields[main] = base_class()
            setattr(subfields[main], sub, getattr(args, parameter))


    for subfield in subfields:
        create = False
        for item in fields(subfields[subfield]):
            if getattr(subfields[subfield], item.name) is not None:
                create = True
                break
        if create:
            setattr(configuration, subfield, subfields[subfield])
        else:
            setattr(configuration, subfield, None)
    return configuration

class WhadDomainSubParser(ArgumentParser):
    """
    Implements a Whad Domain subparser.
    """
    def warning(self, message):
        """Display a warning message in orange (if color is enabled)
        """
        print_formatted_text(
            HTML('<aaa fg="#e97f11">/!\\ <b>%s</b></aaa>' % message)
        )

    def error(self, message):
        """Display an error message in red (if color is enabled)
        """
        print_formatted_text(
            HTML('<ansired>[!] <b>%s</b></ansired>' % message)
        )

class WhadReplayApp(CommandLineApp):

    class WhadReplayMonitor(WhadMonitor):
        def __init__(self, replay_app):
            super().__init__()
            self.__replay_app = replay_app

        def process_packet(self, packet):
            self.__replay_app.display(packet)

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD generic replay tool',
            interface=True,
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
            '-p',
            '--pcapfile',
            dest='pcapfile',
            default=None,
            type=str,
            help='Input PCAP file'
        )

        self.add_argument(
            '-e',
            '--emitter',
            action='store_true',
            dest='emitter',
            default=False,
            help='Act as an emitter'
        )

        self.add_argument(
            '-r',
            '--receiver',
            action='store_true',
            dest='receiver',
            default=False,
            help='Act as a receiver'
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

        self.add_argument(
            '-s',
            '--start',
            dest='start_pos',
            default=0,
            type=int,
            help='Specify the start position in the PCAP file'
        )

        self.add_argument(
            '-z',
            '--end_pos',
            dest='stop_pos',
            default=-1,
            type=int,
            help='Specify the stop position in the PCAP file'
        )

        self.add_argument(
            '-x',
            '--exclude',
            dest='exclude',
            action='append',
            help='Ignore a specific packet',
            type=int,
            default=[]
        )

        self.add_argument(
            '-d',
            '--delay',
            dest='offset',
            default=100,
            type=int,
            help='Additional delay between packets, in milliseconds'
        )

        subparsers = self.add_subparsers(
            required=True,
            dest="domain",
            parser_class=WhadDomainSubParser,
            help='Domain in use'
        )

        self.build_subparsers(subparsers)


    def build_monitor(self) -> WhadReplayMonitor:
        """Create our own wrapper to monitor packets in the terminal.
        """
        return WhadReplayApp.WhadReplayMonitor(self)


    def display(self, pkt):
        """
        Display an packet according to the selected format.

        Four main types of formats can be used:
            * repr: scapy packet repr method (default)
            * show: scapy show method, "field" representation
            * hexdump: hexdump representation of the packet content
            * raw: raw received bytes

        :param  pkt:        Received Signal Strength Indicator
        :type   pkt:        :class:`scapy.packet.packet`
        """
        if isinstance(pkt, Packet):

            metadata = ""
            if hasattr(pkt, "metadata") and self.args.metadata:
                metadata = repr(pkt.metadata)

            # Process scapy show method format
            if self.args.format == "show":
                print_formatted_text(
                    HTML(
                        '<b><ansipurple>%s</ansipurple></b>' % (
                            metadata
                        )
                    )
                )
                pkt.show()

                if hasattr(pkt, "decrypted"):
                    print_formatted_text(
                        HTML(
                            "<ansicyan>[i] Decrypted payload:</ansicyan>"
                        )
                    )
                    pkt.decrypted.show()

            # Process raw bytes format
            elif self.args.format == "raw":
                print_formatted_text(
                    HTML(
                        '<b><ansipurple>%s</ansipurple></b> %s' % (
                            metadata,
                            bytes(pkt).hex()
                        )
                    )
                )

                if hasattr(pkt, "decrypted"):
                    print_formatted_text(
                        HTML(
                            "<ansicyan>[i] Decrypted payload:</ansicyan> %s" %
                            bytes(pkt.decrypted).hex()
                        )
                    )

            # Process hexdump format
            elif self.args.format == "hexdump":
                print_formatted_text(
                    HTML(
                        '<b><ansipurple>%s</ansipurple></b>' % (
                            metadata
                        )
                    )
                )
                print_formatted_text(
                    HTML("<i>%s</i>" %
                        escape(hexdump(bytes(pkt), result="return"))
                    )
                )
                if hasattr(pkt, "decrypted"):
                    print_formatted_text(
                        HTML(
                            "<ansicyan>[i] Decrypted payload:</ansicyan>"
                        )
                    )
                    print_formatted_text(
                            HTML("<i>%s</i>" %
                                escape(hexdump(bytes(pkt.decrypted), result="return")
                            )
                        )
                    )
            # Process scapy repr format
            else:
                print_formatted_text(
                    HTML(
                        '<b><ansipurple>%s</ansipurple></b>' % (
                            metadata
                        )
                    )
                )
                print(repr(pkt))
                if hasattr(pkt, "decrypted"):
                    print_formatted_text(
                        HTML("<ansicyan>[i] Decrypted payload:</ansicyan>")
                    )
                    print(repr(pkt.decrypted))
            print()
        # If it is not a packet, use repr method
        else:
            print(repr(pkt))

    def display_event(self, event):
        """Display an event generated from a replay.
        """
        print_formatted_text(
            HTML(
                "<ansicyan>[i] event: <b>%s</b></ansicyan> %s" % (
                    event.name,
                    "("+event.message +")" if event.message is not None else ""
                )
            )
        )

    def pre_run(self):
        """Pre-run operations: configure scapy theme.
        """
        super().pre_run()
        # If no color is not selected, configure scapy color theme
        if not self.args.nocolor:
            conf.color_theme = BrightTheme()

    def run(self):
        monitors = []
        replay = None
        # Launch pre-run tasks
        self.pre_run()
        try:
            # We need to have at least one role selected
            role = 0
            if self.args.emitter:
                role |= ReplayRole.EMITTER
            if self.args.receiver:
                role |= ReplayRole.RECEIVER

            # If role==0, no role selected
            if role == 0:
                self.error("You need to specify a role with --emitter and/or --receiver.")
                return

            # We also must have an input pcap file selected
            if self.args.pcapfile is None:
                self.error("No input PCAP file specified !")
                return

            # We need to have an interface specified
            if self.interface is not None:
                # We need to have a domain specified
                if self.args.domain is not None:
                    # Parse the arguments to populate a replay configuration
                    configuration = build_configuration_from_args(self.environment, self.args)

                    # Make sure we have a target set
                    if configuration.target is not None:
                        # Generate a replay based on the selected domain
                        replay = self.environment[self.args.domain]["replay_class"](
                            self.interface,
                            self.args.pcapfile,
                            role=role
                        )

                        # Add our own monitor for CLI reporting
                        cli_monitor = self.build_monitor()
                        cli_monitor.attach(replay)
                        cli_monitor.start()
                        monitors.append(cli_monitor)

                        # If output parameter is selected, add a PCAP Writer monitor
                        if self.args.output is not None:
                            monitor_pcap = PcapWriterMonitor(self.args.output)
                            monitor_pcap.attach(replay)
                            monitor_pcap.start()
                            monitors.append(monitor_pcap)

                        # If wireshark parameter is selected, add a WiresharkMonitor
                        if self.args.wireshark:
                            monitor_wireshark = WiresharkMonitor()
                            monitor_wireshark.attach(replay)
                            monitor_wireshark.start()
                            monitors.append(monitor_wireshark)

                        # Prepare the replay instance
                        if replay.prepare(configuration):
                            # Now we can feed our replay instance with packets
                            if self.args.stop_pos >= 0:
                                count = self.args.stop_pos - self.args.start_pos + 1
                            else:
                                count = None

                            # PCAPReader will send back packets in a timely manner, according to PCAP timestamps.
                            reader = PCAPReader(self.args.pcapfile)
                            for packet in reader.packets(start=self.args.start_pos, count=count,
                                                        offset=self.args.offset/1000., exclude=self.args.exclude):
                                replay.send_packet(packet)

                        # Stop our replay instance
                        replay.stop()
                        replay.close()

                        # Close all monitors
                        for monitor in monitors:
                            monitor.close()
                    else:
                        self.error("You must specify a target BD address with option --target.")
                else:
                    self.error("You need to specify a domain.")
            else:
                self.error('You need to specify an interface with option --interface.')


        except UnsupportedDomain as unsupported_domain:
            self.error('WHAD device doesn\'t support selected domain ({})'.format(self.args.domain))

        except UnsupportedCapability as unsupported_capability:
            self.error('WHAD device doesn\'t support selected capability ({})'.format(unsupported_capability.capability))

        except KeyboardInterrupt as keybd:
            self.warning('replay stopped (CTRL-C)')
            replay.stop()
            replay.close()
            for monitor in monitors:
                monitor.close()

    def build_subparsers(self, subparsers):
        """
        Generate the subparsers argument according to the environment.
        """

        # List every domain implementing a replay
        self.environment = list_implemented_replays()

        # Iterate over domain, and get the associated replay parameters
        for domain_name in self.environment:
            self.environment[domain_name]["parameters"] = get_replay_parameters(
                self.environment[domain_name]["configuration_class"]
            )


            self.environment[domain_name]["subparser"] = subparsers.add_parser(
                domain_name,
                description="WHAD {} Replay tool".format(domain_name.capitalize())
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


def whadreplay_main():
    app = WhadReplayApp()
    app.run()
