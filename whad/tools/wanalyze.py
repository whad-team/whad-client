"""
WHAD analyzer

This utility processes incoming packets and feed one or more traffic analyzers
with them, extracting and interpreting data based on various supported protocols.
"""
from inspect import Parameter
import sys
from time import sleep
import logging
from typing import List, Union, Tuple

from prompt_toolkit import print_formatted_text, HTML
from scapy.packet import Packet
from scapy.config import conf
from scapy.themes import BrightTheme

from whad.common.analyzer import InvalidParameter
from whad.scapy.layers import *
from whad.cli.app import CommandLineApp, run_app
from whad.device.unix import UnixConnector, UnixSocketServer
from whad.device import Bridge
from whad.hub import ProtocolHub
from whad.cli.ui import error, success, info, display_packet, format_analyzer_output
from whad.tools.utils import get_analyzers

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadAnalyzePipe(Bridge):
    """
    WHAD analyzer main pipe.

    This pipe processes outbound packets.
    """

    def __init__(self, input_connector, output_connector, processing_function):
        super().__init__(input_connector, output_connector)
        self.processing_function = processing_function

    def on_outbound(self, message):
        """Process outbound messages.

        Outbound packets are packets coming from our input connector,that need to be
        forwarded as packets to the next tool.
        """
        if hasattr(message, "to_packet"):
            pkt = message.to_packet()
            if pkt is not None:
                pkts = self.processing_function(pkt, piped=True)
                if pkts is not None:
                    for forwarded in pkts:
                        msg = message.from_packet(forwarded)
                        super().on_outbound(msg)
        else:
            logger.debug("[wfilter][input-pipe] forward default outbound message %s", message)
            # Forward other messages
            super().on_outbound(message)


def display_analyzers(analyzers: dict):
    """Show available analyzers.
    """
    for domain, analyzers_list in analyzers.items():
        print_formatted_text(HTML(
            f"<b><ansicyan>Available analyzers: </ansicyan> {domain}</b>"
        ))
        for analyzer_name, analyzer_class in analyzers_list.items():
            # Retrieve parameters for analyzer class and format them if some are defined.
            analyzer_params = analyzer_class.PARAMETERS
            output=", ".join(analyzer_class().output.keys())
            print_formatted_text(HTML(
                f"  <b>- {analyzer_name}</b> : {output}"
            ))
            parameters = []
            if len(analyzer_params.keys()) > 0:
                for pname, pvalue in analyzer_params.items():
                    print_formatted_text(HTML(
                        f"      <ansiblue>parameter</ansiblue> {pname} <i>(default: \"{pvalue}\")</i>"
                    ))

        print()

class WhadAnalyzeApp(CommandLineApp):
    """
    Main `wanalyze` CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD analyze tool',
            interface=False,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_STANDARD
        )

        self.add_argument(
            'analyzer',
            help='Analyzer to use',
            nargs="*"
        )


        self.add_argument(
            '--trigger',
            dest='trigger',
            default=False,
            action="store_true",
            help='show when an analyzer is triggered'
        )

        self.add_argument(
            '--json',
            dest='json',
            default=False,
            action="store_true",
            help='serialize output into json format'
        )

        self.add_argument(
            '-p',
            '--packets',
            dest='packets',
            default=False,
            action="store_true",
            help='display packets associated with the analyzer'
        )

        self.add_argument(
            '--label',
            dest='label',
            default=False,
            action="store_true",
            help='display labels before output value'
        )

        self.add_argument(
            '-d',
            '-D',
            '--delimiter',
            dest='delimiter',
            default="\n",
            help='delimiter between outputs'
        )

        self.add_argument(
            '-r',
            '--raw',
            dest='raw',
            action="store_true",
            default=False,
            help='dump output directly to stdout buffer'
        )

        self.add_argument(
            '-l',
            '--list',
            action="store_true",
            help='List of available analyzers'
        )

        self.add_argument(
            '-s',
            '--set',
            dest='ta_params',
            nargs=1,
            action='append',
            metavar='param=value',
            help="set analyzer parameter to value"
        )

        # Initialize analyzers and parameters.
        self.provided_analyzers = []
        self.provided_parameters = {}
        self.selected_analyzers = {}

    def on_packet(self, pkt: Packet, piped: bool = False) -> Union[List[Packet], None]:
        """
        Packet processing callback.

        :param pkt: Packet to process.
        :type pkt: Packet
        :param piped: `True` if packet comes from a pipe, `False` otherwise.
        :type piped: bool, optional
        """
        for analyzer_name, analyzer in self.selected_analyzers.items():
            analyzer.process_packet(pkt)

            if analyzer.triggered and not analyzer._displayed and self.args.trigger and not piped:
                info(analyzer_name + " → " + "triggered")
                analyzer._displayed = True

            if analyzer.completed:
                if self.args.packets and piped:
                    marked_packets = analyzer.marked_packets
                    analyzer.reset()
                    return marked_packets

                if analyzer_name in self.provided_parameters:
                    out = []
                    if not self.args.raw and not self.args.json:
                        for parameter in self.provided_parameters[analyzer_name]:
                            try:
                                out.append(
                                    ((parameter + ": ") if self.args.label else "") +
                                    format_analyzer_output(analyzer.output[parameter],
                                                           mode="human_readable")
                                )
                            except KeyError:
                                error(f"Unknown output parameter {parameter}, ignoring.")
                        print(self.args.delimiter.join(out))
                    elif self.args.raw:
                        for parameter in self.provided_parameters[analyzer_name]:
                            try:
                                sys.stdout.buffer.write(format_analyzer_output(
                                    analyzer.output[parameter], mode="raw"))
                            except KeyError:
                                error(f"Unknown output parameter {parameter}, ignoring.")
                    elif self.args.json:
                        for parameter in self.provided_parameters[analyzer_name]:
                            try:
                                json_value = format_analyzer_output(analyzer.output[parameter],
                                                                    mode="json")
                                if json_value is not None:
                                    if self.args.label:
                                        print("{\"" + parameter + "\": " + json_value + "}")
                                    else:
                                        print(json_value)
                                else:
                                    error((f"Parameter {parameter} not serializable "
                                           f"in JSON, ignoring."))
                            except KeyError:
                                error(f"Unknown output parameter {parameter}, ignoring.")

                    sys.stdout.flush()

                else:
                    if not self.args.json:
                        success("[✓] " + analyzer_name + " → " + "completed")
                        for output_name, output_value in analyzer.output.items():
                            value=format_analyzer_output(output_value, mode="human_readable")
                            if value == "&":
                                value = "&amp;"
                            print_formatted_text(HTML(f"  - <b>{output_name}: </b> {value}"))
                        if self.args.packets:
                            print()
                            print_formatted_text(HTML(
                                f"  - <b>{len(analyzer.marked_packets)} packets analyzed: </b>"
                            ))

                            for packet in analyzer.marked_packets:
                                display_packet(
                                    packet,
                                    show_metadata = self.args.metadata,
                                    format = self.args.format
                                )
                        print()
                    else:
                        out = "{"
                        for output_name, output_value in analyzer.output.items():
                            json_value = format_analyzer_output(output_value,mode="json")
                            out += "\"" + output_name + "\": " + json_value + ", "
                        out = out[:-2] + "}"
                        print(out)
                    analyzer._displayed = False
                analyzer.reset()

        # No packets returned
        return None

    def get_provided_analyzers(self) -> Tuple[list, dict]:
        """Retrieve a list of analyzers with their corresponding parameters.

        :return: list of available analyzers and their associated parameters.
        :rtype: tuple
        """
        available_analyzers = list(get_analyzers(self.args.domain).keys())
        analyzers = []
        parameters = {}
        for analyzer in self.args.analyzer:
            if "." in analyzer:
                name, param = analyzer.split(".")
                if name in available_analyzers:
                    analyzers.append(name)
                    if name in parameters:
                        parameters[name].append(param)
                    else:
                        parameters[name] = [param]
                else:
                    error(f"Unknown analyzer ({name}).")
                    sys.exit(1)
            else:
                if analyzer in available_analyzers:
                    analyzers.append(analyzer)
                else:
                    error(f"Unknown analyzer ({analyzer}).")
                    sys.exit(1)
        return list(set(analyzers)), parameters

    def run(self):
        # Launch pre-run tasks
        self.pre_run()

        # Parse analyzer parameters passed by the user (--set param=value)
        config_params = {}
        if self.args.ta_params is not None:
            for param in self.args.ta_params:
                if '=' in param[0]:
                    pname, pvalue = param[0].split('=')[:2]
                    if pname != '':
                        config_params[pname] = pvalue

        if self.args.list:
            analyzers = get_analyzers()
            display_analyzers(analyzers)

        try:
            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                # Configure the current domain
                ProtocolHub.set_domain(self.args.domain)

                #parameters = self.args.__dict__
                connector = UnixConnector(interface)
                #for parameter_name, parameter_value in parameters.items():
                #    connector.add_parameter(parameter_name, parameter_value)

                self.provided_analyzers, self.provided_parameters = self.get_provided_analyzers()
                self.selected_analyzers = {}
                for name, clazz in get_analyzers(self.args.domain).items():
                    if name in self.provided_analyzers or len(self.provided_analyzers) == 0:
                        # Pick parameters required by the analyzer from our current configured params
                        params = {}
                        for pname, pvalue in config_params.items():
                            if pname in clazz.PARAMETERS:
                                params[pname] = pvalue

                        # Instantiate the requested traffic analyzer with its optional params
                        self.selected_analyzers[name] = clazz(**params)
                        self.selected_analyzers[name]._displayed = False

                connector.domain = self.args.domain
                hub = ProtocolHub(2)
                connector.format = hub.get(self.args.domain).format


                if self.is_stdout_piped() and self.args.packets:
                    unix_server = UnixConnector(UnixSocketServer(parameters={
                        'domain': self.args.domain,
                        'format': self.args.format,
                        'metadata' : self.args.metadata
                    }))


                    while not unix_server.device.opened:
                        if unix_server.device.timedout:
                            return
                        sleep(0.1)

                    # Create our packet bridge
                    logger.info("[wanalyze] Starting our output pipe")
                    WhadAnalyzePipe(connector, unix_server, self.on_packet).wait()
                else:
                    connector.on_packet = self.on_packet
                    # Unlock connector
                    connector.unlock()

                    # Wait for the associated interface to disconnect
                    connector.join()
        except InvalidParameter as param_err:
            # Invalid parameter provided
            self.error(f"An invalid value has been provided for parameter '{param_err.parameter}' ({param_err.value}) !")
        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wanalyze_main():
    """Launcher for wanalyze CLI application.
    """
    app = WhadAnalyzeApp()
    run_app(app)

