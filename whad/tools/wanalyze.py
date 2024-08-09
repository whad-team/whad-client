"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineApp, ApplicationError, run_app
from scapy.all import *
from whad.device.unix import  UnixSocketConnector, UnixConnector, UnixSocketServerDevice
from whad.device import Bridge, ProtocolHub
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet, format_analyzer_output
from whad.tools.utils import get_analyzers

import logging
import time
import sys
import json

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadAnalyzeUnixSocketConnector(UnixSocketConnector):
    pass

class WhadAnalyzePipe(Bridge):

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
            pkts = self.processing_function(pkt, piped=True)
            if pkts is not None:
                for forwarded in pkts:
                    msg = message.from_packet(forwarded)
                    super().on_outbound(msg)
        else:
            logger.debug('[wfilter][input-pipe] forward default outbound message %s' % message)
            # Forward other messages
            super().on_outbound(message)


def display_analyzers(analyzers):
    for domain, analyzers_list in analyzers.items():
        print_formatted_text(HTML("<b><ansicyan>Available analyzers: </ansicyan> {domain}</b>".format(domain=domain)))
        for analyzer_name, analyzer_class in analyzers_list.items():
            print_formatted_text(HTML("  <b>- {analyzer_name}</b> : {output}".format(analyzer_name=analyzer_name, output=", ".join(analyzer_class().output.keys()))))

        print()

class WhadAnalyzeApp(CommandLineApp):

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

    def on_packet(self, pkt, piped=False):
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
                                    format_analyzer_output(analyzer.output[parameter], mode="human_readable")
                                )
                            except KeyError:
                                error("Unknown output parameter {param}, ignoring.".format(param=parameter))
                        print(self.args.delimiter.join(out))
                    elif self.args.raw:
                        for parameter in self.provided_parameters[analyzer_name]:
                            try:
                                sys.stdout.buffer.write(format_analyzer_output(analyzer.output[parameter], mode="raw"))
                            except KeyError:
                                error("Unknown output parameter {param}, ignoring.".format(param=parameter))
                    elif self.args.json:
                        for parameter in self.provided_parameters[analyzer_name]:
                            try:
                                json_value = format_analyzer_output(analyzer.output[parameter], mode="json")
                                if json_value is not None:
                                    if self.args.label:
                                        print("{\"" + parameter + "\": " + json_value + "}")
                                    else:
                                        print(json_value)
                                else:
                                    error("Parameter {param} not serializable in JSON, ignoring.".format(param=parameter))
                            except KeyError:
                                error("Unknown output parameter {param}, ignoring.".format(param=parameter))

                    sys.stdout.flush()

                else:
                    if not self.args.json:
                        success("[✓] " + analyzer_name + " → " + "completed")
                        for output_name, output_value in analyzer.output.items():
                            print_formatted_text(
                                HTML("  - <b>{name}: </b> {value}".format(
                                        name=output_name,
                                        value=format_analyzer_output(output_value,mode="human_readable")
                                    )
                                )
                            )
                        if self.args.packets:
                            print()
                            print_formatted_text(HTML("  - <b>{count} packets analyzed: </b>".format(count=len(analyzer.marked_packets))))

                            for packet in analyzer.marked_packets:
                                display_packet(
                                    pkt,
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

    def get_provided_analyzers(self):
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
                    error("Unknown analyzer ({analyzer}).".format(analyzer=name))
                    exit(1)
            else:
                if analyzer in available_analyzers:
                    analyzers.append(analyzer)
                else:
                    error("Unknown analyzer ({analyzer}).".format(analyzer=analyzer))
                    exit(1)
        return list(set(analyzers)), parameters

    def run(self):
        # Launch pre-run tasks
        self.pre_run()

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

                parameters = self.args.__dict__

                connector = WhadAnalyzeUnixSocketConnector(interface)
                for parameter_name, parameter_value in parameters.items():
                    connector.add_parameter(parameter_name, parameter_value)

                self.provided_analyzers, self.provided_parameters = self.get_provided_analyzers()
                self.selected_analyzers = {}
                for analyzer_name, analyzer_class in get_analyzers(self.args.domain).items():
                    if analyzer_name in self.provided_analyzers or len(self.provided_analyzers) == 0:
                        self.selected_analyzers[analyzer_name] = analyzer_class()
                        self.selected_analyzers[analyzer_name]._displayed = False

                connector.domain = self.args.domain
                hub = ProtocolHub(2)
                connector.format = hub.get(self.args.domain).format


                if self.is_stdout_piped() and self.args.packets:
                    unix_server = UnixConnector(UnixSocketServerDevice(parameters={
                        'domain': self.args.domain,
                        'format': self.args.format,
                        'metadata' : self.args.metadata
                    }))


                    while not unix_server.device.opened:
                        if unix_server.device.timedout:
                            return
                        else:
                            sleep(0.1)
                    # Create our packet bridge
                    logger.info("[wanalyze] Starting our output pipe")
                    output_pipe = WhadAnalyzePipe(connector, unix_server, self.on_packet)
                else:
                    connector.on_packet = self.on_packet

                while interface.opened:
                    time.sleep(.1)

        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wanalyze_main():
    app = WhadAnalyzeApp()
    run_app(app)
