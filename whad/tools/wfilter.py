"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import sys
import logging
from time import sleep

# We need all scapy layers to craft filter expressions
# pylint: disable-next=wildcard-import
from scapy.layers.all import *
from scapy.packet import Packet

# We also need our custom layers
from whad.scapy.layers import *

# Required to configure scapy theme.
from scapy.themes import BrightTheme
from scapy.config import conf

from whad.cli.app import CommandLineApp, run_app
from whad.device.unix import UnixSocketServer, UnixConnector
from whad.device import Bridge
from whad.hub import ProtocolHub
from whad.cli.ui import display_packet, error

logger = logging.getLogger(__name__)

class WhadFilterPipe(Bridge):
    """Whad filter output pipe

    When wfilter is chained with another whad tool, it spawns a device
    based on the specified profile using the specified WHAD adapter and forward
    it to the chained tool. The chained tool will then forward packets back and forth.
    """

    def __init__(self, input_connector, output_connector, on_rx_packet_cb, on_tx_packet_cb):
        super().__init__(input_connector, output_connector)
        self.on_rx_packet = on_rx_packet_cb
        self.on_tx_packet = on_tx_packet_cb


    def on_outbound(self, message):
        """Process outbound messages.

        Outbound packets are packets coming from our input connector,that need to be
        forwarded as packets to the next tool.
        """
        if hasattr(message, "to_packet"):
            pkt = message.to_packet()
            if pkt is not None:
                pkt = self.on_rx_packet(pkt)
                if pkt is not None:
                    msg = message.from_packet(pkt)
                    super().on_outbound(msg)
        else:
            logger.debug("[wfilter][input-pipe] forward default outbound message %s", message)
            # Forward other messages
            super().on_outbound(message)


    def on_inbound(self, message):
        """Process inbound messages.

        Inbound packets are packets coming from our output connector,that need to be
        forwarded as packets to the previous tool.
        """
        if hasattr(message, "to_packet"):
            pkt = message.to_packet()
            if pkt is not None:
                pkt = self.on_tx_packet(pkt)
                if pkt is not None:
                    msg = message.from_packet(pkt)
                    super().on_inbound(msg)
        else:
            logger.debug("[wfilter][input-pipe] forward default inbound message %s", message)
            # Forward other messages
            super().on_inbound(message)


class WhadFilterApp(CommandLineApp):
    """wfilter CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD filter tool',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

        self.add_argument(
            'filter',
            help='filter to evaluate',
            nargs='?'
        )

        # Metada can be disabled here
        self.add_argument(
            '--no-metadata',
            dest='metadata',
            action="store_false",
            help='Hide packets metadata'
        )

        # Format can be overriden here
        self.add_argument(
            '--format',
            dest='format',
            action="store",
            default='repr',
            choices=['repr', 'show', 'raw', 'hexdump', 'tshark'],
            help='Indicate format to display packet'
        )

        self.add_argument(
            '--down',
            dest='down',
            action="store_true",
            default=None,
            help='process down stream'
        )


        self.add_argument(
            '--up',
            dest='up',
            action="store_true",
            default=None,
            help='process up stream'
        )

        self.add_argument(
            '-t',
            '--transform',
            dest='transform',
            type=str,
            default=None,
            help='apply a transformation'
        )

        self.add_argument(
            '-e',
            '--invert',
            dest='invert',
            action="store_true",
            default=False,
            help='invert filter'
        )

        self.add_argument(
            '-f',
            '--forward',
            dest='forward',
            action="store_true",
            default=False,
            help='forward packets not matched by the filter (dropped by default)'
        )

        self.add_argument(
            '-l',
            '--load',
            dest='loadables',
            default=None,
            action="append",
            help='load Scapy packet definitions from external Python file'
        )

        # Initialize our packet filter
        self.packet_filter = None

    def build_filter(self):
        """Build filter from provided args.
        """
        if self.args.filter is None:
            self.args.filter = "True"

        # Generate our packet filter lambda.
        if self.args.invert:
            filter_lambda = f"lambda p,pkt,packet: not {self.args.filter}"
        else:
            filter_lambda = f"lambda p,pkt,packet: {self.args.filter}"

        # Create our lambda function.
        try:
            # pylint: disable-next=eval-used
            return eval(filter_lambda)
        except SyntaxError:
            return None


    def on_rx_packet(self, pkt):
        """Packet reception callback.

        We apply our filter function to each packet received to determine if
        we must keep it or not. If no filter function is provided, we keep all
        of them.
        """
        if not self.args.down:
            if not self.is_stdout_piped():
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
            return pkt

        try:
            # We call our packet filter with the same arguments 3 times to
            # cover the `p`, `pkt` and `packet` variables in our lambda.
            if self.packet_filter(pkt, pkt, pkt):
                if self.args.transform is not None:

                    # Build our custom environment.
                    env = dict(globals())
                    env.update({
                        'p': pkt,
                        'pkt': pkt,
                        'packet': pkt
                    })

                    # Execute our transform.
                    # pylint: disable-next=exec-used
                    exec(self.args.transform, env)

                    # recompute CRC ?
                if not self.is_stdout_piped():
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                return pkt

            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt

            # No packet to forward.
            return None

        # We catch all types of exception here as the python code used by
        # the user may cause any issue.
        #
        # pylint: disable-next=broad-exception-caught
        except Exception:
            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt

            # No packet to forward.
            return None

    def on_tx_packet(self, pkt):
        """Packet transmission callback.
        """
        if not self.args.up:
            if not self.is_stdout_piped():
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
            return pkt

        try:
            # We call our packet filter with the same arguments 3 times to
            # cover the `p`, `pkt` and `packet` variables in our lambda.
            if self.packet_filter(pkt, pkt, pkt):
                if self.args.transform is not None:
                    # Build our custom environment.
                    env = dict(globals())
                    env.update({
                        'p': pkt,
                        'pkt': pkt,
                        'packet': pkt
                    })

                    # Execute our transform.
                    # pylint: disable-next=exec-used
                    exec(self.args.transform, env)

                if not self.is_stdout_piped():
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                return pkt

            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt
            return None

        # We catch all types of exception here as the python code used by
        # the user may cause any issue.
        #
        # pylint: disable-next=broad-exception-caught
        except Exception:
            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt
            return None

    def run(self):
        """wfilter main function.
        """
        # Launch pre-run tasks
        self.pre_run()

        if self.args.down is None and self.args.up is None:
            self.args.up   = True
            self.args.down = True

        # Load any Scapy definition files if provided
        if self.args.loadables is not None:
            for loadable in self.args.loadables:
                l = __import__(loadable)
                for obj in dir(l):
                    o = getattr(l, obj)
                    try:
                        if issubclass(o, Packet) and o != Packet:
                            globals()[obj] = o
                    except TypeError:
                        pass

        try:
            # Build our packet filter, exit if invalid.
            self.packet_filter = self.build_filter()
            if self.packet_filter is None:
                error("Syntax error in provided filter expression.")
                return

            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                # Load parameters from input tool
                parameters = self.args.__dict__
                connector = UnixConnector(interface)

                # Set the current domain in the hub and inject into connector.
                ProtocolHub.set_domain(self.args.domain)
                connector.domain = self.args.domain

                if self.is_stdout_piped():
                    unix_server = UnixConnector(UnixSocketServer(parameters=parameters))


                    while not unix_server.device.opened:
                        if unix_server.device.timedout:
                            return
                        sleep(0.1)

                    # Create our packet bridge
                    logger.info("[wfilter] Starting our output pipe")
                    WhadFilterPipe(connector, unix_server, self.on_rx_packet,
                                   self.on_tx_packet).join()

                else:
                    # Unlock Unix connector
                    connector.unlock()

                    # Take format and metadata settings from input tool,
                    # if provided.
                    if "format" in parameters and parameters["format"] in ('repr', 'show',
                                                                           'raw', 'hexdump',
                                                                           'tshark'):
                        self.args.format = parameters["format"]

                    # Overwrite its packet rx method
                    connector.on_packet = self.on_rx_packet

                    # Keep running while interface is active
                    connector.join()
            else:
                sys.exit(1)
        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wfilter_main():
    """Launcher for wfilter CLI application.
    """
    app = WhadFilterApp()
    run_app(app)
