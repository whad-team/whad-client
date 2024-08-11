"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineApp, ApplicationError, run_app
from scapy.all import *
from whad.device.unix import UnixSocketServerDevice, UnixConnector
from whad.device import Bridge, ProtocolHub
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet
import logging
from time import sleep
from scapy.config import conf

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

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
            pkt = self.on_rx_packet(pkt)
            if pkt is not None:
                msg = message.from_packet(pkt)
                super().on_outbound(msg)
        else:
            logger.debug('[wfilter][input-pipe] forward default outbound message %s' % message)
            # Forward other messages
            super().on_outbound(message)


    def on_inbound(self, message):
        """Process inbound messages.

        Inbound packets are packets coming from our output connector,that need to be
        forwarded as packets to the previous tool.
        """
        if hasattr(message, "to_packet"):
            pkt = message.to_packet()
            pkt = self.on_tx_packet(pkt)
            if pkt is not None:
                msg = message.from_packet(pkt)
                super().on_inbound(msg)
        else:
            logger.debug('[wfilter][input-pipe] forward default inbound message %s' % message)
            # Forward other messages
            super().on_inbound(message)


class WhadFilterApp(CommandLineApp):

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
    def build_filter(self):
        if self.args.filter is None:
            self.args.filter = "True"
        filter_template = "lambda p : not %s" if self.args.invert else "lambda p : %s"
        if "packet." in self.args.filter:
            self.args.filter.replace("packet.", "p.")
        elif "pkt." in self.args.filter:
            self.args.filter.replace("pkt.", "p.")

        return eval(filter_template % (self.args.filter))

    def on_rx_packet(self, pkt):
        if not self.args.down:
            if not self.is_stdout_piped():
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
            return pkt

        filter = self.build_filter()
        try:
            if filter(pkt):
                if self.args.transform is not None:
                    p = packet = pkt
                    exec(self.args.transform)
                    # recompute CRC ?
                if not self.is_stdout_piped():
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                return pkt
            else:

                if self.args.forward:
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                    return pkt
                return None
        except:
            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt
            return None

    def on_tx_packet(self, pkt):
        if not self.args.up:
            if not self.is_stdout_piped():
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
            return pkt

        filter = self.build_filter()
        try:
            if filter(pkt):
                if self.args.transform is not None:
                    p = packet = pkt
                    exec(self.args.transform)
                if not self.is_stdout_piped():
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                return pkt
            else:
                if self.args.forward:
                    display_packet(
                        pkt,
                        show_metadata = self.args.metadata,
                        format = self.args.format
                    )
                    return pkt
                return None
        except:
            if self.args.forward:
                display_packet(
                    pkt,
                    show_metadata = self.args.metadata,
                    format = self.args.format
                )
                return pkt
            return None

    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        if self.args.down is None and self.args.up is None:
            self.args.up   = True
            self.args.down = True

        try:
            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                parameters = self.args.__dict__
                connector = UnixConnector(interface)

                connector.domain = self.args.domain
                hub = ProtocolHub(2)
                connector.format = hub.get(self.args.domain).format

                #connector.translator = get_translator(self.args.domain)(connector.hub)
                #connector.format = connector.translator.format

                if self.is_stdout_piped():
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
                    logger.info("[wfilter] Starting our output pipe")
                    output_pipe = WhadFilterPipe(connector, unix_server, self.on_rx_packet, self.on_tx_packet)

                else:
                    connector.on_packet = self.on_rx_packet

                # Keep running while interface is active
                while interface.opened:
                    sleep(.1)
            else:
                exit(1)
        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()


def wfilter_main():
    app = WhadFilterApp()
    run_app(app)
