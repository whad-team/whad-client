"""User-defined transform tool
"""
import logging
from time import sleep

from scapy.config import conf
from scapy.themes import BrightTheme

from whad.cli.app import CommandLineApp, run_app
from whad.device.unix import UnixSocketServer, UnixConnector
from whad.device import Bridge
from whad.hub import ProtocolHub

logger = logging.getLogger(__name__)

class UserTransformPipe(Bridge):
    """User-defined transform pipe
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
            logger.debug(
                '[user-transform][input-pipe] forward default outbound message %s',
                message
            )
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
            logger.debug(
                '[user-transform][input-pipe] forward default inbound message %s',
                message
            )
            # Forward other messages
            super().on_inbound(message)


class UserTransformApp(CommandLineApp):
    """User-defined transform command-line application

    This class defines a configurable transform application that calls user-defined
    callbacks when packets flows in and out.
    """

    def __init__(self, inbound_cb = None, outbound_cb = None):
        """Application uses an interface and has commands.
        """
        # Save callbacks
        self.__inbound_cb = inbound_cb
        self.__outbound_cb = outbound_cb

        # Initialize user-defined transform app
        super().__init__(
            description='User transform application',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

    def on_rx_packet(self, pkt):
        """Process inbound packet
        """
        logger.debug("[user-transform][on_rx_packet] inbound packet received")
        if self.__inbound_cb is not None:
            pkt = self.__inbound_cb(pkt)
        return pkt


    def on_tx_packet(self, pkt):
        """Process outbound packet
        """
        logger.debug("[user-transform][on_tx_packet] outbound packet received")
        if self.__outbound_cb is not None:
            pkt = self.__outbound_cb(pkt)
        return pkt

    def run(self):
        """Application's main task
        """
        # Launch pre-run tasks
        self.pre_run()

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

                if self.is_stdout_piped():
                    unix_server = UnixConnector(UnixSocketServer(parameters=parameters))

                    while not unix_server.device.opened:
                        if unix_server.device.timedout:
                            return
                        else:
                            sleep(0.1)
                    # Create our packet bridge
                    logger.debug("[user-transform] Starting our output pipe")
                    _ = UserTransformPipe(
                        connector,
                        unix_server,
                        self.on_rx_packet,
                        self.on_tx_packet
                    )

                else:
                    connector.on_packet = self.on_rx_packet

                # Once configured, unlock connector to enable packet processing
                connector.unlock()

                # Keep running while interface is active
                while interface.opened:
                    sleep(.1)
            else:
                exit(1)
        except KeyboardInterrupt:
            # Launch post-run tasks
            self.post_run()

def user_transform(inbound_cb, outbound_cb):
    """User-defined transform application wrapper
    """
    app = UserTransformApp(inbound_cb, outbound_cb)
    run_app(app)
