"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging

from prompt_toolkit import print_formatted_text, HTML

from whad.cli.app import CommandLineApp, run_app
from whad.device.tcp import TCPSocketConnector
from whad.device.websocket import WebSocketConnector

logger = logging.getLogger(__name__)

class WhadServerApp(CommandLineApp):
    """Main wserver CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description="WHAD server tool",
            interface=True,
            commands=False
        )

        self.add_argument(
            '--websocket',
            '--ws',
            '-w',
            action='store_true',
            dest='websocket',
            default=False,
            help="Enable websocket mode."
        )


        self.add_argument(
            '-j',
            '--json',
            action='store_true',
            dest='json',
            default=False,
            help="Export as JSON (websocket mode only)"
        )

        self.add_argument(
            "--address",
            "-a",
            dest="address",
            action="store",
            default="127.0.0.1",
            help="IP address to use"
        )

        self.add_argument(
            "--port",
            "-p",
            dest="port",
            action="store",
            default="12345",
            help="Port to use"
        )

        # Initialize properties.
        self.address = None
        self.port = None
        self.server = None

    def run(self, pre: bool = True, post: bool = True):
        """CLI application main routine.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            # Format address and port
            self.address = self.args.address
            self.port = int(self.args.port)

            # We need to have an interface specified
            if interface is not None:
                self.serve(interface)
            else:
                self.error("You have to provide an interface to proxify.")

        except KeyboardInterrupt:
            self.warning("Server stopped (CTRL-C)")

        if self.server is not None:
            self.server.shutdown()

        # Launch post-run tasks
        self.post_run()

    def serve(self, device):
        """
        Create a TCP proxy device according to provided address and port and serve forever.
        """
        print_formatted_text(HTML(
            f"<ansicyan>[i] Device proxy running on {self.address}:{self.port} </ansicyan>"
        ))

        if self.args.websocket:
            logger.debug("[wserver] Uses websocket mode")
            self.server = WebSocketConnector(device, self.address, self.port,
                                             json_mode = self.args.json)
            self.server.serve()
        else:
            logger.debug("[wserver] Uses default TCP mode")
            # Setup a TCP server and await connections.
            self.server = TCPSocketConnector(device, self.address, self.port)
            self.server.serve()

def wserver_main():
    """Launcher for wserver.
    """
    app = WhadServerApp()
    run_app(app)
