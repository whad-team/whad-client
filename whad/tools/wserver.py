"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML

from whad.cli.app import CommandLineApp, ApplicationError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.device.tcp import TCPSocketConnector
logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadServerApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD server tool',
            interface=True,
            commands=False
        )

        self.add_argument(
            '--address',
            '-a',
            dest='address',
            action="store",
            default="127.0.0.1",
            help='IP address to use'
        )

        self.add_argument(
            '--port',
            '-p',
            dest='port',
            action="store",
            default="12345",
            help='Port to use'
        )

    def run(self):
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
                self.error('You have to provide an interface to proxify.')

        except KeyboardInterrupt as keybd:
            self.warning('Server stopped (CTRL-C)')

        if self.server is not None:
            self.server.shutdown()

        # Launch post-run tasks
        self.post_run()

    def serve(self, device):
        '''
        Create a TCP proxy device according to provided address and port and serve forever.
        '''
        print_formatted_text(
            HTML(
                "<ansicyan>[i] Device proxy running on %s:%s </ansicyan>" %
                (self.address, str(self.port))
            )
        )
        self.server = TCPSocketConnector(device, self.address, self.port)
        self.server.serve()

def wserver_main():
    try:
        app = WhadServerApp()
        app.run()
    except ApplicationError as err:
        err.show()
