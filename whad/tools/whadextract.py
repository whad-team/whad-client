"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time

from whad.cli.app import CommandLineApp
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
logger = logging.getLogger(__name__)

class WhadExtractApp(CommandLineApp):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD extraction tool',
            interface=True,
            commands=False
        )

        '''
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
        '''

    def run(self):

        # Launch pre-run tasks
        self.pre_run()

        while True:
            print("Hello from whadextract !")
            time.sleep(1)
        # Launch post-run tasks
        self.post_run()


def whadextract_main():
    app = WhadExtractApp()
    app.run()
