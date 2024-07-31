"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
from prompt_toolkit import print_formatted_text, HTML

from whad.common.monitors.pcap import PcapWriterMonitor
from whad.cli.app import CommandLineApp, ApplicationError, run_app
from scapy.all import *
#from whad.common.ipc import IPCPacket
from whad.device.unix import UnixConnector, UnixSocketServerDevice
from whad.device import Bridge
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
from whad.cli.ui import error, warning, success, info, display_event, display_packet
from whad.common.monitors import PcapWriterMonitor
from whad.tools.utils import get_translator
from time import sleep
import logging
import sys

logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.INFO)

class WhadDumpPipe(Bridge):
    pass

class WhadDumpApp(CommandLineApp):
    connector = None
    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD PCAP export',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

        self.add_argument(
            'pcap',
            help='Pcap file to export'
        )


    def run(self):
        # Launch pre-run tasks
        monitor = None
        self.pre_run()

        try:
            if self.args.pcap is not None:
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
                    connector.translator = get_translator(self.args.domain)(connector.hub)
                    connector.format = connector.translator.format

                    self.connector = connector
                    monitor = PcapWriterMonitor(self.args.pcap)
                    monitor.attach(connector)
                    monitor.start()

                    if self.is_stdout_piped():
                        unix_server = UnixConnector(UnixSocketServerDevice(parameters={
                            'domain': self.args.domain,
                            'format': self.args.format,
                            'metadata': self.args.metadata
                        }))
                        # Create our packet bridge
                        logger.info("[wdump] Starting our output pipe")
                        output_pipe = WhadDumpPipe(connector, unix_server)

                    while interface.opened:
                        time.sleep(.1)
            else:
                pass
        except KeyboardInterrupt:
            # Launch post-run tasks
            if monitor is not None:
                monitor.stop()
                monitor.close()
            self.post_run()


def wdump_main():
    app = WhadDumpApp()
    run_app(app)
