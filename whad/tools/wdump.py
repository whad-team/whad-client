"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import os
import logging
from time import sleep

from scapy.config import conf
from scapy.themes import BrightTheme

from whad.cli.ui import wait, success, error
from whad.cli.app import CommandLineApp, run_app
from whad.device import Bridge
from whad.hub import ProtocolHub
from whad.device.unix import UnixConnector, UnixSocketServer
from whad.common.monitors import PcapWriterMonitor

logger = logging.getLogger(__name__)

class WhadDumpApp(CommandLineApp):
    """
    Main `wdump` CLI application class.
    """

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
            '-f',
            '--force',
            action='store_true',
            dest='force',
            default=False,
            help="Force file overwrite"
        )

        self.add_argument(
            '-a',
            '--append',
            dest='append',
            action='store_true',
            default=False,
            help="Append packets to existing file"
        )

        self.add_argument(
            'pcap',
            help='Pcap file to export'
        )

        # Initialize our monitor.
        self.monitor = None


    def run(self):
        # Launch pre-run tasks
        self.monitor = None
        self.pre_run()

        try:
            if self.args.pcap is not None:

                # If pcap file already exists, ask the user if he/she wants to
                # overwrite it if no '--append' option set
                if os.path.exists(self.args.pcap):
                    if os.path.isfile(self.args.pcap):
                        if not self.args.append:
                            if not self.args.force:
                                self.warning((
                                    "PCAP file already exists, use --append to add packets"
                                    " to it or --force to force overwriting"))
                                return

                            try:
                                # Remove file
                                os.unlink(self.args.pcap)
                            except IOError:
                                self.error("Cannot create PCAP file")
                    else:
                        self.error("Cannot write to PCAP file (not a regular file)")
                        return

                if self.is_piped_interface():
                    interface = self.input_interface
                else:
                    interface = self.interface

                if interface is not None:
                    if not self.args.nocolor:
                        conf.color_theme = BrightTheme()

                    connector = UnixConnector(interface)
                    connector.domain = self.args.domain
                    hub = ProtocolHub(2)
                    connector.format = hub.get(self.args.domain).format

                    self.connector = connector
                    self.monitor = PcapWriterMonitor(self.args.pcap)
                    self.monitor.attach(connector)
                    self.monitor.start()

                    if self.is_stdout_piped():
                        unix_server = UnixConnector(UnixSocketServer(
                            parameters=self.args.__dict__
                        ))

                        while not unix_server.device.opened:
                            if unix_server.device.timedout:
                                return
                            sleep(0.1)

                        # Create our packet bridge
                        logger.info("[wdump] Starting our output pipe")
                        bridge = Bridge(connector, unix_server)
                        bridge.join()
                    else:
                        # Unlock Unix connector first
                        connector.unlock()

                        # Process packets
                        while interface.opened:
                            wait(f"Dumping {self.monitor.packets_written} packets into pcap file: ",
                                suffix = self.args.pcap
                            )
                            sleep(.5)
            else:
                error("You must provide a pcap file.")
        except KeyboardInterrupt:
            # Launch post-run tasks
            if self.monitor is not None:
                self.monitor.stop()
                self.monitor.close()
            self.post_run()

    def post_run(self):
        if not self.is_stdout_piped():
            wait(
                f"Dumping {self.monitor.packets_written} packets into pcap file: ",
                suffix = self.args.pcap,
                end = True
            )
            success(
                f"{self.monitor.packets_written} packets have been dumped into {self.args.pcap}"
            )
        super().post_run()

def wdump_main():
    """Launcher for `wdump` CLI application.
    """
    app = WhadDumpApp()
    run_app(app)
