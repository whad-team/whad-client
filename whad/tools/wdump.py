"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import os
import logging
import time

from whad.cli.ui import wait, success, error
from whad.cli.app import CommandLineApp, run_app
from whad.device import Bridge, ProtocolHub
from scapy.all import *
from whad.device.unix import UnixConnector, UnixSocketServerDevice
from whad.common.monitors import PcapWriterMonitor
from whad.common.monitors.pcap import PcapWriterMonitor

logger = logging.getLogger(__name__)

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
                                self.warning('PCAP file already exists, use --append to add packets to it or --force to force overwriting')
                                return
                            else:
                                try:
                                    # Remove file
                                    os.unlink(self.args.pcap)
                                except IOError:
                                    self.error("Cannot create PCAP file")
                    else:
                        self.error('Cannot write to PCAP file (not a regular file)')
                        return

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

                    self.connector = connector
                    self.monitor = PcapWriterMonitor(self.args.pcap)
                    self.monitor.attach(connector)
                    self.monitor.start()

                    if self.is_stdout_piped():
                        unix_server = UnixConnector(UnixSocketServerDevice(parameters=self.args.__dict__))


                        while not unix_server.device.opened:
                            if unix_server.device.timedout:
                                return
                            else:
                                sleep(0.1)

                        # Create our packet bridge
                        logger.info("[wdump] Starting our output pipe")
                        output_pipe = WhadDumpPipe(connector, unix_server)
                        while interface.opened:
                            time.sleep(.1)
                    else:
                        while interface.opened:
                            wait("Dumping {count} packets into pcap file: ".format(
                                    count=str(self.monitor.packets_written)
                                ),
                                suffix = self.args.pcap
                            )
                            time.sleep(.2)
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
            wait("Dumping {count} packets into pcap file: ".format(
                    count=str(self.monitor.packets_written)
                ),
                suffix = self.args.pcap,
                end = True
            )
            success("{count} packets have been dumped into {pcap}".format(
                    count = str(self.monitor.packets_written),
                    pcap = self.args.pcap
                )
            )
        super().post_run()

def wdump_main():
    app = WhadDumpApp()
    run_app(app)
