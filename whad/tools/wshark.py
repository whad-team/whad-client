"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import sys
import logging
from time import sleep

from scapy.config import conf
from scapy.themes import BrightTheme

from whad.cli.ui import wait, success
from whad.hub import ProtocolHub
from whad.device import Bridge
from whad.device.connector import WhadDeviceConnector
from whad.device.unix import UnixConnector, UnixSocketServer
from whad.common.monitors import WiresharkMonitor
from whad.cli.app import CommandLineApp, run_app

# wshark logger
logger = logging.getLogger(__name__)

class WhadWiresharkApp(CommandLineApp):
    """Main WiresharkApp class
    """

    # App connector
    connector = None

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD wireshark',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )

        # Initialize parameters.
        self.monitor = None

    def run(self):
        """Application main() routine
        """

        # Launch pre-run tasks
        self.monitor = None
        self.pre_run()
        try:
            if self.is_piped_interface():
                interface = self.input_interface
            else:
                interface = self.interface

            if interface is not None:
                if not self.args.nocolor:
                    conf.color_theme = BrightTheme()

                # Using a UnixConnector is just a small hack, as it acts like
                # a dummy connector.
                connector = UnixConnector(interface)
                connector.domain = self.args.domain
                hub = ProtocolHub(2)
                connector.format = hub.get(self.args.domain).format

                # Attack a wireshark monitor
                self.monitor = WiresharkMonitor()
                self.monitor.attach(connector)
                self.monitor.start()

                if self.is_stdout_piped():
                    proxy = UnixConnector(UnixSocketServer(parameters=self.args.__dict__))

                    while not proxy.device.opened:
                        if proxy.device.timedout:
                            return
                        sleep(0.1)

                    # Bridge both connectors and their respective interfaces
                    _ = Bridge(connector, proxy)

                    # Wait for the user to CTL-C or close Wireshark
                    while interface.opened and not self.monitor.is_terminated():
                        sleep(.1)

                else:
                    connector.unlock()

                    # Wait for the user to CTL-C or close Wireshark
                    while interface.opened and not self.monitor.is_terminated():
                        wait(f"Forwarding {self.monitor.packets_written} packets to wireshark")
                        sleep(.2)

        except KeyboardInterrupt:
            # Launch post-run tasks
            if self.monitor is not None:
                self.monitor.stop()
                self.monitor.close()
        finally:
            self.post_run()

    def post_run(self):
        if not self.is_stdout_piped() and self.monitor is not None:
            wait(f"Forwarding {self.monitor.packets_written} packets to wireshark",
                end=True
            )
            success(f"{self.monitor.packets_written} packets have been forwarded to wireshark")
        super().post_run()


def wshark_main():
    """Launcher for wshark.
    """
    app = WhadWiresharkApp()
    run_app(app)
