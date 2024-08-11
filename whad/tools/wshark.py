"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
import time

from scapy.all import *
from scapy.config import conf
from whad.cli.ui import wait, success
from whad.device import Bridge, ProtocolHub
from whad.device.unix import UnixConnector, UnixSocketServerDevice
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

                parameters = self.args.__dict__

                parameters.update({
                    #"on_tx_packet_cb" : self.on_tx_packet,
                    #"on_rx_packet_cb" : self.on_rx_packet,
                })

                # Using a UnixConnector is just a small hack, as it acts like
                # a dummy connector.
                connector = UnixConnector(interface)
                if self.is_stdout_piped():
                    proxy = UnixConnector(UnixSocketServerDevice(parameters=self.args.__dict__))

                    while not proxy.device.opened:
                        if proxy.device.timedout:
                            return
                        else:
                            sleep(0.1)

                    # Bridge both connectors and their respective interfaces
                    bridge = Bridge(connector, proxy)

                # Save our connector and force its domain
                self.connector = connector
                self.connector.domain = self.args.domain
                #self.connector.translator = get_translator(self.args.domain)(connector.hub)
                #self.connector.format = connector.translator.format


                # Query our protocol hub to gather the correct format function
                # based on the provided domain
                hub = ProtocolHub(2)
                self.connector.format = hub.get(self.args.domain).format

                # Attack a wireshark monitor
                self.monitor = WiresharkMonitor()
                self.monitor.attach(self.connector)
                self.monitor.start()

                if self.is_stdout_piped():
                    # Wait for the user to CTL-C
                    while interface.opened:
                        time.sleep(.1)
                else:
                    while interface.opened:
                        wait("Forwarding {count} packets to wireshark".format(
                                count=str(self.monitor.packets_written)
                            )
                        )
                        time.sleep(.2)


        except KeyboardInterrupt:
            # Launch post-run tasks
            if self.monitor is not None:
                self.monitor.stop()
                self.monitor.close()
            self.post_run()

    def post_run(self):
        if not self.is_stdout_piped():
            wait("Forwarding {count} packets to wireshark".format(
                    count=str(self.monitor.packets_written)
                ),
                end=True
            )
            success("{count} packets have been forwarded to wireshark".format(
                    count = str(self.monitor.packets_written)
                )
            )
        super().post_run()


def wshark_main():
    app = WhadWiresharkApp()
    run_app(app)
