"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import os
import logging
import time

from whad.exceptions import RequiredImplementation
from whad.cli.ui import wait, success, display_packet
from whad.cli.app import CommandLineApp, run_app
from whad.device import Bridge, ProtocolHub
from scapy.all import *
from whad.device.unix import UnixConnector, UnixSocketServerDevice
from whad.common.monitors import PcapWriterMonitor
from whad.common.monitors.pcap import PcapWriterMonitor
#from whad.unifying import Injector
from whad.phy.connector.injector import Injector

from queue import Queue
logger = logging.getLogger(__name__)


class WhadInjectApp(CommandLineApp):
    connector = None
    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD generic injection tool',
            interface=True,
            commands=False,
            input=CommandLineApp.INPUT_WHAD,
            output=CommandLineApp.OUTPUT_WHAD
        )
        self._input_queue = Queue()

    def on_incoming_packet(self, packet):
        self._input_queue.put(packet)

    def run(self):
        # Launch pre-run tasks
        self.pre_run()

        try:
            if self.is_piped_interface():

                if self.interface is not None:
                    if not self.args.nocolor:
                        conf.color_theme = BrightTheme()

                    parameters = self.args.__dict__


                    connector = UnixConnector(self.input_interface)

                    connector.domain = self.args.domain
                    hub = ProtocolHub(2)
                    connector.format = hub.get(self.args.domain).format
                    #connector.translator = get_translator(self.args.domain)(connector.hub)
                    #connector.format = connector.translator.format

                    connector.on_packet = self.on_incoming_packet
                    self.injector = Injector(self.interface)
                    #self.injector.autosync = True
                    #self.injector.attach_callback(lambda p:p.show())
                    while True:
                        #sleep(1)
                        if not self._input_queue.empty():
                            packet = self._input_queue.get()
                            print(packet.metadata, repr(packet))
                            self.injector.inject(packet)
                else:
                    raise RequiredImplementation()

        except KeyboardInterrupt:
            self.post_run()


def winject_main():
    app = WhadInjectApp()
    run_app(app)
