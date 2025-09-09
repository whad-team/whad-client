"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import sys
import os
import logging

from scapy.config import conf
from scapy.themes import BrightTheme

from whad.cli.app import run_app
from whad.common.pcap import extract_pcap_metadata

from whad.device import Device
from whad.exceptions import WhadDeviceNotFound, WhadDeviceError
from whad.tools.utils import list_implemented_sniffers
from whad.tools.wsniff import WhadSniffApp

logger = logging.getLogger(__name__)

class WhadPlayApp(WhadSniffApp):
    """wsniff main CLI application class.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD play tool',
            interface=False,
            pcap_argument=True
        )

        self.add_argument(
            "--flush",
            dest="flush",
            action="store_true",

        )

        # Initialize PCAP file path.
        self.pcap_file = None

    def infer_domain_from_pcap(self):
        """Infer target domain from PCAP file.

        PCAP file `reserved1` field is used by WHAD to store the domain name
        in order to use it later for replay or injection. If this information
        is not present in the provided PCAP file, user is requested to specify
        it through command-line.
        """
        self.pcap_file = None
        index_pcap_file = None
        override_domain = False
        for i, arg in enumerate(sys.argv):
            if ".pcap" in arg:
                self.pcap_file = arg
                index_pcap_file = i
            elif arg in list_implemented_sniffers():
                override_domain = True
        if index_pcap_file is not None and not override_domain:
            if os.path.exists(self.pcap_file):
                domain = extract_pcap_metadata(self.pcap_file)
                if domain in list_implemented_sniffers():
                    sys.argv.insert(index_pcap_file + 1, domain)
                else:
                    self.error("You need to provide a domain")
                    sys.exit(1)
            else:
                self.error("PCAP file not found")
                sys.exit(1)

    def build_device_path(self):
        """Create our device path based on provided parameters.
        """
        return "pcap:" + ("flush:" if self.args.flush else "") + self.args.pcap

    def pre_run(self):
        """Pre-run operations: configure scapy theme.
        """

        # If no color is not selected, configure scapy color theme
        self.infer_domain_from_pcap()
        super().pre_run()

        if not self.args.nocolor:
            conf.color_theme = BrightTheme()

        if self.args.pcap is not None:
            self.interface = Device.create(self.build_device_path())

    def run(self):
        """Wrapper for our wplay utility, since we use a PCAP file rather than
        a compatible WHAD interface.
        """
        try:
            super().run()
        except WhadDeviceNotFound:
            self.error("PCAP file not found")
        except WhadDeviceError as err:
            # Generally raised when PCAP file is not supported
            self.error(err.message)

def wplay_main():
    """Launcher for wplay.
    """
    app = WhadPlayApp()
    run_app(app)
