"""Logitech Unifying scanning tool

This utility finds any Logitech Unifying device and displays captured packets,
with a quick interpretation. It allows the user to quickly identify a mouse or
a keyboard based on the intepreted values.
"""
import logging

# Required to display colored texts
from prompt_toolkit import HTML, print_formatted_text

# Scapy
from scapy.packet import Packet

# Whad dependencies
from whad.cli.app import CommandLineDeviceSink, run_app
from whad.unifying.connector import Sniffer, ESBAddress
from whad.esb.exceptions import InvalidESBAddressException
from whad.scapy.layers.unifying import Logitech_Unifying_Hdr, \
    Logitech_Keepalive_Payload, Logitech_Mouse_Payload, \
    Logitech_Encrypted_Keystroke_Payload, Logitech_Unencrypted_Keystroke_Payload

# Logging
logger = logging.getLogger(__name__)

TOOL_DESCRIPTION="""This tool scans for Logitech Unifying devices and tries to classify them
based on the data they send. It can search for devices in automatic mode,
listen on a specific channel or target a specific device.
"""

class UniScanApp(CommandLineDeviceSink):
    """
    Unifying scanning application.

    This class inherits from `CommandLineDeviceSink` as it cannot be chained
    with another WHAD tool and will consume the data sent by a compatible
    device.
    """

    def __init__(self):
        """Application uses an interface and has no commands.
        """
        super().__init__(
            description=TOOL_DESCRIPTION,
            interface=True,
            commands=False
        )

        # Channel option
        self.add_argument(
            '-c',
            '--channel',
            metavar='CHANNEL',
            dest='channel',
            type=int,
            default=None,
            help="Find devices on channel CHANNEL"
        )

        # Target device address option
        self.add_argument(
            '-a',
            '--address',
            metavar='ADDRESS',
            dest='address',
            default=None,
            help="Follow a specific device with address ADDRESS"
        )


    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                # If an address is not provided, we scan for devices
                if self.args.address is None:
                    # Start scanning
                    self.scan()
                else:
                    # If an address is provided, we check its format and start
                    # sniffing packets from this device
                    try:
                        addr = ESBAddress(self.args.address)
                        self.sniff(addr)
                    except InvalidESBAddressException:
                        # Invalid device address
                        self.error('Target address does not match the expected format !')

            else:
                # Missing interface.
                self.error('You need to specify an interface with option --interface.')

        except KeyboardInterrupt:
            self.warning('wuni-scan stopped (CTL-C)')

        # Launch post-run tasks
        self.post_run()

    def sniff(self, address: ESBAddress):
        """Sniff packets set to the device identified by the provided Unifying
        address (5 bytes).
        """
        # Create our sniffer
        sniffer = Sniffer(self.interface)

        # Configure the target device address and channel. If channel is None,
        # the hardware will loop over the 100 possible channels.
        channel = self.args.channel
        if channel is not None and (channel < 0 or  channel > 100):
            self.error(f'Invalid channel value ({channel}). Channel must be in the 0-100 range.')

        # Start sniffing
        sniffer.channel = channel
        sniffer.start()

        # If no channel is specified, then automatically loop on all channels.
        if self.args.channel is None:
            print_formatted_text(HTML(
                'Following device <ansicyan>{address}</ansicyan> in auto mode ...'
            ).format(address=str(address)))
        else:
            print_formatted_text(HTML((
                "Sniffing device <ansicyan>{address}</ansicyan> "
                "on channel <ansicyan>{channel}</ansicyan>..."
                )).format(address=str(address), channel=self.args.channel))

        # Loop while CTL-C is not pressed, wait for a Unifying packet and display
        # it with a specific formatting.
        while True:
            for packet in sniffer.sniff():
                if Logitech_Unifying_Hdr in packet:
                    self.show_packet(packet)

    def scan(self):
        """Search for Logitech Unifying devices based on packets they send.
        If channel is specified, will lock on this channel and detect devices,
        otherwise the hardware will loop on all channels and will report any
        Unifying packet captured.
        """
        # Create our sniffer
        sniffer = Sniffer(self.interface)

        # Enable sniffing on our channel
        channel = self.args.channel
        if channel is not None and (channel < 0 or channel > 100):
            self.error(f'Invalid channel value ({channel}). Channel must be in the 0-100 range.')
            return
        sniffer.channel = channel
        sniffer.start()

        # Sniff packets and display them
        print('Scanning for Unifying devices on channels 0-100 ...')
        while True:
            for packet in sniffer.sniff():
                if Logitech_Unifying_Hdr in packet:
                    self.show_packet(packet)

    def show_packet(self, packet: Packet):
        """Display a Logitech Unifying packet with a short analysis.
        """
        # Extract Logitech Unifying payload
        payload = packet[Logitech_Unifying_Hdr]

        # Determine device type and generate comment
        comment = ''
        if Logitech_Mouse_Payload in packet:
            # Unencrypted mouse move, decode
            comment = '| <b>Mouse</b> (movement)'
        elif Logitech_Encrypted_Keystroke_Payload in packet:
            # Encrypted keystroke
            comment = '| <b>Keyboard</b> (encrypted keystroke)'
        elif Logitech_Unencrypted_Keystroke_Payload in packet:
            # Unencrypted keystroke
            comment = '| <b>Keyboard</b> <ansired>(unencrypted keystroke)</ansired>'
        elif Logitech_Keepalive_Payload in packet:
            # Unifying keep-alive
            comment = '| keep-alive'

        print_formatted_text(HTML((
            "<ansicyan>[{channel:03d}]</ansicyan><ansicyan>[{addr}]</ansicyan> "
            "<b>{payload}</b> %s" % comment
        )).format(channel=packet.metadata.channel,
                    addr=str(
                        packet.address if
                        hasattr(packet, "address") else
                        packet.metadata.address
                    ),
                    payload=bytes(payload).hex()))


def wuni_scan_main():
    """Logitech Unifying scanner main routine.
    """
    app = UniScanApp()
    run_app(app)
