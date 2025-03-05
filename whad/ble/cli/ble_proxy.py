"""Bluetooth Low Energy MitM tool

This utility will connect to a device and spawn a similar device that will act
as a proxy to the target device.
"""
import logging

from hexdump import hexdump
from prompt_toolkit import print_formatted_text, HTML

from whad.ble import Scanner, BDAddress
from whad.device import WhadDevice
from whad.ble.tools.proxy import GattProxy, LinkLayerProxy
from whad.cli.app import CommandLineDeviceSource, run_app
from whad.hub.ble import Direction

logger = logging.getLogger(__name__)

class VerboseLLProxy(LinkLayerProxy):
    """Verbose link-layer proxy class.

    This class intercepts any BLE link-layer operation and displays it in terminal.
    """

    def on_connect(self):
        """Handle connection
        """
        print_formatted_text(HTML(
            "<ansimagenta>Remote device connected</ansimagenta>"
        ))

    def on_disconnect(self):
        """Handle disconnection.
        """
        print_formatted_text(HTML(
            "<ansimagenta>Remote device disconnected</ansimagenta>"
        ))

    def on_ctl_pdu(self, pdu, direction):
        """Display captured Control PDU"""
        if direction == Direction.MASTER_TO_SLAVE:
            print_formatted_text(HTML("&lt;&lt;&lt; <ansicyan>Control PDU</ansicyan>"))
        else:
            print_formatted_text(HTML("&gt;&gt;&gt; <ansicyan>Control PDU</ansicyan>"))
        hexdump(bytes(pdu))
        return super().on_ctl_pdu(pdu, direction)


    def on_data_pdu(self, pdu, direction):
        """Display captured data PDU"""
        if direction == Direction.MASTER_TO_SLAVE:
            print_formatted_text(HTML("&lt;&lt;&lt; <ansimagenta>Data PDU</ansimagenta>"))
        else:
            print_formatted_text(HTML("&gt;&gt;&gt; <ansimagenta>Data PDU</ansimagenta>"))
        hexdump(bytes(pdu))
        return super().on_data_pdu(pdu, direction)

class VerboseProxy(GattProxy):
    """Main BLE GATT proxy
    """

    def on_characteristic_read(self, service, characteristic, value, offset=0, length=0):
        """Triggered when a characteristic read.
        """
        if offset > 0:
            print_formatted_text(HTML((
                f"&lt;&lt;&lt; <ansicyan>Characteristic {characteristic.uuid} read "
                f"(offset: {offset})</ansicyan>"
            )))
        else:
            print_formatted_text(HTML(
                f"&gt;&gt;&gt; <ansicyan>Characteristic {characteristic.uuid} read</ansicyan>"
            ))
        hexdump(value)

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'',
                                without_response=False):
        """Triggered when a characteristic write.
        """
        if offset > 0:
            print_formatted_text(HTML((
                f"&lt;&lt;&lt; <ansicyan>Characteristic {characteristic.uuid} written "
                f"(offset: {offset})</ansicyan>"
            )))
        else:
            print_formatted_text(HTML(
                f"&gt;&gt;&gt; <ansicyan>Characteristic {characteristic.uuid} written</ansicyan>"
            ))
        hexdump(value)

    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        """Triggered when a GATT client subscribes to a characteristic.
        """
        if notification:
            print_formatted_text(HTML((
                    f"[!] <ansicyan>Subscribed to notification for charac. "
                    f"{characteristic.uuid}</ansicyan>"
            )))
        if indication:
            print_formatted_text(HTML((
                    f"[!] <ansicyan>Subscribed to indication for charac. "
                    f"{characteristic.uuid}</ansicyan>"
            )))

    def on_characteristic_unsubscribed(self, service, characteristic):
        """Triggered when a GATT client unsubscribes from a characteristic.
        """
        print_formatted_text(HTML(
                f"[!] <ansicyan>Unubscribed from charac. {characteristic.uuid}</ansicyan>"
        ))

    def on_notification(self, service, characteristic, value):
        """Triggered when a notification is received.
        """
        print_formatted_text(HTML((
            f"&lt;&lt;&lt; <ansicyan>[!] Notification for charac. "
            f"{characteristic.uuid}:</ansicyan>"
        )))
        hexdump(value)

    def on_indication(self, service, characteristic, value):
        """Triggered when a indication is received.
        """
        print_formatted_text(HTML((
            f"&lt;&lt;&lt; <ansicyan>[!] Indication for charac. "
            f"{characteristic.uuid}:</ansicyan>"
        )))
        hexdump(value)

    def on_connect(self, conn_handle):
        """Triggered when a remote device connects to our spoofed device.
        """
        super().on_connect(conn_handle)

        print_formatted_text(HTML(
            "<ansimagenta>Remote device connected</ansimagenta>"
        ))

    def on_disconnect(self, conn_handle):
        """Triggered when a remote device disconnects from our spoofed device.
        """
        print_formatted_text(HTML(
            "<ansimagenta>Remote device disconnected</ansimagenta>"
        ))

    def on_mtu_changed(self, mtu):
        print_formatted_text(HTML(
            f"<ansicyan>MTU changed to {mtu}"
        ))

class BleProxyApp(CommandLineDeviceSource):
    """Bluetooth Low-Energy Proxy application

    This application provides a GATT proxy feature that allows the user to connect
    to a target device, discovers its services and characteristics and spawns a
    duplicate device and proxify any BLE operation to the target device.
    """

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD Bluetooth Low Energy proxy tool',
            interface=True,
            commands=False
        )

        self.add_argument("bdaddr", metavar="BDADDR", help="Target device BD address")

        # Add an optional random type argument
        self.add_argument(
            "-p",
            "--proxy-interface",
            dest="proxy_iface",
            type=str,
            required=True,
            help="Specify the WHAD interface to use for our spoofed device"
        )

        self.add_argument(
            "-t",
            "--timeout",
            dest="timeout",
            type=int,
            default=30,
            help="Scan timeout in seconds"
        )

        self.add_argument(
            "-w",
            "--wireshark",
            dest="wireshark",
            action="store_true",
            default=False,
            help="Enable real-time wireshark monitoring"
        )

        self.add_argument(
            "-s",
            "--spoof",
            dest="spoof",
            action="store_true",
            default=False,
            help="Enable BD address spoofing (if available)"
        )

        self.add_argument(
            "--link-layer",
            dest="linklayer",
            action="store_true",
            default=False,
            help="Enable link-layer mode"
        )

        self.add_argument(
            "-o",
            "--output",
            dest="output",
            default=None,
            help="Output PCAP file path"
        )

        self.proxy = None

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                if self.args.bdaddr is None:
                    self.error("Please provide a target BD address.")
                else:
                    self.spawn_proxy()
            else:
                self.error("You need to specify an interface with option --interface.")

        except KeyboardInterrupt:
            self.warning("wble-proxy stopped (CTL-C)")
            
            # Stop gracefully
            if self.proxy is not None:
                self.proxy.stop()

        # Launch post-run tasks
        self.post_run()

    def spawn_proxy(self):
        """Create a GATT proxy
        """
        # Exit if proxy interface not specified
        if self.args.proxy_iface is None:
            return

        proxy_iface = WhadDevice.create(self.args.proxy_iface)
        target = None

        # Start scanning, we are looking for our target device
        print(f"Scanning for target device (timeout: {self.args.timeout} seconds)...")
        scanner = Scanner(self.interface)
        scanner.start()
        for device in scanner.discover_devices(timeout=self.args.timeout):
            if device.address.lower() == self.args.bdaddr.lower():
                if device.adv_records is not None and device.scan_rsp_records is not None:
                    target = device
                    #adv_data = device.adv_records.to_bytes()
                    #scan_rsp = device.scan_rsp_records.to_bytes()
                    break

        # Device search timeout reached, show warning and stop proxy
        if target is None:
            self.warning("Target device not found, connection timeout exceeded.")
            scanner.stop()
            return

        # Stop scanning
        scanner.stop()

        # Display target device info
        addr_type = "random" if target.address_type == BDAddress.RANDOM else "public"
        print(f"Found target device {target.address} ({addr_type})")

        if target is not None:
            if not self.args.linklayer:
                self.proxy = VerboseProxy(
                    proxy_iface,
                    self.interface,
                    adv_data=target.adv_records.to_bytes(),
                    scan_data=target.scan_rsp_records.to_bytes(),
                    bd_address=self.args.bdaddr.lower(),
                    spoof=self.args.spoof,
                    random=(target.address_type == BDAddress.RANDOM)
                )
            else:
                self.proxy = VerboseLLProxy(
                    proxy=proxy_iface,
                    target=self.interface,
                    adv_data=target.adv_records.to_bytes(),
                    scan_data=target.scan_rsp_records.to_bytes(),
                    bd_address=self.args.bdaddr.lower(),
                    spoof=self.args.spoof,
                    random=(target.address_type == BDAddress.RANDOM)
                )

            # Start our proxy
            self.proxy.start()

            # Set output PCAP file if provided
            if self.args.output is not None:
                pcap_mon = self.proxy.get_pcap_monitor(self.args.output)
                pcap_mon.start()
            else:
                pcap_mon = None

            # Create a Wireshark monitor
            if self.args.wireshark:
                ws_mon = self.proxy.get_wireshark_monitor()
                ws_mon.start()
            else:
                ws_mon = None

            print('Proxy is ready, press a key to stop.')
            input()

            # Stop proxy
            self.proxy.stop()
            self.proxy = None

            # Stop Wireshark monitor
            if ws_mon is not None:
                ws_mon.stop()
                ws_mon.detach()

            # Stop PCAP monitor
            if pcap_mon is not None:
                pcap_mon.stop()
                pcap_mon.detach()


def ble_proxy_main():
    """Launcher for wble-proxy.
    """
    app = BleProxyApp()
    run_app(app)
