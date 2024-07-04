"""Bluetooth Low Energy MitM tool

This utility will connect to a device and spawn a similar device that will act
as a proxy to the target device.
"""
from time import time
from hexdump import hexdump
from prompt_toolkit import print_formatted_text, HTML

from whad.ble import Scanner
from whad.device import WhadDevice
from whad.ble.tools.proxy import GattProxy, LinkLayerProxy
from whad.cli.app import CommandLineDeviceSource, run_app
from whad.hub.ble import Direction

import logging
logger = logging.getLogger(__name__)

class VerboseLLProxy(LinkLayerProxy):
    """Verbose link-layer proxy
    """

    def __init__(self, app, proxy=None, target=None, adv_data=None, scan_data=None, bd_address=None, spoof=False):
        """Initialize our parent class instance.
        """
        super().__init__(proxy=proxy, target=target, adv_data=adv_data, scan_data=scan_data, \
                         bd_address=bd_address, spoof=spoof)
        self.__app = app

    def on_connect(self):
        print_formatted_text(HTML(
            f"<ansimagenta>Remote device connected</ansimagenta>"
        ))

    def on_disconnect(self):
        print_formatted_text(HTML(
            f"<ansimagenta>Remote device disconnected</ansimagenta>"
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

    def __init__(self, app, proxy=None, target=None, adv_data=None, scan_data=None, bd_address=None, spoof=False, profile=None):
        """Initialize our parent class instance.
        """
        super().__init__(proxy=proxy, target=target, adv_data=adv_data, scan_data=scan_data, \
                         bd_address=bd_address, spoof=spoof, profile=profile)
        self.__app = app
        
    def on_characteristic_read(self, service, characteristic, value, offset=0, length=0):
        if offset > 0:
            print_formatted_text(HTML(
                f"&lt;&lt;&lt; <ansicyan>Characteristic {characteristic.uuid} read (offset: {offset})</ansicyan>"
            ))
        else:
            print_formatted_text(HTML(
                f"&gt;&gt;&gt; <ansicyan>Characteristic {characteristic.uuid} written</ansicyan>"
            ))            
        hexdump(value)

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
        if offset > 0:
            print_formatted_text(HTML(
                f"&lt;&lt;&lt; <ansicyan>Characteristic {characteristic.uuid} read (offset: {offset})</ansicyan>"
            ))
        else:
            print_formatted_text(HTML(
                f"&gt;&gt;&gt; <ansicyan>Characteristic {characteristic.uuid} written</ansicyan>"
            ))  
        hexdump(value)

    def on_characteristic_subscribed(self, service, characteristic, notification=False, indication=False):
        if notification:
            print_formatted_text(HTML(
                    f"[!] <ansicyan>Subscribed to notification for charac. {characteristic.uuid}</ansicyan>"
            ))
        if indication:
            print_formatted_text(HTML(
                    f"[!] <ansicyan>Subscribed to notification for charac. {characteristic.uuid}</ansicyan>"
            ))    

    def on_characteristic_unsubscribed(self, service, characteristic):
        print_formatted_text(HTML(
                f"[!] <ansicyan>Unubscribed from charac. {characteristic.uuid}</ansicyan>"
        ))

    def on_notification(self, service, characteristic, value):
        print_formatted_text(HTML(
            f"&lt;&lt;&lt; <ansicyan>[!] Notification for charac. {characteristic.uuid}:</ansicyan>"
        ))
        hexdump(value)

    def on_indication(self, service, characteristic, value):
        print_formatted_text(HTML(
            f"&lt;&lt;&lt; <ansicyan>[!] Indication for charac. {characteristic.uuid}:</ansicyan>"
        ))
        hexdump(value)

    def on_connect(self, conn_handle):
        print_formatted_text(HTML(
            f"<ansimagenta>Remote device connected</ansimagenta>"
        ))

    def on_disconnect(self, conn_handle):
        print_formatted_text(HTML(
            f"<ansimagenta>Remote device disconnected</ansimagenta>"
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
            "--output",
            dest="output",
            default=None,
            help="Output PCAP file path"
        )

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            # We need to have an interface specified
            if self.interface is not None:
                self.spawn_proxy()                
            else:
                self.error("You need to specify an interface with option --interface.")

        except KeyboardInterrupt as keybd:
            self.warning("ble-proxy stopped (CTL-C)")

        # Launch post-run tasks
        self.post_run()

    def spawn_proxy(self):
        """Create a GATT proxy
        """
        proxy_iface = WhadDevice.create(self.args.proxy_iface)
        adv_data = None
        scan_rsp = None
        
        # Start scanning, we are looking for our target device
        print(f"Scanning for target device (timeout: {self.args.timeout} seconds)...")
        scan_start_ts = time()
        scanner = Scanner(self.interface)
        scanner.start()
        for device in scanner.discover_devices():
            if device.address.lower() == self.args.bdaddr:
                if device.adv_records is not None and device.scan_rsp_records is not None:
                    adv_data, scan_rsp = device.adv_records.to_bytes(), device.scan_rsp_records.to_bytes()
                    break
                
            # Device search timeout reached, show warning and stop proxy
            if time() - scan_start_ts > self.args.timeout:
                self.warning("Target device not found, connection timeout exceeded.")
                return

        if adv_data is not None and scan_rsp is not None:
            if not self.args.linklayer:
                proxy = VerboseProxy(
                    self,
                    proxy_iface,
                    self.interface,
                    adv_data=adv_data,
                    scan_data=scan_rsp,
                    bd_address=self.args.bdaddr,
                    spoof=self.args.spoof
                )
            else:
                proxy = VerboseLLProxy(
                    self,
                    proxy=proxy_iface,
                    target=self.interface,
                    adv_data=adv_data,
                    scan_data=scan_rsp,
                    bd_address=self.args.bdaddr,
                    spoof=self.args.spoof
                )
            
            # Start our proxy
            proxy.start()

            # Set output PCAP file if provided\
            if self.args.output is not None:
                print("Setting a pcap monitor")
                pcap_mon = proxy.get_pcap_monitor(self.args.output)
                pcap_mon.start()
            else:
                pcap_mon = None

            # Create a Wireshark monitor
            if self.args.wireshark:
                ws_mon = proxy.get_wireshark_monitor()
                ws_mon.start()
            else:
                ws_mon = None
            
            print('Proxy is ready, press a key to stop.')
            input()

            # Stop Wireshark monitor
            if ws_mon is not None:
                ws_mon.stop()
                ws_mon.detach()
            
            # Stop PCAP monitor
            if pcap_mon is not None:
                pcap_mon.stop()
                pcap_mon.detach()


def ble_proxy_main():
    app = BleProxyApp()
    run_app(app)
