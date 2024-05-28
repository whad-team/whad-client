"""Bluetooth Low Energy MitM tool

This utility will connect to a device and spawn a similar device that will act
as a proxy to the target device.
"""
from time import time
from hexdump import hexdump
from prompt_toolkit import print_formatted_text, HTML

from whad.ble import Scanner
from whad.device import WhadDevice
from whad.ble.tools.proxy import GattProxy
from whad.cli.app import CommandLineDeviceSource

import logging
logger = logging.getLogger(__name__)

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
                f"<<< <ansicyan>Characteristic {characteristic.uuid} read (offset: {offset})</ansicyan>"
            ))
        else:
            print_formatted_text(HTML(
                f">>> <ansicyan>Characteristic {characteristic.uuid} written</ansicyan>"
            ))            
        hexdump(value)

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
        if offset > 0:
            print_formatted_text(HTML(
                f"<<< <ansicyan>Characteristic {characteristic.uuid} read (offset: {offset})</ansicyan>"
            ))
        else:
            print_formatted_text(HTML(
                f">>> <ansicyan>Characteristic {characteristic.uuid} written</ansicyan>"
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
            f"<<< <ansicyan>[!] Notification for charac. {characteristic.uuid}:</ansicyan>"
        ))
        hexdump(value)

    def on_indication(self, service, characteristic, value):
        print_formatted_text(HTML(
            f"<<< <ansicyan>[!] Indication for charac. {characteristic.uuid}:</ansicyan>"
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
            action="store_true",
            default=False,
            help="Enable real-time wireshark monitoring"
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
            proxy = VerboseProxy(self, proxy_iface, self.interface, adv_data=adv_data, scan_data=scan_rsp, bd_address=self.args.bdaddr)
            proxy.start()
            if self.args.wireshark:
                ws_mon = proxy.get_wireshark_monitor()
                ws_mon.start()
            print('Proxy is ready, press a key to stop.')
            input()


def ble_proxy_main():
    app = BleProxyApp()
    app.run()
