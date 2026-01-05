"""Bluetooth Low Energy clone utility for WHAD

$ ble-clone --dump [bd address] profile.json
$ ble-clone -i hci0 profile.json
"""
from time import time
from json import loads, dumps
from json.decoder import JSONDecodeError

from hexdump import hexdump
from prompt_toolkit import print_formatted_text, HTML

from whad.cli.app import CommandLineApp, run_app
from whad.ble import Peripheral, GenericProfile, AdvDataFieldList
from whad.ble.connector import Central, Scanner
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error
from whad.ble.profile.characteristic import CharacteristicProperties

def check_profile(profile):
    """Check profile validity.

    :param dict p: Profile
    :return bool: True if profile format is OK, False otherwise
    """
    # Make sure we have a 'devinfo' entry
    if 'devinfo' not in profile:
        return False

    # Make sure we have a valid adv_data entry
    if 'adv_data' not in profile['devinfo']:
        return False
    try:
        bytes.fromhex(profile["devinfo"]["adv_data"])
    except JSONDecodeError:
        return False
    except KeyError:
        return False
    except ValueError:
        return False

    # Make sure we have a valid scan_rsp entry (if provided)
    if 'scan_rsp' not in profile['devinfo']:
        return False
    if profile['devinfo']['scan_rsp'] is not None:
        try:
            bytes.fromhex(profile["devinfo"]["scan_rsp"])
        except JSONDecodeError:
            return False
        except KeyError:
            return False
        except ValueError:
            return False

    # Make sure we have a BD address
    if 'bd_addr' not in profile['devinfo']:
        return False

    # OK
    return True


class MonitoringProfile(GenericProfile):
    """Monitoring profile class used to display what is going with the emulated
    device.
    """


    def on_characteristic_read(self, service, characteristic, offset=0, length=0):
        """Characteristic read hook.

        This hook is called whenever a characteristic is about to be read by a GATT client.
        If this method returns a byte array, this byte array will be sent back to the
        GATT client. If this method returns None, then the read operation will return an
        error (not allowed to read characteristic value).
        

        :param BlePrimaryService service: Service owning the characteristic
        :param BleCharacteristic characteristic: Characteristic object
        :param int offset: Read offset (default: 0)
        :param int length: Max read length
        :return: Value to return to the GATT client
        """
        print_formatted_text(HTML((
            f"<ansigreen>Reading</ansigreen> characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(characteristic.value)

    def on_connect(self, conn_handle):
        print_formatted_text(HTML(
            "<ansired>New connection</ansired> handle:{conn_handle:d}"
        ))

    def on_disconnect(self, conn_handle):
        print_formatted_text(HTML(f"<ansired>Disconnection</ansired> handle:{conn_handle:d}"))

    def on_characteristic_written(self, service, characteristic, offset=0, value=b'',
                                  without_response=False):
        """Characteristic written hook

        This hook is called whenever a charactertistic has been written by a GATT
        client.
        """
        print_formatted_text(HTML((
            f"<ansimagenta>Wrote</ansimagenta> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)


    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        # Check if we have a hook to call
        print_formatted_text(HTML((
            f"<ansicyan>Subscribed</ansicyan> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))

    def on_characteristic_unsubscribed(self, service, characteristic):
        print_formatted_text(HTML((
            f"<ansicyan>Unsubscribed</ansicyan> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))

    def on_notification(self, service, characteristic, value):
        print_formatted_text(HTML((
            f"<ansicyan>Notification</ansicyan> from characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)

    def on_indication(self, service, characteristic, value):
        print_formatted_text(HTML((
            f"<ansicyan>Indication</ansicyan> from characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)

class BleCloneApp(CommandLineApp):
    """wble-clone CLI application class.
    """

    def __init__(self):
        super().__init__(
            description='WHAD Bluetooth Low Energy cloning utility',
            commands = False,
            interface = True
        )
        self.add_argument(
            '--dump',
            '-d',
            dest='dump',
            help='BD address of the device to dump'
        )
        self.add_argument('profile', metavar='PROFILE', help='Device profile file (JSON)')


    def dump_device(self, bdaddr, profile_path):
        """Create a dump of a device's profile
        """
        # Switch to Scanner mode, search our device
        scanner = Scanner(self.interface)
        scanner.start()

        start_time = time()
        device = None
        for dev in scanner.discover_devices():
            if dev.address.lower() == bdaddr.lower():
                if dev.got_scan_rsp or (time() - start_time) >= 10.0:
                    break

        # Device not found, stop
        if device is None:
            scanner.stop()
            return

        # Generate device advertising information
        if device.scan_rsp_records is not None:
            scan_rsp = device.scan_rsp_records.to_bytes().hex()
        else:
            scan_rsp = None

        device_metadata = {
            'adv_data': device.adv_records.to_bytes().hex(),
            'scan_rsp': scan_rsp,
            'bd_addr': str(device.address),
            'addr_type': device.address_type
        }
        scanner.stop()

        # Switch to central mode
        central = Central(self.interface)
        central.start()

        # Connect to target device
        device = central.connect(bdaddr)
        if device is None:
            self.error(f"Cannot connect to {bdaddr}, device does not respond.")
        else:
            # Perform profile discovery
            try:
                device.discover()
            except AttError as atterr:
                show_att_error(self, atterr)
                return
            except GattTimeoutException:
                self.error(
                    "GATT Timeout while discovering services and characteristics. Aborted."
                )
                return

            # Show discovered services and characteristics
            for service in device.services():
                print_formatted_text(HTML((
                    f"<ansicyan><b>Service {service.name}</b></ansicyan> "
                    f"(handle 0x{service.handle:04x} to 0x{service.end_handle:04x})"
                )))

                for charac in service.characteristics():
                    properties = charac.properties
                    rights = ''
                    if properties & CharacteristicProperties.READ != 0:
                        rights += '<ansigreen>R</ansigreen>'
                    if properties & CharacteristicProperties.WRITE != 0:
                        rights += '<ansired>W</ansired>'
                    if properties & CharacteristicProperties.INDICATE != 0:
                        rights += '<ansicyan>I</ansicyan>'
                    if properties & CharacteristicProperties.NOTIFY != 0:
                        rights += '<ansiblue>N</ansiblue>'

                    print_formatted_text(HTML((
                        f"  <b>{charac.name}</b> {rights}, handle 0x{charac.handle:x},"
                        f" value handle 0x{charac.value_handle:04x}"
                    )))

                    for desc in charac.descriptors():
                        print_formatted_text(HTML((
                           f"    Descriptor type {desc.type_uuid}, "
                           f"handle 0x{desc.handle:04x}"
                        )))
                print('')

            # Load GATT profile JSON data
            json_data = device.export_json()
            profile = loads(json_data)

            # Add specific device info (for emulating)
            profile['devinfo'] = device_metadata
            json_data = dumps(profile)
            try:
                print(f"Writing profile JSON data to {profile_path} ...")
                with open(profile_path, 'w', encoding="utf-8") as f:
                    f.write(json_data)
            except IOError:
                self.error(f"An error occurred when writing to {profile_path}")

            # Disconnect
            device.disconnect()

        # Terminate central
        central.stop()

    def run(self):
        """Override App's run() method to handle scripting feature.
        """
        # Launch pre-run tasks
        self.pre_run()

        if self.args.interface is None:
            self.error('You must provide a WHAD interface with the --interface option.')
        else:
            # If dump is enabled
            if self.args.dump is not None:
                if self.args.profile is not None:
                    self.dump_device(self.args.dump, self.args.profile)
                else:
                    self.error('You must provide a target file to store the device profile.')
            elif self.args.profile is not None:
                # Emulate device
                with open(self.args.profile, 'r', encoding="utf-8") as f:
                    profile_json = f.read()
                    profile = loads(profile_json)

                # Check profile and emulate if everything is OK
                if check_profile(profile):
                    # Load device info
                    device_adv_data = bytes.fromhex(profile["devinfo"]["adv_data"])
                    device_scan_rsp = bytes.fromhex(profile["devinfo"]["scan_rsp"])

                    # Create a profile
                    device_profile = MonitoringProfile(from_json = profile_json)
                    periph = Peripheral(
                        self.interface,
                        profile=device_profile,
                        adv_data=AdvDataFieldList.from_bytes(device_adv_data),
                        scan_data=AdvDataFieldList.from_bytes(device_scan_rsp),
                        #bd_address=profile['devinfo']['bd_addr']
                    )
                    periph.start()
                    print((
                        f"Emulation of device {profile['devinfo']['bd_addr']} is active,"
                        f" press any key to stop..."))
                    try:
                        input()
                    except KeyboardInterrupt:
                        pass
                    print('\rStopping emulation ...')
                    periph.stop()
                else:
                    self.error('Bad JSON file format')

        # Launch post-run tasks
        self.post_run()

def ble_clone_main():
    """BLE clone application.
    """
    app = BleCloneApp()
    run_app(app)
