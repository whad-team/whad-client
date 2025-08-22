"""BLE emulate command handler
"""
from json import loads

from prompt_toolkit import print_formatted_text, HTML

from hexdump import hexdump

from whad.cli.app import command
from whad.ble import Peripheral, GenericProfile, AdvDataFieldList

class MonitoringProfile(GenericProfile):
    """GATT monitoring profile.
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
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(characteristic.value)

    def on_connect(self, conn_handle):
        print_formatted_text(HTML(f"<ansired>New connection</ansired> handle:{conn_handle}"))

    def on_disconnect(self, conn_handle):
        print_formatted_text(HTML(f"<ansired>Disconnection</ansired> handle:{conn_handle}"))

    def on_characteristic_written(self, service, characteristic, offset=0, value=b'',
                                  without_response=False):
        """Characteristic written hook

        This hook is called whenever a charactertistic has been written by a GATT
        client.
        """
        print_formatted_text(HTML((
            f"<ansimagenta>Wrote</ansimagenta> to characteristic"
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)


    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        # Check if we have a hook to call
        print_formatted_text(HTML((
            f"<ansicyan>Subscribed</ansicyan> to characteristic"
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))

    def on_characteristic_unsubscribed(self, service, characteristic):
        print_formatted_text(HTML((
            f"<ansicyan>Unsubscribed</ansicyan> to characteristic"
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))

    def on_notification(self, service, characteristic, value):
        print_formatted_text(HTML((
            f"<ansicyan>Notification</ansicyan> from characteristic"
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)

    def on_indication(self, service, characteristic, value):
        print_formatted_text(HTML((
            f"<ansicyan>Indication</ansicyan> from characteristic"
            f"<ansicyan>{characteristic.uuid}</ansicyan>"
            f" of service <ansicyan>{service.uuid}</ansicyan>"
        )))
        hexdump(value)

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
    except ValueError:
        return False

    # Make sure we have a valid scan_rsp entry (if provided)
    if 'scan_rsp' not in profile['devinfo']:
        return False
    if profile['devinfo']['scan_rsp'] is not None:
        try:
            bytes.fromhex(profile["devinfo"]["scan_rsp"])
        except ValueError:
            return False

    # Make sure we have a BD address
    if 'bd_addr' not in profile['devinfo']:
        return False

    # OK
    return True



@command('emulate')
def emulate_handler(app, command_args):
    """emulate a device from an exported profile
    
    <ansicyan><b>emulate</b> <i>[profile JSON file]</i></ansicyan>

    This command will emulate a device from its exported GATT profile (using
    the <ansicyan>profile</ansicyan> command). It will try to spoof its BD address (if possible),
    and will expose the exact same services and characteristics as the original one.

    If a GATT client connects to the emulated device, all the operations will
    be logged and detailed.
    """
    # We need to have an interface specified
    if app.interface is not None:
        if len(command_args) >= 1:
            # Import profile JSON
            with open(command_args[0],'r', encoding="utf-8") as dev_profile:
                profile_json = dev_profile.read()
                profile = loads(profile_json)

            # Check profile and emulate if everything is OK
            if check_profile(profile):
                # Load device info
                device_adv_data = bytes.fromhex(profile["devinfo"]["adv_data"])
                device_scan_rsp = bytes.fromhex(profile["devinfo"]["scan_rsp"])

                # Create a profile
                device_profile = MonitoringProfile(from_json = profile_json)
                periph = Peripheral(
                    app.interface,
                    profile=device_profile,
                    adv_data=AdvDataFieldList.from_bytes(device_adv_data),
                    scan_data=AdvDataFieldList.from_bytes(device_scan_rsp),
                    bd_address=profile['devinfo']['bd_addr']
                )
                periph.start()
                print((f"Emulation of device {profile['devinfo']['bd_addr']} is active,"
                       f" press any key to stop..."))
                try:
                    input()
                except KeyboardInterrupt:
                    pass
                print("\rStopping emulation ...")
                periph.stop()
            else:
                app.error("Bad JSON file format")
        else:
            app.error("You must provide an exported profile file (JSON).")
