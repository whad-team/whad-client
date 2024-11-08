"""BLE profile command handler
"""
from json import loads, dumps
from binascii import hexlify
from argparse import Namespace

from prompt_toolkit import print_formatted_text, HTML

from whad.ble.profile.characteristic import CharacteristicProperties
from whad.cli.app import command, CommandLineApp
from whad.ble import Central, Scanner
from whad.ble.exceptions import ConnectionLostException, PeripheralNotFound
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error

# Expected parameters that must be passed to our program
# to use an already established connection
EXPECTED_BLE_PARAMS = [
    "initiator_bdaddr",
    "initiator_addrtype",
    "target_bdaddr",
    "target_addrtype",
    "conn_handle",
]

def profile_discover(app: CommandLineApp, device) -> bool:
    """Discover the GATT profile of a given device

    :param app: WHAD application instance
    :type app: :class:ẁhad.cli.app.CommandLineApp`
    :param device: Peripheral device to enumerate
    :type device: :class:`whad.ble.profile.PeripheralDevice`
    :return: `True` on success, `False` if an error occurred during profile discovery
    :rtype: bool
    """
    try:
        device.discover()
    except AttError as atterr:
        show_att_error(app, atterr)
        return False
    except GattTimeoutException:
        app.error("GATT Timeout while discovering services and characteristics. Aborted.")
        return False

    # Show discovered services and characteristics
    for service in device.services():
        print_formatted_text(HTML((
            "<ansicyan><b>Service {name}</b></ansicyan> "
            " (handle {handle} to {end_handle})"
            )).format(
                name=service.name, handle=service.handle,
                end_handle=service.end_handle
            )
        )

        # Loop on service characteristics
        for charac in service.characteristics():
            properties = charac.properties
            rights = ''
            if properties & CharacteristicProperties.READ != 0:
                rights += '<ansigreen>R</ansigreen>'
            if properties & CharacteristicProperties.WRITE != 0:
                rights += '<ansired>W</ansired>'
            if properties & CharacteristicProperties.WRITE_WITHOUT_RESPONSE != 0:
                rights += '<ansimagenta>W</ansimagenta>'
            if properties & CharacteristicProperties.INDICATE != 0:
                rights += '<ansicyan>I</ansicyan>'
            if properties & CharacteristicProperties.NOTIFY != 0:
                rights += '<ansiblue>N</ansiblue>'

            # Print characteristic properties
            print_formatted_text(
                HTML("  <b>{name}</b> %s, handle {handle}, value handle: {value_handle}" % rights)
                    .format(
                        name=charac.name,
                        rights=rights,
                        handle=charac.handle,
                        value_handle=charac.value_handle
                    )
            )

            # Display descriptors
            for desc in charac.descriptors():
                print_formatted_text(
                    HTML("    <ansiblue>Descriptor type {name}</ansiblue>, handle: {handle}")
                        .format(name=desc.name, handle=desc.handle)
                )

        print('')

    # Success
    return True

def profile_export(app, command_args: list, device, device_metadata: dict):
    """Export a discovered GATT profile into a JSON file.
    """
    # Load GATT profile JSON data
    json_data = device.export_json()
    profile = loads(json_data)

    # Add specific device info (for emulating)
    profile['devinfo'] = device_metadata
    json_data = dumps(profile)
    try:
        print(f"Writing profile JSON data to {command_args[0]} ...")
        with open(command_args[0], 'w', encoding='utf-8') as profile:
            profile.write(json_data)
    except IOError:
        app.error("An error occured when writing to %s", command_args[0])

@command('profile')
def profile_handler(app, command_args):
    """discover services and characteristics
    
    <ansicyan><b>profile</b> <i>[JSON_PROFILE]</i></ansicyan>

    This command connects to a target device, discover its services and characteristics,
    and optionnaly exports the device's profile into a <i>JSON_PROFILE</i> file. This JSON
    file may be used later for emulating a similar device with the exact same properties
    and profile, see <ansicyan>emulate</ansicyan> command.
    """
    # We need to have an interface specified
    if app.interface is not None and app.args.bdaddr is not None:

        print(f"Searching for target device {app.args.bdaddr} ...")

        # Switch to Scanner mode, search our device
        scanner = Scanner(app.interface)
        scanner.start()

        device = None
        for scanned_device in scanner.discover_devices(timeout=30.0):
            if scanned_device.address.lower() == app.args.bdaddr.lower():
                device = scanned_device
                if device.got_scan_rsp:
                    break

        # Check device is our device
        if device is None:
            # Stop scanner
            scanner.stop()

            # Display error message
            app.error(f"BLE peripheral {app.args.bdaddr} cannot be found.")
            return

        # Generate device advertising information
        device_metadata = {
            'adv_data': hexlify(device.adv_records.to_bytes()).decode('utf-8'),
            'bd_addr': str(device.address),
            'addr_type': device.address_type,
            'scan_rsp': None
        }
        if device.scan_rsp_records is not None:
            device_metadata['scan_rsp'] = (
                hexlify(device.scan_rsp_records.to_bytes()).decode('utf-8')
            )

        scanner.stop()

        # Switch to central mode
        central = Central(app.interface)
        central.start()

        try:
            print("Connecting to target device ...")

            # Connect to target device
            device = central.connect(app.args.bdaddr, random=app.args.random)
            if device is None:
                app.error("Cannot connect to %s, device does not respond.", app.args.bdaddr)
            else:
                try:
                    print("Enumerating services and characteristics ...")
                    # Perform profile discovery
                    result = profile_discover(app, device)

                    # Export profile to JSON file if required
                    if result and len(command_args) >= 1:
                        # Load GATT profile JSON data
                        json_data = device.export_json()
                        profile = loads(json_data)

                        # Add specific device info (for emulating)
                        profile['devinfo'] = device_metadata
                        json_data = dumps(profile)
                        try:
                            print(f"Writing profile JSON data to {command_args[0]} ...")
                            with open(command_args[0], 'w', encoding='utf-8') as profile:
                                profile.write(json_data)
                        except IOError:
                            app.error(f"An error occured when writing to {command_args[0]}")

                    # Disconnect
                    device.disconnect()
                except ConnectionLostException:
                    app.error("BLE device disconnected during discovery.")

        except PeripheralNotFound:
            app.error(f"BLE peripheral {app.args.bdaddr} cannot be found.")

        # Terminate central
        central.stop()

    # Piped interface
    elif app.args.bdaddr is None and app.is_piped_interface():

        # Make sure we have all the required parameters
        for param in EXPECTED_BLE_PARAMS:
            if not hasattr(app.args, param):
                app.error("Source interface does not provide a BLE connection")

        initiator = BDAddress(str(app.args.initiator_bdaddr),
                              addr_type=int(app.args.initiator_addrtype))
        advertiser = BDAddress(str(app.args.initiator_bdaddr),
                               addr_type=int(app.args.initiator_addrtype))
        existing_connection = Namespace(
            initiator=initiator.value,
            init_addr_type=int(app.args.initiator_addrtype),
            advertiser=advertiser.value,
            adv_addr_type=int(app.args.target_addrtype),
            conn_handle=int(app.args.conn_handle)
        )

        central = Central(app.input_interface, existing_connection)
        device = central.peripheral()

        try:
            # Read GATT characteristic
            profile_discover(app, device)

            # Export profile to JSON file if required
            if len(command_args) >= 1:
                app.warning("Cannot create profile file when chained.")

        except ConnectionLostException:
            app.error("BLE device disconnected during discovery.")
    else:
        app.error("You need to specify a target device with option --bdaddr.")
