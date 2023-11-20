"""BLE profile command handler
"""
import logging

from time import time, sleep
from json import loads, dumps
from binascii import hexlify
from prompt_toolkit import print_formatted_text, HTML
from argparse import Namespace

from whad.ble.profile.characteristic import CharacteristicProperties
from whad.cli.app import command
from whad.ble import Central, Scanner
from whad.ble.exceptions import ConnectionLostException
from whad.ble.bdaddr import BDAddress
from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error

def profile_discover(app, device):
    try:
        device.discover()
    except AttError as atterr:
        show_att_error(app, atterr)
        return
    except GattTimeoutException as timeout:
        app.error('GATT Timeout while discovering services and characteristics. Aborted.')
        return

    # Show discovered services and characteristics
    for service in device.services():
        print_formatted_text(HTML(
            '<ansicyan><b>Service %s</b></ansicyan> (handle %d to %d)' % (
                service.name,
                service.handle,
                service.end_handle
            )
        ))
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
            
            print_formatted_text(HTML(
                '  <b>%s</b> %s, handle %d, value handle: %d' % (
                    charac.name,
                    rights,
                    charac.handle,
                    charac.value_handle
                )
            ))

            for desc in charac.descriptors():
                print_formatted_text(HTML(
                    '    <ansiblue>Descriptor type %s</ansiblue>, handle: %d' % (
                        desc.name,
                        desc.handle
                    ) 
                ))
        print('')

def profile_export(app, command_args, device, device_metadata):
    # Load GATT profile JSON data
    json_data = device.export_json()
    profile = loads(json_data)

    # Add specific device info (for emulating)
    profile['devinfo'] = device_metadata
    json_data = dumps(profile)
    try:
        print('Writing profile JSON data to %s ...' % command_args[0])
        open(command_args[0], 'w').write(json_data)
    except IOError as ioerr:
        app.error('An error occured when writing to %s' % command_args[0])

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
        
        # Switch to Scanner mode, search our device
        scanner = Scanner(app.interface)
        scanner.start()

        start_time = time()
        for device in scanner.discover_devices():
            if device.address.lower() == app.args.bdaddr.lower():
                if device.got_scan_rsp or (time() - start_time) >= 10.0:
                    break

        # Generate device advertising information
        device_metadata = {
            'adv_data': hexlify(device.adv_records.to_bytes()).decode('utf-8'),
            'scan_rsp': hexlify(device.scan_rsp_records.to_bytes()).decode('utf-8') if device.scan_rsp_records is not None else None,
            'bd_addr': str(device.address),
            'addr_type': device.address_type
        }
        scanner.stop()

        # Switch to central mode
        central = Central(app.interface)
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr)
        if device is None:
            app.error('Cannot connect to %s, device does not respond.' % app.args.bdaddr)
        else:
            try:
                # Perform profile discovery
                profile_discover(app, device)

                # Export profile to JSON file if required
                if len(command_args) >= 1:
                    # Load GATT profile JSON data
                    json_data = device.export_json()
                    profile = loads(json_data)

                    # Add specific device info (for emulating)
                    profile['devinfo'] = device_metadata
                    json_data = dumps(profile)
                    try:
                        print('Writing profile JSON data to %s ...' % command_args[0])
                        open(command_args[0], 'w').write(json_data)
                    except IOError as ioerr:
                        app.error('An error occured when writing to %s' % command_args[0])

                # Disconnect
                device.disconnect()
            except ConnectionLostException as conn_lost:
                app.error('BLE device disconnected during discovery.')

        # Terminate central
        central.stop()
    
    # Piped interface
    elif app.args.bdaddr is None and app.is_piped_interface():

        # Make sure we have all the required parameters
        for param in ['initiator_bdaddr', 'initiator_addrtype', 'target_bdaddr', 'target_addrtype', 'conn_handle']:
            if not hasattr(app.args, param):
                app.error('Source interface does not provide a BLE connection')
        
        initiator = BDAddress(str(app.args.initiator_bdaddr), addr_type=int(app.args.initiator_addrtype))
        advertiser = BDAddress(str(app.args.initiator_bdaddr), addr_type=int(app.args.initiator_addrtype))
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
                app.warning('Cannot create profile file when chained.')

        except ConnectionLostException as conn_lost:
            app.error('BLE device disconnected during discovery.')

        central.stop()

    elif app.interface is None:
        # If stdin is piped, that means previous program has failed.
        # We display this warning only if the tool has been launched in
        # standalone mode
        if not app.is_stdin_piped():
            app.error('You need to specify an interface with option --interface.')
    else:
        app.error('You need to specify a target device with option --bdaddr.')