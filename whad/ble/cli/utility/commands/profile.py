"""BLE profile command handler
"""
from time import time, sleep
from json import loads, dumps
from binascii import hexlify
from prompt_toolkit import print_formatted_text, HTML
from whad.ble.profile.characteristic import CharacteristicProperties
from whad.cli.app import command
from whad.ble import Central, Scanner
from hexdump import hexdump
from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.utility.helpers import show_att_error

@command('profile')
def profile_handler(app, command_args):
    """discover services and characteristics
    
    <ansicyan><b>profile</b> <i>([export file path])</i></ansicyan>

    This command connects to a target device, discover its services and characteristics,
    and optionnaly export the device's profile into a JSON file. This JSON file may be
    used later for emulating a similar device with the exact same properties and
    profile.
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
            # Perform profile discovery
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
                    '<ansicyan><b>Service %s</b></ansicyan> (handle 0x%04x to 0x%04x)' % (
                        service.uuid,
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
                    if properties & CharacteristicProperties.INDICATE != 0:
                        rights += '<ansicyan>I</ansicyan>'
                    if properties & CharacteristicProperties.NOTIFY != 0:
                        rights += '<ansiblue>N</ansiblue>'
                    
                    print_formatted_text(HTML(
                        '  <b>%s</b> %s, handle 0x%04x, value handle 0x%04x' % (
                            charac.uuid,
                            rights,
                            charac.handle,
                            charac.value_handle
                        )
                    ))

                    for desc in charac.descriptors():
                        print_formatted_text(HTML(
                           '    Descriptor type %s, handle 0x%04x' % (
                                desc.type_uuid,
                                desc.handle
                           ) 
                        ))
                print('')

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

        # Terminate central
        central.stop()

    elif app.interface is None:
        app.error('You need to specify an interface with option --interface.')
    else:
        app.error('You need to specify a target device with option --bdaddr.')