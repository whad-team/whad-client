"""BLE characteristic write command handler
"""
from binascii import unhexlify, Error as BinasciiError

from whad.cli.app import command
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.profile.attribute import UUID, InvalidUUIDException
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error, create_central

# Expected parameters that must be passed to our program
# to use an already established connection
EXPECTED_BLE_PARAMS = [
    "initiator_bdaddr",
    "initiator_addrtype",
    "target_bdaddr",
    "target_addrtype",
    "conn_handle",
]

@command('write')
def write_handler(app, command_args):
    """write data to a a GATT attribute

    <ansicyan><b>write</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

    Write data to the specified GATT attribute (identified by its handle) or to
    a characteristic value (identified by its UUID, if unique).

    Data can be provided hex-encoded if prefixed by "hex":

    > write 41 hex 41 42 43

    The command above will write 'ABC' to attribute identified by the handle 41.
    
    Data can also be provided as text:

    > write 41 ABC

    """
    if app.is_piped_interface():
        # Make sure we have all the required parameters
        for param in EXPECTED_BLE_PARAMS:
            if not hasattr(app.args, param):
                app.error("Source interface does not provide a BLE connection")

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=True)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        device = central.peripheral()

        # Read GATT characteristic
        perform_write(
            app,
            device,
            command_args,
            without_response=False,
            profile_loaded=profile_loaded
        )

    # We need to have an interface specified
    elif app.interface is not None and app.args.bdaddr is not None:

        # Make sure BD address is valid
        if not BDAddress.check(app.args.bdaddr):
            app.error("Invalid BD address: %s", app.args.bdaddr)
            return

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=False)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        # Start central
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr, random=app.args.random)
        if device is None:
            app.error("Cannot connect to %s, device does not respond.", app.args.bdaddr)
        else:
            # Perform write
            perform_write(
                app,
                device,
                command_args,
                without_response=False
            )

        # Disconnect
        device.disconnect()
        central.stop()
    else:
        app.error("You need to specify a target device with option --bdaddr.")


@command('writecmd')
def writecmd_handler(app, command_args):
    """write data to a a GATT attribute without (no response)

    <ansicyan><b>writecmd</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

    Write data to the specified GATT attribute (identified by its handle) or to
    a characteristic value (identified by its UUID, if unique) without waiting
    for a response.

    Data can be provided hex-encoded if prefixed by "hex":

    > writecmd 41 hex 41 42 43

    The command above will write 'ABC' to attribute identified by the handle 41.
    
    Data can also be provided as text:

    > writecmd 41 ABC
    """
    if app.is_piped_interface():
        # Make sure we have all the required parameters
        for param in EXPECTED_BLE_PARAMS:
            if not hasattr(app.args, param):
                app.error("Source interface does not provide a BLE connection")

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=True)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        device = central.peripheral()

        # Read GATT characteristic
        perform_write(
            app,
            device,
            command_args,
            without_response=True,
            profile_loaded=profile_loaded
        )

        # Disconnect
        device.disconnect()
        central.stop()

    # We need to have an interface specified
    elif app.interface is not None and app.args.bdaddr is not None:

        # Make sure BD address is valid
        if not BDAddress.check(app.args.bdaddr):
            app.error(f"Invalid BD address: {app.args.bdaddr}")
            return

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=False)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        # Switch to central mode
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr, random=app.args.random)
        if device is None:
            app.error(f"Cannot connect to {app.args.bdaddr}, device does not respond.")
        else:
            # Perform write
            perform_write(
                app,
                device,
                command_args,
                without_response=True
            )

            # Disconnect
            device.disconnect()

        # Stop central role
        central.stop()

    else:
        app.error("You need to specify a target device with option --bdaddr.")


def perform_write(app, device, args, without_response=False, profile_loaded=False):
    """Perform attribute/handle characteristic
    """
    # parse target arguments
    if len(args) <2:
        app.error(("You must provide at least a characteristic value handle"
                   "or characteristic UUID, and a value to write."))
        return
    else:
        handle = None
        offset = None
        uuid = None

    # Figure out what the handle is
    if args[0].lower().startswith('0x'):
        try:
            handle = int(args[0].lower(), 16)
        except ValueError:
            app.error("Wrong handle: %s", args[0])
            return
    else:
        try:
            handle = int(args[0])
        except ValueError:
            try:
                handle = UUID(args[0].replace('-',''))
            except InvalidUUIDException:
                app.error("Wrong UUID: %s", args[0])
                return

    # Do we have hex data ?
    if args[1].lower() == 'hex':
        # Decode hex data
        hex_data = ''.join(args[2:])
        try:
            char_value = unhexlify(hex_data.replace('\t',''))
        except BinasciiError:
            app.error("Provided hex value contains non-hex characters.")
            return
    else:
        char_value = args[1]

    if not isinstance(char_value, bytes):
        char_value = bytes(char_value,'utf-8')
  
    # Perform ATT write by handle
    if not isinstance(handle, UUID):
        try:
            if without_response:
                device.write_command(handle, char_value)
            else:
                device.write(handle, char_value)
        except AttError as att_err:
            show_att_error(app, att_err)
        except GattTimeoutException:
            app.error('GATT timeout while writing.')
    else:
        if not profile_loaded:
            # Perform discovery if required
            device.discover()

        # Search characteristic from its UUID
        target_charac = device.find_characteristic_by_uuid(handle)                       
        if target_charac is not None:
            try:
                if without_response:
                    target_charac.write(char_value, without_response=True)
                else:
                    target_charac.value = char_value
            except AttError as att_err:
                show_att_error(app, att_err)
            except GattTimeoutException:
                app.error('GATT timeout while writing.')
        else:
            app.error("No characteristic found with UUID %s", handle)
