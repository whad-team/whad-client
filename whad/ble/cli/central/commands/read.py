"""BLE characteristic read command handler
"""
import logging
from hexdump import hexdump

from prompt_toolkit import print_formatted_text, HTML
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.profile.attribute import UUID, InvalidUUIDException
from whad.cli.app import command
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error, create_central

# Global logger
logger = logging.getLogger(__name__)

# Expected parameters that must be passed to our program
# to use an already established connection
EXPECTED_BLE_PARAMS = [
    "initiator_bdaddr",
    "initiator_addrtype",
    "target_bdaddr",
    "target_addrtype",
    "conn_handle",
]

def read_gatt_characteristic(app, command_args, device, profile_loaded=False):
    """Read the value of a GATT characteristic based on the given command arguments.

    :param command_args: arguments to pass to 'read'
    :type command_args: list
    :param device: Peripheral device from which the characteristic value has to be read
    :type device: :class:`whad.ble.profile.PeripheralDevice`
    :param profile_loaded: pre-loaded GATT profile
    :type profile_loaded: GattProfile 
    """
    # parse target arguments
    if len(command_args) == 0:
        app.error('You must provide at least a characteristic value handle or characteristic UUID.')
        return
    else:
        handle = None
        offset = None

    # figure out what the handle is
    if command_args[0].lower().startswith('0x'):
        try:
            handle = int(command_args[0].lower(), 16)
        except ValueError:
            app.error("Wrong handle: %s", command_args[0])
            return
    else:
        try:
            handle = int(command_args[0])
        except ValueError:
            try:
                handle = UUID(command_args[0].replace('-',''))
            except InvalidUUIDException:
                app.error("Wrong UUID: %s", command_args[0])
                return

    # Check offset and length
    if len(command_args) >= 2:
        try:
            offset = int(command_args[1])
        except ValueError:
            app.error("Wrong offset value, will use 0 instead.")
            offset = None

    # Perform characteristic read by handle
    if not isinstance(handle, UUID):
        try:
            value = device.read(handle, offset=offset)

            # Display result as hexdump
            if len(value) > 0:
                hexdump(value)
            else:
                print_formatted_text(HTML('<i>Empty data</i>'))

        except AttError as att_err:
            show_att_error(app, att_err)
        except GattTimeoutException:
            app.error("GATT timeout while reading.")

    else:
        if not profile_loaded:
            # Perform discovery if UUID is given
            device.discover()

        # Search characteristic from its UUID
        target_charac = device.find_characteristic_by_uuid(handle)                       
        if target_charac is not None:
            try:
                # Read data
                if offset is not None:
                    value = target_charac.read(offset=offset)
                else:
                    value = target_charac.read()

                # Display result as hexdump
                if len(value) > 0:
                    hexdump(value)
                else:
                    print_formatted_text(HTML('<i>Empty data</i>'))

            except AttError as att_err:
                show_att_error(app, att_err)
            except GattTimeoutException:
                app.error("GATT timeout while reading.")
        else:
            app.error("No characteristic found with UUID %s", handle)

@command('read')
def read_handler(app, command_args):
    """read a GATT attribute
    
    <ansicyan><b>read</b> <i>[UUID | handle] ([offset])</i></ansicyan>

    Read an attribute identified by its handle, or read the value of a characteristic
    identified by its UUID (if unique). An optional offset can be provided
    to start reading from the specified byte position (it will issue a
    <i>ReadBlob</i> operation).

    Result is displayed as an hexadecimal dump with corresponding ASCII text:

    $ whad-ble -i hci0 -b 00:11:22:33:44:55 read 42
    00000000: 74 68 69 73 20 69 73 20  61 20 74 65 73 74        this is a test
    """
    # We need to have an interface specified
    if app.interface is not None and app.args.bdaddr is not None:

        # Make sure BD address is valid
        if not BDAddress.check(app.args.bdaddr):
            app.error("Invalid BD address: %s", app.args.bdaddr)
            return

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=False)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        # Start central mode
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr, random=app.args.random)
        if device is None:
            app.error("Cannot connect to %s, device does not respond.", app.args.bdaddr)
        else:
            # Read GATT characteristic
            read_gatt_characteristic(app, command_args, device, profile_loaded)

            # Disconnect
            device.disconnect()

        # Terminate central
        central.stop()

    # Piped interface
    elif app.args.bdaddr is None and app.is_piped_interface():

        # Make sure we have all the required parameters
        for param in EXPECTED_BLE_PARAMS:
            if not hasattr(app.args, param):
                app.error("Source interface does not provide a BLE connection")

        # Create Central connector based on app configuration
        central, profile_loaded = create_central(app, piped=True)

        # If no connector returned, there was an error, simply exit.
        if central is None:
            return

        # Retrieve connected device
        device = central.peripheral()

        # Read GATT characteristic
        read_gatt_characteristic(app, command_args, device, profile_loaded)

        # Disconnect
        device.disconnect()
        central.stop()
        central.close()

    elif app.interface is not None:
        app.error("You need to specify a target device with option --bdaddr.")
