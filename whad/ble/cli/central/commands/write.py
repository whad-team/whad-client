"""BLE characteristic write command handler
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble import Central
from binascii import unhexlify, Error as BinasciiError

from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.ble.cli.central.helpers import show_att_error

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
    # We need to have an interface specified
    if app.interface is not None and app.args.bdaddr is not None:
        
        # Switch to central mode
        central = Central(app.interface)
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr)
        if device is None:
            app.error('Cannot connect to %s, device does not respond.' % app.args.bdaddr)
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

    elif app.interface is None:
        app.error('You need to specify an interface with option --interface.')
    else:
        app.error('You need to specify a target device with option --bdaddr.')

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
    # We need to have an interface specified
    if app.interface is not None and app.args.bdaddr is not None:
        
        # Switch to central mode
        central = Central(app.interface)
        central.start()

        # Connect to target device
        device = central.connect(app.args.bdaddr)
        if device is None:
            app.error('Cannot connect to %s, device does not respond.' % app.args.bdaddr)
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
        central.stop()
        
    elif app.interface is None:
        app.error('You need to specify an interface with option --interface.')
    else:
        app.error('You need to specify a target device with option --bdaddr.')

def perform_write(app, device, args, without_response=False):
    """Perform attribute/handle characteristic
    """
    # parse target arguments
    if len(args) <2:
        app.error('You must provide at least a characteristic value handle or characteristic UUID, and a value to write.')
        return
    else:
        handle = None
        offset = None
        uuid = None

    # Figure out what the handle is
    if args[0].lower().startswith('0x'):
        try:
            handle = int(args[0].lower(), 16)
        except ValueError as badval:
            app.error('Wrong handle: %s' % args[0])
            return
    else:
        try:
            handle = int(args[0])
        except ValueError as badval:
            try:
                handle = UUID(args[0].replace('-',''))
            except:
                app.error('Wrong UUID: %s' % args[0])
                return

    # Do we have hex data ?
    if args[1].lower() == 'hex':
        # Decode hex data
        hex_data = ''.join(args[2:])
        try:
            char_value = unhexlify(hex_data.replace('\t',''))
        except BinasciiError as err:
            app.error('Provided hex value contains non-hex characters.')
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
        except GattTimeoutException as timeout:
            app.error('GATT timeout while writing.')
    else:
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
            except GattTimeoutException as timeout:
                app.error('GATT timeout while writing.')
        else:
            app.error('No characteristic found with UUID %s' % handle)