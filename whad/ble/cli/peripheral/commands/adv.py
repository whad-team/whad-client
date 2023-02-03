"""BLE emulate command handler
"""
from binascii import unhexlify
from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble import AdvDataFieldList
from whad.ble.utils.att import UUID
from whad.ble.stack.att.exceptions import AttError
from whad.ble.stack.gatt.exceptions import GattTimeoutException

@command('ad')
def ad_handler(app, command_args):
    """Handle Advertising Data.

    <ansicyan><b>adv</b> <i>ACTION</i> <i>[PARAMS]</i></ansicyan>

    This command manipulates the peripheral's advertising data, allowing
    to add, remove and list every fields. The following <i>ACTION</i>s are
    supported:

    <b>add<b>: add a new field to the advertising data
    <b>remove<b>: remove an existing field from the advertising data
    <b>list</b>: list all the registered fields
    """
    pass

