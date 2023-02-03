"""BLE Interactive shell
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble.cli.peripheral.shell import BlePeriphShell

@command('interactive')
def interactive_handler(app, command_args):
    """interactive BLE shell

    <ansicyan><b>interactive</b></ansicyan>

    Starts an interactive shell and let you create and advertise a BLE WHAD device:
    - create, list and remove services
    - create, list and remove characteristics
    - set characteristic value, send notifications/indications
    """
    # We need to have an interface specified
    if app.interface is not None:
        # Launch an interactive shell
        myshell = BlePeriphShell(app.interface)
        myshell.run()
    else:
        app.error('You need to specify an interface with option --interface.')