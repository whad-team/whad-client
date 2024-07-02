"""BLE Interactive shell
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble import Scanner
from whad.ble.cli.central.shell import BleCentralShell

@command('interactive')
def interactive_handler(app, command_args):
    """interactive BLE shell

    <ansicyan><b>interactive</b></ansicyan>

    Starts an interactive shell and let you interact with a BLE WHAD device:
    - scan devices
    - connect to a device
    - list services and characteristics
    - read/write characteristics
    """
    # Launch an interactive shell
    myshell = BleCentralShell(app.interface)
    myshell.run()
