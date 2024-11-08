"""BLE Interactive shell
"""
from whad.cli.app import command
from whad.ble.cli.central.shell import BleCentralShell

@command('interactive')
def interactive_handler(app, _):
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
