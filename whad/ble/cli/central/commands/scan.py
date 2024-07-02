"""BLE Scan command handler
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble import Scanner

@command('scan')
def scan_handler(app, command_args):
    """scan for BLE devices

    <ansicyan><b>scan</b></ansicyan>

    This command will scan for BLE devices and show them in a list.
    """
    # We need to have an interface specified
    if app.is_piped_interface():
        app.error('This command cannot be used chained with another whad tool.')        
    elif app.interface is not None:
        # Switch to BLE scan mode
        scanner = Scanner(app.interface)
    
        print_formatted_text(HTML('<ansigreen> RSSI Lvl  Type  BD Address        Extra info</ansigreen>'))
        scanner.start()
        try:
            for device in scanner.discover_devices():
                # Show device
                print(device)
        except KeyboardInterrupt as keybd_int:
            print('\rScan terminated by user')
        scanner.stop()
