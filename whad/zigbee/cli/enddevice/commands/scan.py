"""ZigBee Scan command handler
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.dot15d4.address import Dot15d4Address
from whad.zigbee.connector.enddevice import EndDevice

@command('scan')
def scan_handler(app, command_args):
    """scan for ZigBee networks

    <ansicyan><b>scan</b></ansicyan>

    This command will scan for Zigbee networks and show them in a list.
    """
    # We need to have an interface specified
    if app.is_piped_interface():
        app.error('This command cannot be used chained with another whad tool.')
    elif app.interface is not None:
        # Switch to Zigbee End Device mode
        enddevice = EndDevice(app.interface)

        print_formatted_text(HTML('<ansigreen>Channel   PAN ID   Ext. PAN ID             Joining</ansigreen>'))
        enddevice.start()
        try:
            for network in enddevice.discover_networks():
                # Show network
                print(
                        network.channel," "*6,
                        hex(network.pan_id)," ",
                        Dot15d4Address(network.extended_pan_id),
                        "permitted" if network.is_joining_permitted() else "forbidden"
                )

        except KeyboardInterrupt as keybd_int:
            print('\rScan terminated by user')
        enddevice.stop()
    else:
        app.error('You need to specify an interface with option --interface.')
