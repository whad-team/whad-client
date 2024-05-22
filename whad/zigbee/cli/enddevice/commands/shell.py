"""BLE Interactive shell
"""

from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.zigbee.cli.enddevice.shell import ZigbeeEndDeviceShell

@command('interactive')
def interactive_handler(app, command_args):
    """interactive Zigbee shell

    <ansicyan><b>interactive</b></ansicyan>

    Starts an interactive shell and let you interact with a Zigbee WHAD network:
    - scan networks
    - join a network
    - list applications and clusters
    - trigger actions
    """
    # We need to have an interface specified
    if app.interface is not None:
        # Launch an interactive shell
        myshell = ZigbeeEndDeviceShell(app.interface)
        myshell.run()
    else:
        # If stdin is piped, that means previous program has failed.
        # We display this warning only if the tool has been launched in
        # standalone mode
        if not app.is_stdin_piped():
            app.error('You need to specify an interface with option --interface.')
