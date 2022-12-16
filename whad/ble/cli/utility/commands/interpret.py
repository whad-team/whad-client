"""Implement the interpret command
"""
from os.path import exists, isfile
from prompt_toolkit import print_formatted_text, HTML
from whad.cli.app import command
from whad.ble.cli.utility.interpreter import interpret_pcap

@command('interpret')
def interpret_handler(app, command_args):
    """interpret a PCAP file

    <ansicyan><b>interpret <i>pcap_file</i></b></ansicyan>

    Parses and interpret a PCAP file containing BLE packets.
    """
    if len(command_args) >= 1:
        pcap_file = command_args[0]
        if exists(pcap_file) and isfile(pcap_file):
            # Allright, launch the interpeter
            interpret_pcap(pcap_file)
        else:
            app.error('Cannot access provided PCAP file.')
    else:
        app.error('No pcap file given.')