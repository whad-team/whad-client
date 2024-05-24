"""WHAD server tool

This utility implements a server module, allowing to create a TCP proxy
which can be used to access a device remotely.
"""
import logging
from prompt_toolkit import print_formatted_text, HTML
import time
from whad.tools.whadsniff import display_packet
from whad.cli.app import CommandLinePipe
from scapy.all import *
from whad.common.ipc import IPCPacket
import sys
from json import JSONDecodeError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady
logger = logging.getLogger(__name__)

class WhadExtractApp(CommandLinePipe):

    def __init__(self):
        """Application uses an interface and has commands.
        """
        super().__init__(
            description='WHAD extraction tool',
            interface=True,
            commands=False
        )


        self.add_argument(
            '-l',
            '--layer',
            dest="layers",
            help='layer to extract',
            action="append",
            default=[]

        )

        self.add_argument(
            '-f',
            '--field',
            dest="fields",
            help='field to extract',
            action="append",
            default=[]
        )


    extractor_template = "lambda p : {}"


    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            if self.is_stdin_piped():

                while True:
                    dump = sys.stdin.readline()
                    try:
                        data = IPCPacket.from_dump(dump.replace("\n", ""))
                        display_values = {}
                        for layer in self.args.layers:
                            try:
                                layer_class = eval(layer)
                                if isinstance(layer_class, Packet_metaclass):
                                    try:
                                        display_values[layer] = data[layer_class]
                                    except IndexError:
                                        pass
                            except NameError:
                                pass

                        for field in self.args.fields:
                            found = False
                            nested_fields = field.split(".")
                            field_value = data
                            for nested_field in nested_fields:
                                if hasattr(field_value, nested_field):
                                    found = True
                                    field_value = getattr(field_value, nested_field)
                                elif isinstance(field_value, list):
                                        for item in field_value:
                                            if hasattr(item, nested_field):
                                                found = True
                                                field_value = getattr(item, nested_field)
                                                break
                                            else:
                                                found = False
                                else:
                                    found = False
                            if found:
                                display_values[field] = field_value
                        arglist = sys.argv[1:]
                        for arg in arglist:
                            if arg.startswith("-"):
                                arglist.remove(arg)

                        if len(display_values.values()) > 0:
                            sys.stdout.write(" ".join(repr(display_values[i]) for i in arglist if i in display_values)) # preserve order
                            sys.stdout.write("\n")
                            sys.stdout.flush()
                    except JSONDecodeError:
                        self.error("A decoding error occured, terminating.")
                        exit()
            else:
                self.error("This tool must be piped.")
        except KeyboardInterrupt:
            pass
        # Launch post-run tasks
        self.post_run()


def whadextract_main():
    app = WhadExtractApp()
    app.run()
