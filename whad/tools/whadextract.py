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
            '-f',
            '--field',
            dest="fields",
            help='field to extract',
            action="append"
        )


    extractor_template = "lambda p : {}"


    def run(self):
        # Launch pre-run tasks
        self.pre_run()
        try:
            while True:
                dump = sys.stdin.readline()
                data = IPCPacket.from_dump(dump.replace("\n", ""))
                fields_value = {}
                #print(self.args.fields)
                for field in self.args.fields:
                    nested_fields = field.split(".")
                    #print(nested_fields)
                    field_value = data
                    for nested_field in nested_fields:
                        #print('>>>>', data, nested_field)
                        if hasattr(field_value, nested_field):
                            field_value = getattr(field_value, nested_field)
                            #print(field_value)
                    fields_value[field] = field_value

                sys.stdout.write(" ".join(str(i) for i in fields_value.values()))

                sys.stdout.write("\n")
                sys.stdout.flush()#self.extractor_template, self.args.field, dump)
                    #display_packet(data, show_metadata=True, format="repr")
        except KeyboardInterrupt:
            pass
        # Launch post-run tasks
        self.post_run()


def whadextract_main():
    app = WhadExtractApp()
    app.run()
