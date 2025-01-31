from whad.device import WhadDevice
from whad.rf4ce import Controller
from whad.dot15d4.address import Dot15d4Address
from whad.common.monitors import WiresharkMonitor
from whad.rf4ce.stack.apl.profiles import MSOProfile
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys
import logging
from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:

            # Get the provided device
            dev = WhadDevice.create(interface)
            # Create a default MSO profile
            mso = MSOProfile()
            # Create a RF4CE controller
            controller = Controller(dev, profiles=[mso])
            controller.set_channel(15)
            controller.start()
            controller.stack.get_layer('nwk').get_service('management').discovery()

            # Bind with a specific target
            mso.bind(Dot15d4Address("c5:92:a7:d2:59:d1:19:c4").value, 0x269a)

            input()
            # Transmit an audio file using MSO profile
            mso.send_audio("/tmp/trololo.wav")

            # Transmit keystrokes according to user input
            while True:
                print("> ", end="")
                string = input()
                for s in string:
                    mso.send_key(s)
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
