from whad.zigbee import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)
            sniffer.start()
            while True:
                input()
                sniffer.send(Dot15d4(bytes([0xa7,0x12, 0x61, 0x88, 0xf9, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0xd3, 0x00, 0x68, 0x65, 0x6c, 0x6c,  0x6f])),channel=12)
                print("Packet transmitted !")

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
