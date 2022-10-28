from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
import sys

if __name__ == '__main__':
    # Connect to target device and performs discovery
    try:
        def show_packet(pkt):
            pkt.show()

        dev = WhadDevice.create("uart0")
        sniffer1 = Sniffer(dev)
        sniffer1.reactive_jam(pattern=b"\x04\x00\x0a", position=4, channel=0)
        while True:
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
