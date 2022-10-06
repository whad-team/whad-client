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

        dev = WhadDevice.create("uart1")
        sniffer1 = Sniffer(dev)
        sniffer1.reactive_jam(pattern=b"\xe3\x47\x91", position=2, channel=37)
        while True:
            input()



    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
