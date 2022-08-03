from whad.domain.zigbee import Sniffer
from whad.device.uart import UartDevice
from time import time,sleep
from scapy.compat import raw
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target device
        device = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = UartDevice(device, 115200)
            sniffer = Sniffer(dev)
            sniffer.channel = 25
            sniffer.start()
            for i in sniffer.sniff():
                print(repr(i))
                print(raw(i).hex())



        except (KeyboardInterrupt, SystemExit):
            dev.close()
    else:
        print('Usage: %s [device]' % sys.argv[0])
