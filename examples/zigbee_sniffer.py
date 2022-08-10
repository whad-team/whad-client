from whad.domain.zigbee import Sniffer
from whad.device.uart import UartDevice
from time import time,sleep
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target device
        device = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = UartDevice(device, 115200)
            sniffer = Sniffer(dev)
            #sniffer.channel = 14
            sniffer.start()
            while True:
                input()
                sniffer.send(Dot15d4(bytes.fromhex("618864472400008a5c480200008a5c1e5d28e1000000013ce801008d150001ea59de1f960eea8aee185a11893096414e05a243")),channel=11)
                print(":)")
            for i in sniffer.sniff():
                print(repr(i))
                print(raw(i).hex())



        except (KeyboardInterrupt, SystemExit):
            dev.close()
    else:
        print('Usage: %s [device]' % sys.argv[0])
