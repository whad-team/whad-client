from whad.zigbee import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.common.monitors import PcapWriterMonitor, WiresharkMonitor
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
            monitor = WiresharkMonitor()
            monitor.attach(sniffer)
            monitor.start()
            sniffer.channel = 16
            sniffer.start()
            for i in sniffer.sniff():
                print(i.metadata, repr(i))



        except (KeyboardInterrupt, SystemExit):
            monitor.detach()
            monitor.close()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
