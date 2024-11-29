from whad.device import WhadDevice
from whad.wirelesshart.connector import Sniffer
from whad.common.monitors import WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys
from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            #monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)
            # Instantiate a sniffer
            sniffer = Sniffer(dev)

            # Attach & start the wireshark monitor
            #monitor.attach(sniffer)
            #monitor.start()

            # Synchronize the sniffer
            sniffer.synchronize(0, 10)
            while True:
                sleep(1)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
