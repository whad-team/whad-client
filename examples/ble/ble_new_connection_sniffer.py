from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            # Create WHAD device from provided interface
            dev = WhadDevice.create(interface)

            # Create Sniffer connector & configure it for connection only
            sniffer = Sniffer(dev)
            sniffer.configure(advertisements=False, connection=True)

            # Iterate over received traffic
            sniffer.start()
            for i in sniffer.sniff():
                print(i.metadata, repr(i))


        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
