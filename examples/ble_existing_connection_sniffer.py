from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)


            # Access address discovery
            sniffer.configure(access_addresses_discovery=True)
            sniffer.start()
            for i in sniffer.sniff():
                print("[i] Access address found: ", repr(i))
            """
            sniffer.configure(active_connection=0xee8b0570)
            sniffer.start()
            while True:
                sleep(1)
            """
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
