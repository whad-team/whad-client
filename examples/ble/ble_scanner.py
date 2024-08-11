from whad.ble import Scanner
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create the device
            dev = WhadDevice.create(interface)

            # Create the Scanner connector
            scanner = Scanner(dev)

            # Start the scanner and iterate over devices
            scanner.start()
            for i in scanner.discover_devices():
                print(i)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
