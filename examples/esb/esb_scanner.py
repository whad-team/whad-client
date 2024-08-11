from whad.esb import Scanner
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import ESB_Hdr
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create a Whad Device
            dev = WhadDevice.create(interface)

            # Instantiate a Scanner connector
            connector = Scanner(dev)
            connector.start()

            # Iterate over discovered devices
            for d in connector.discover_devices():
                print(d)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
