import sys

from whad.ble import Sniffer
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create WHAD device from provided interface
            dev = WhadDevice.create(interface)

            # Create a Sniffer connector from the device
            sniffer = Sniffer(dev)

            # Configure the sniffer to keep only advertisements
            sniffer.configure(advertisements=True, connection=False)

            # Start the sniffer and iterate on received packets to display them
            sniffer.start()
            for pkt in sniffer.sniff(timeout=30.0):
                print(repr(pkt))

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
