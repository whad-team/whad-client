from whad.esb import ESB
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            connector = ESB(dev)
            connector.sniff_esb(channel=5, address="ca:e9:06:ec:a4")
            connector.start()
            input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
