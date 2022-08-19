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
            def show_packet(pkt):
                pkt.show()

            dev = WhadDevice.create(interface)
            sniffer = Sniffer(dev)
            sniffer.configure(advertisements=True, connection=False)

            sniffer.attach_callback(show_packet)
            sniffer.start()
            while True:
                sleep(0.1)



        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
