from whad.domain.ble import Sniffer
from whad.device.adapters import UbertoothDevice
from time import time,sleep
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target device
        device = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = UbertoothDevice()
            sniffer = Sniffer(dev)
            sniffer.configure(advertisements=True, connection=False)
            '''
            sniffer.start()
            for i in sniffer.sniff():
                print(i.metadata, repr(i))
            '''


        except (KeyboardInterrupt, SystemExit):
            dev.close()
    else:
        print('Usage: %s [device]' % sys.argv[0])
