from whad.ble import Sniffer
from whad.ble.connector.sniffer import SynchronizedConnection
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
            #[sniffer] Connection synchronized -> access_address=0xc8ab6bce, crc_init=0x0cca08, hop_interval=54 (67500 us), hop_increment=11, channel_map=0xffff0f0010.
            sniffer.configure(active_connection=SynchronizedConnection(access_address=0xc8ab6bce, crc_init=0x0cca08))
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
