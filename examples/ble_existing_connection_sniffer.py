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
            """
            sniffer.configure(access_addresses_discovery=True)
            sniffer.start()
            for i in sniffer.sniff():
                print("[i] Access address found: ", repr(i))
            """
            #  [sniffer] Connection synchronized -> access_address=0x9096cd63, crc_init=0xa4f31c, hop_interval=36 (45000 us), hop_increment=13, channel_map=0xffffffff1f.


            sniffer.configure(active_connection=SynchronizedConnection(access_address=0x9096cd63, crc_init=0xa4f31c, channel_map=bytes.fromhex("ffefffff1f")))
            sniffer.start()
            for i in sniffer.sniff():
                print(i)

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
