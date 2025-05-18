from whad.ble import Sniffer
from whad.hub.ble import ChannelMap
from whad.ble.connector.sniffer import SynchronizedConnection
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

            # Configure the sniffer to synchronize on an existing connection
            sniffer = Sniffer(dev)

            sniffer.configure(
                active_connection = SynchronizedConnection(
                        access_address=0x9096cd63,
                        crc_init=0xa4f31c,
                        channel_map=ChannelMap.from_bytes(bytes.fromhex("ffefffff1f"))
                )
            )
            
            # Iterate over traffic
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
