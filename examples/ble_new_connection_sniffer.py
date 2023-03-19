from whad.ble import Sniffer
from whad.ble.utils.analyzer import GATTServerDiscovery
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request
import sys
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

            analyzer = GATTServerDiscovery()
            sniffer = Sniffer(dev)
            sniffer.configure(advertisements=False, connection=True)
            sniffer.start()
            for i in sniffer.sniff():
                print(i.metadata, repr(i))
                analyzer.process_packet(i)
                if analyzer.triggered:
                    print("triggered")

                if analyzer.completed:
                    print("completed")


        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
