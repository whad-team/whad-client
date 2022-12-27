from whad.unifying import Keyboard
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys,time

def show(pkt):
    print(pkt.metadata, repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Keyboard(dev)
            #connector.attach_callback(show, on_reception=False, on_transmission=True)
            connector.start()
            connector.channel = 5
            connector.address = "9b:0a:90:42:90"
            connector.synchronize()

            while True:
                time.sleep(1)
                connector.send_key("a")
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
