from whad.unifying import Dongle
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys,time

def show(pkt):
    print(pkt.metadata, repr(pkt))

def show_key(key):
    print("We received a new keystroke: ", key)
    return False

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)

            connector = Dongle(dev, on_keystroke=show_key)
            #connector.attach_callback(show, on_reception=True, on_transmission=False)

            connector.address = "9b:0a:90:42:99"
            connector.key = bytes.fromhex("08f59b42156fa86c4288b64d02ca4006")
            #connector.address = "ca:e9:06:ec:a4"
            connector.channel = 8
            connector.start()
            connector.wait_wakeup()
            #connector.wait_synchronization()
            input()
            for i in connector.stream():
                print(i)
            while True:
                time.sleep(1)
        except (KeyboardInterrupt, SystemExit):
            connector.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
