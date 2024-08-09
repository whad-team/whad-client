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

def show_mouse_move(x,y):
    print("We received a new mouse move: ", x,y)
    return False

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create a WHAD device
            dev = WhadDevice.create(interface)

            # Emulate a Unifying dongle, configure callbacks when a keystroke or a mouse move is detected
            connector = Dongle(dev, on_keystroke=show_key, on_move_mouse=show_mouse_move)

            # Configure the connector
            connector.address =  "ca:e9:06:ec:a4"
            connector.channel = 8

            connector.start()

            # Wait for synchronization
            connector.wait_synchronization()

            # Iterate over received packets
            for i in connector.stream():
                print(repr(i))

        except (KeyboardInterrupt, SystemExit):
            connector.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
