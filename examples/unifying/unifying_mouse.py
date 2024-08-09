from whad.unifying import Keylogger, Mouselogger, Mouse
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

        try:

            # Create the Whad device, emulate a mouse
            dev = WhadDevice.create(interface)
            connector = Mouse(dev)

            # Attach a callback to monitor received packets
            connector.attach_callback(show, on_reception=True, on_transmission=False)
            connector.start()

            # Configure channel & address
            connector.channel = None
            connector.address =  "ca:e9:06:ec:a4"

            # Synchronize with the dongle
            connector.synchronize()

            # Transmit mouse moves
            for _ in range(10):
                connector.move(-100, 0)
                time.sleep(1)

            connector.unlock()
            time.sleep(3)
            connector.lock()

            for _ in range(10):
                connector.move(100, 0)
                time.sleep(1)
            connector.stop()

        except (KeyboardInterrupt, SystemExit):
            connector.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
