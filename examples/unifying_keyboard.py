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


            #connector.key = bytes.fromhex("08f59b42d06fd3bdc588cd4d1c244018")
            #connector.aes_counter = 0
            #connector.attach_callback(show, on_reception=True, on_transmission=False)

            connector = Keyboard(dev)
            connector.start()
            # Select a specific address
            connector.address = "ca:e9:06:ec:a4"

            # Synchronize with the dongle
            connector.synchronize()

            # Lock the dongle on the current channel
            connector.lock()

            # Acts as a keyboard
            time.sleep(1)
            connector.volume_up()
            time.sleep(1)
            connector.volume_down()
            time.sleep(1)
            connector.volume_toggle()
            time.sleep(1)
            connector.volume_toggle()
            time.sleep(1)
            connector.send_text("Hello world !")
            time.sleep(1)
            connector.send_key("ENTER")
            connector.unlock()
            connector.stop()
        except (KeyboardInterrupt, SystemExit):
            connector.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
