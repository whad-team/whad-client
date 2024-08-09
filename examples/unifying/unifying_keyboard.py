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

        try:
            # Create the device
            dev = WhadDevice.create(interface)

            # Emulate a keyboard
            connector = Keyboard(dev)
            connector.start()

            # Select a specific address
            connector.address = "ca:e9:06:ec:a4"

            # Program key and AES counter (by default, no encryption)
            #connector.key = bytes.fromhex("08f59b42c46f2a139688a44d69ac4066")
            #connector.aes_counter = 0

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
