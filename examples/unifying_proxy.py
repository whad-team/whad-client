from whad.unifying import Dongle, Mouse
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.scapy.layers.esb import *
from whad.scapy.layers.unifying import *
from scapy.compat import raw
import sys,time

def showm(pkt):
    print("[mouse]", pkt.metadata, repr(pkt))

def showd(pkt):
    print("[dongle]", pkt.metadata, repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 3:
        # Retrieve target interface
        interface1 = sys.argv[1]
        interface2 = sys.argv[2]

        # Connect to target device and performs discovery
        try:
            dev1 = WhadDevice.create(interface1)
            dev2 = WhadDevice.create(interface2)
            mouse = Mouse(dev1)
            dongle = Dongle(dev2)


            mouse.attach_callback(showm)
            dongle.attach_callback(showd)

            mouse.start()
            mouse.channel = 5
            mouse.address =  "ca:e9:06:ec:a4"
            dongle.address = "ca:e9:06:ec:a4"

            mouse.synchronize()

            dongle.channel = mouse.channel
            dongle.start()

            mouse.channel = 5
            mouse.lock()

            input()
            dongle.auto(False)
            dongle.send(ESB_Hdr()/ESB_Payload_Hdr()/Logitech_Unifying_Hdr()/Logitech_Keepalive_Payload(timeout=1))
            dongle.auto(True)

            input()
            mouse.unlock()

        except (KeyboardInterrupt, SystemExit):
            mouse.stop()
            dongle.stop()
            dev1.close()
            dev2.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device1] [device2]' % sys.argv[0])
