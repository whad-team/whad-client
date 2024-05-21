from whad.device import WhadDevice
from whad.rf4ce import Controller
from whad.dot15d4.address import Dot15d4Address
from whad.common.monitors import WiresharkMonitor
from whad.rf4ce.stack.apl.profiles import MSOProfile
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys
import logging
from time import sleep

def show(pkt):
    #if hasattr(pkt, "metadata"):
    #print(bytes(pkt).hex(), repr(pkt))
    pass
if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            mso = MSOProfile()
            controller = Controller(dev, profiles=[mso])
            controller.set_channel(15)
            controller.attach_callback(show)
            monitor.attach(controller)
            monitor.start()
            controller.start()

            print(controller.discovery())
            input()
            controller.set_channel(15)
            '''
            print(controller.stack.get_layer('nwk').get_service('management').pair_request(
                    destination_pan_id=0x269a,
                    destination_ieee_address=Dot15d4Address("c5:92:a7:d2:59:d1:19:c4").value
                )
            )
            '''
            mso.bind(Dot15d4Address("c5:92:a7:d2:59:d1:19:c4").value, 0x269a)
            #target.discovery_response(True, destination_address="C4:19:D1:AE:35:0D:70:02")
            input()

            while True:
                mso.send_audio("/tmp/trololo.wav")
                input()

            while True:
                print("> ", end="")
                string = input()
                for s in string:
                    mso.send_key(s)
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
