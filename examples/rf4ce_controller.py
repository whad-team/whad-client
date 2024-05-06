from whad.device import WhadDevice
from whad.rf4ce import Controller
from whad.dot15d4.address import Dot15d4Address
from whad.common.monitors import WiresharkMonitor
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys
import logging

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata, bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            controller = Controller(dev)
            controller.set_channel(15)
            monitor.attach(controller)
            monitor.start()
            controller.start()

            print(controller.discovery())
            input()
            controller.set_channel(15)
            print(controller.stack.get_layer('nwk').get_service('management').pair_request(
                destination_pan_id=0x269a,
                destination_ieee_address=Dot15d4Address("c4:19:d1:59:d2:a7:92:c5").value
                )
            )
            #target.discovery_response(True, destination_address="C4:19:D1:AE:35:0D:70:02")
            input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
