from whad.device import WhadDevice
from whad.zigbee import EndDevice
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
import sys

def show(pkt):
    if hasattr(pkt, "metadata"):
        print(pkt.metadata, bytes(pkt).hex(), repr(pkt))

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            dev = WhadDevice.create(interface)
            connector = EndDevice(dev)
            input()
            connector.attach_callback(show)
            connector.start()
            print(connector.stack.get_layer('nwk').get_service("management").network_discovery())
            while True:
                input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
