from whad.device import WhadDevice
from whad.dot15d4 import Coordinator
from whad.exceptions import WhadDeviceNotFound
from whad.dot15d4.stack.mac import MACScanType
from whad.common.monitors import WiresharkMonitor
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
            monitor = WiresharkMonitor()
            dev = WhadDevice.create(interface)
            connector = Coordinator(dev)
            monitor.attach(connector)
            monitor.start()
            input()
            connector.attach_callback(show)
            connector.start()
            connector.start_beacon()
            while True:
                input()
        except (KeyboardInterrupt, SystemExit):
            monitor.stop()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
