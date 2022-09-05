from whad.zigbee import EndDevice
from whad.zigbee.stack.mac.constants import MACScanType
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        # Connect to target device and performs discovery
        try:
            dev = WhadDevice.create(interface)
            endDevice = EndDevice(dev)
            endDevice.start()
            management_service, _ = endDevice.stack.mac_services
            print(management_service.scan())
            #management_service.associate(coordinator_pan_id=0xcb3a, coordinator_address=0xed23)

            input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
