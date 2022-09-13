from whad.zigbee import EndDevice
from whad.zigbee.stack.mac.constants import MACScanType
from whad.device import WhadDevice
from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.exceptions import WhadDeviceNotFound
from time import time,sleep
from whad.common.monitors import PcapWriterMonitor
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

import logging
logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.zigbee.stack.mac').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.nwk').setLevel(logging.INFO)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]
        # Connect to target device and performs discovery
        try:
            #monitor = PcapWriterMonitor("/tmp/decrypt.pcap")
            dev = WhadDevice.create(interface)
            endDevice = EndDevice(dev)
            #monitor.attach(endDevice)
            #monitor.start()
            endDevice.start()
            #endDevice.stack.nwk.database.set("nwkSecurityLevel", 5)
            #endDevice.stack.nwk.add_key("44:81:97:51:b6:02:04:91:81:dc:8b:c2:71:4d:f0:9d")
            management_service = endDevice.stack.nwk.get_service("management")
            for network in management_service.network_discovery():
                print(network)
            management_service.join(extended_pan_id=0xf4ce364269d30198)
            #management_service = endDevice.stack.mac.get_service("management")
            #management_service.associate(coordinator_pan_id=0x2699, coordinator_address=0x0, channel_page=0, channel=16)

            input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
