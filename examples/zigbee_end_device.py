from whad.zigbee import EndDevice
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.mac.constants import MACScanType
from whad.device import WhadDevice
from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.exceptions import WhadDeviceNotFound
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.zcl import ZCLOnOff, ZCLTouchLink
from time import time,sleep
from whad.common.monitors import PcapWriterMonitor
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

import logging
logging.basicConfig(level=logging.WARNING)
logging.getLogger('whad.zigbee.stack.mac').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.nwk').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.aps').setLevel(logging.INFO)
#logging.getLogger('whad.zigbee.stack.apl').setLevel(logging.INFO)

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
            endDevice.set_channel(25)
            endDevice.start()
            #endDevice.stack.nwk.database.set("nwkSecurityLevel", 5)
            #endDevice.stack.nwk.add_key("44:81:97:51:b6:02:04:91:81:dc:8b:c2:71:4d:f0:9d")
            onoff = ZCLOnOff()
            touchlink = ZCLTouchLink()
            myApp1 = ApplicationObject("commissioning", 0xc05e, 0x0100, application_device_version=0, input_clusters=[touchlink], output_clusters=[touchlink])
            myApp2 = ApplicationObject("onoff", 0x0104, 0x0100, application_device_version=0, input_clusters=[], output_clusters=[onoff])
            endDevice.stack.apl.attach_application(myApp1, endpoint=1)
            endDevice.stack.apl.attach_application(myApp2, endpoint=2)
            while True:
                touchlink.scan_request()
                input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
