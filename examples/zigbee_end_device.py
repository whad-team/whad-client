from whad.zigbee import EndDevice
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.mac.constants import MACScanType
from whad.device import WhadDevice
from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.exceptions import WhadDeviceNotFound
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.zcl.clusters import ZCLOnOff#, ZCLTouchLink
from time import time,sleep
from whad.common.monitors import PcapWriterMonitor
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
import sys

import logging
logging.basicConfig(level=logging.WARNING)
#logging.getLogger('whad.zigbee.stack.mac').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.nwk').setLevel(logging.INFO)
#logging.getLogger('whad.zigbee.stack.aps').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.apl').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.apl.zcl').setLevel(logging.INFO)

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
            zdo = endDevice.stack.apl.get_application_by_name("zdo")
            endDevice.stack.apl.initialize()
            endDevice.stack.apl.start()
            input()
            while True:
                zdo.device_and_service_discovery.nwk_addr_req(0xf4ce3673877b2d89)
                input()
            '''
            onoff = ZCLOnOff()
            myApp2 = ApplicationObject("onoff", 0x0104, 0x0100, device_version=0, input_clusters=[], output_clusters=[onoff])

            endDevice.stack.apl.attach_application(myApp2, endpoint=1)

            onoff.connect(0xde04,10)
            while True:
                onoff.toggle()
                input()
            input()
            '''

            '''
            zdo.network_manager.configure_extended_address(0x000b57fffe209d2a)
            zdo.network_manager.configure_sequence_numbers(72,207, 50)
            zdo.network_manager.configure_short_address(0x0001)
            zdo.network_manager.configure_extended_pan_id(0x78a2c3ba68773ae3)
            zdo.security_manager.provision_network_key('16:0c:f2:9d:d4:da:92:37:4f:c0:fb:66:f4:27:af:12')


            endDevice.stack.apl.start()


            #onoff.connect(0x0018,255)

            input()
            while True:
                onoff.toggle()
                input()
            '''
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
