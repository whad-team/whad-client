from whad.zigbee import EndDevice
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.mac.constants import MACScanType
from whad.device import WhadDevice
from whad.zigbee.crypto import NetworkLayerCryptoManager
from whad.exceptions import WhadDeviceNotFound
from whad.zigbee.stack.apl.application import ApplicationObject
from time import time,sleep
from whad.common.monitors import PcapWriterMonitor
from scapy.compat import raw
from scapy.layers.dot15d4 import Dot15d4
from whad.zigbee.profile.device import Router
import sys

import logging
logging.basicConfig(level=logging.WARNING)
#logging.getLogger('whad.zigbee.stack.mac').setLevel(logging.INFO)
#logging.getLogger('whad.zigbee.stack.nwk').setLevel(logging.INFO)
#logging.getLogger('whad.zigbee.stack.aps').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.apl').setLevel(logging.INFO)
#logging.getLogger('whad.zigbee.stack.apl.zcl').setLevel(logging.INFO)

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]
        # Connect to target device and performs discovery
        try:
            #monitor = PcapWriterMonitor("/tmp/decrypt.pcap")

            dev = WhadDevice.create(interface)
            endDevice = EndDevice(dev)
            endDevice.start()
            selected_network = None

            print("[i] Discovering networks.")
            for network in endDevice.discover_networks():
                print("[i] Network detected: ", network)
                if network.extended_pan_id == 0xf4ce3673877b2d89:
                    selected_network = network

            print("[i] Joining network: ", selected_network)
            selected_network.join()
            try:
                print("[i] Network key:", selected_network.network_key)

                devices = selected_network.discover()
                for device in devices:
                    print("[i] New device discovered:", device)

                for device in selected_network.devices:
                    for endpoint in device.endpoints:
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                input()
                                print("[i] lightbulb toggled")
                                onoff.toggle()
            except KeyboardInterrupt:
                selected_network.leave()
            #discover()
            #print(selected_network.devices)

            '''
            for network in endDevice.discover_networks():
                if network.extended_pan_id == 0xf4ce3673877b2d89:
                    endDevice.join(network)

            print(endDevice.stack.apl.get_application_by_name("zdo").device_and_service_discovery.get_node_descriptor(0))
            '''
            '''
            for device in endDevice.discover_devices():
                print("> ", repr(device))
            '''
            #monitor.attach(endDevice)
            #monitor.start()

            '''
            zdo = endDevice.stack.apl.get_application_by_name("zdo").discovery_manager.discover_devices()
            endDevice.stack.apl.initialize()
            endDevice.stack.apl.start()
            input()
            print(endDevice.stack.nwk.database.get("nwkNeighborTable").table)
            for address in endDevice.stack.nwk.database.get("nwkNeighborTable").table:
                print(hex(address))
                zdo.device_and_service_discovery.ieee_addr_req(address, request_type=1)

                input()
            '''
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
