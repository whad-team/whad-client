from whad.device import WhadDevice
from whad.zigbee import EndDevice
from whad.common.monitors import WiresharkMonitor
from whad.zigbee.stack.apl.zcl.clusters.touchlink import ZCLTouchLinkClient
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys

import logging

logging.getLogger('whad.zigbee.stack.apl').setLevel(logging.INFO)
logging.getLogger('whad.zigbee.stack.apl.zcl').setLevel(logging.INFO)


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

            touchlink = ZCLTouchLinkClient()
            zll = ApplicationObject("zll_app", 0xc05e, 0x0100, device_version=0, input_clusters=[], output_clusters=[])
            zll.add_output_cluster(touchlink)

            end_device = EndDevice(dev)
            #end_device = EndDevice(dev, applications=[zll])
            monitor.attach(end_device)
            monitor.start()
            end_device.attach_callback(show)
            end_device.start()


            selected_network = None
            print("[i] Discovering networks.")
            for network in end_device.discover_networks():
                print("[i] Network detected: ", network)
                selected_network = network
            print("Selected: ", selected_network)
            #network_address = touchlink.scan(address_assignment=True, factory_new=False, link_initiator=True)
            #selected_network.network_key = bytes.fromhex("01020102030403040506050607080708")

            #while not selected_network.rejoin(0x0003):
            #    pass
            selected_network.join()
            try:
                print("[i] Network key:", selected_network.network_key)
                #end_device.stack.get_layer('apl').get_application_by_name('zdo').network_manager.network = selected_network
                devices = selected_network.discover()
                for device in devices:
                    print("[i] New device discovered:", device)

                for device in selected_network.nodes:
                    for endpoint in device.endpoints:
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                input()
                                print("[i] lightbulb toggled")
                                onoff.toggle()

            except KeyboardInterrupt:
                selected_network.leave()

            while True:
                input()
        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
