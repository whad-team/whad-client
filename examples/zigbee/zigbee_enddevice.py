from whad.device import WhadDevice
from whad.zigbee import EndDevice
from whad.common.monitors import WiresharkMonitor
from whad.zigbee.stack.apl.zcl.clusters.touchlink import ZCLTouchLinkClient
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface
        interface = sys.argv[1]

        try:
            # Create a wireshark monitor
            monitor = WiresharkMonitor()

            # Create the WHAD device
            dev = WhadDevice.create(interface)

            # Create an end device & attach & start the wireshark monitor
            end_device = EndDevice(dev)
            monitor.attach(end_device)
            monitor.start()
            end_device.start()


            # Discover available networks
            selected_network = None
            print("[i] Discovering networks.")
            for network in end_device.discover_networks():
                print("[i] Network detected: ", network)
                selected_network = network

            # Select the latest one
            print("Selected: ", selected_network)

            # Initate a join procedure
            selected_network.join()
            try:
                # Display the network key
                print("[i] Network key:", selected_network.network_key)

                # Discover the nodes in the network
                devices = selected_network.discover()
                for device in devices:
                    print("[i] New device discovered:", device)

                # For each device, iterate over the available endpoints & search for a ZCL input cluster
                for device in selected_network.nodes:
                    for endpoint in device.endpoints:
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                # Manipulate the ZCL On Off API
                                input()
                                print("[i] lightbulb toggled")
                                onoff.toggle()

            except KeyboardInterrupt:
                selected_network.leave()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
