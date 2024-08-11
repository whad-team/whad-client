from whad.device import WhadDevice
from whad.zigbee import Coordinator
from whad.common.monitors import WiresharkMonitor
from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.zcl.clusters.onoff import OnOffServer, ZCLCluster
from whad.exceptions import WhadDeviceNotFound
from scapy.compat import raw
from random import randint
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        # Retrieve target interface

        interface = sys.argv[1]

        try:
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)

            # Define a custom ON/OFF ZCL Server
            class CustomOnOffServer(OnOffServer):
                @ZCLCluster.command_receive(0x00, "Off")
                def on_off(self, command):
                    super().on_off(command)
                    print("-> Custom Off")

            # Instantiate the custom OnOff ZCL Server
            onoff = CustomOnOffServer()

            # Create an Application object and set OnOff ZCL as input cluster
            basic_app = ApplicationObject(
                "basic_app",
                profile_id = 0x0104,
                device_id = 0x0100,
                device_version = 0,
                input_clusters = [
                    onoff
                ]
            )
            # Instantiate a coordinator with our application object
            coordinator = Coordinator(dev, applications=[basic_app])

            # Attach & start the wireshark monitor
            monitor.attach(coordinator)
            monitor.start()

            # Start the coordinator
            coordinator.start()

            # Start a network formation
            print("[i] Network formation !")
            network = coordinator.start_network()
            while True:
                # When there is an user input, discover the network
                input()
                for device in network.discover():
                    print("[i] New device discovered:", device)

                # Iterate over the devices in the network
                for device in network.nodes:
                    # For each device, iterate over the endpoints
                    for endpoint in device.endpoints:
                        # If a OnOff is found in endpoint, attach to the cluster
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                input()
                                # Manipulate the OnOff cluster API to toggle the state
                                print("[i] lightbulb toggled")
                                onoff.toggle()

        except (KeyboardInterrupt, SystemExit):
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])
