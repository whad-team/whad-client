from whad.device import WhadDevice
from whad.zigbee import EndDevice
from whad.common.monitors import WiresharkMonitor
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
            monitor = WiresharkMonitor()

            dev = WhadDevice.create(interface)
            end_device = EndDevice(dev)
            monitor.attach(end_device)
            monitor.start()
            input()
            end_device.attach_callback(show)
            end_device.start()

            selected_network = None
            print("[i] Discovering networks.")
            for network in end_device.discover_networks():
                print("[i] Network detected: ", network)
                if network.extended_pan_id == 0x6055f90000f714e4:
                    selected_network = network
            print("Selected: ", selected_network)

            selected_network.join()
            try:
                print("[i] Network key:", selected_network.network_key)

                devices = selected_network.discover()
                for device in devices:
                    print("[i] New device discovered:", device)
                '''
                for device in selected_network.devices:
                    for endpoint in device.endpoints:
                        if endpoint.profile_id == 0x0104 and 6 in endpoint.input_clusters:
                            onoff = endpoint.attach_to_input_cluster(6)
                            while True:
                                input()
                                print("[i] lightbulb toggled")
                                onoff.toggle()
                '''
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
