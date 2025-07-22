from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.df_attack import DFAttacks
from time import sleep


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

try:
    dev = WhadDevice.create(interface)

    connector = DFAttacks(dev)

    connector.profile.auto_provision()
    connector.start()

    print("Node is provisioned !")

    while True:
        input("Press any key to start network discovery, from address 0x01 to 0x0A...")
        connector.do_network_discovery(0x01, 0x0A)
        print("Currently discovering nodes, please wait ....")
        # wait for the discovery to be over
        sleep((0x0A - 0x01) * 3.5)

        print("Nodes discovered, evaluating distance to them...")
        nodes = connector.do_get_hops()
        sleep(0x0A - 0x01)

        topology = connector.get_network_topology()

        for range_start, (range_length, distance) in topology.items():
            print(
                "Node 0x%x to 0x%x , %d hops away"
                % (range_start, range_start + range_length, distance)
            )


except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
