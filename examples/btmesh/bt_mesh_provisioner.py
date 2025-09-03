from whad.scapy.layers.btmesh import *
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connector.provisioner import Provisioner

from whad.scapy.layers.btmesh import *

from scapy.all import (
    EIR_Hdr,
)

from random import randbytes

if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [device]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]


try:
    dev = WhadDevice.create(interface)

    # Auto provision node
    provisioner = Provisioner(dev)
    provisioner.profile.auto_provision()
    provisioner.start()
    print("Provisionner started\n")

    provisioner.start_listening_beacons()

    while True:
        i = input(
            "Press enter key to see unprovisioned devices, or enter index of node to provision ... :"
        )
        print("\n")

        devices = provisioner.get_unprovisioned_devices()
        try:
            i = int(i, 0)
        except ValueError:
            # If no index in input, print received unprovisioned beacons
            if len(devices) == 0:
                print("No Unprovisioned beacons received....\n")

            else:
                print("Index | Device UUID")
                for index in range(len(devices)):
                    print(
                        "|─ %d : %s" % (index, str(devices[index])),
                    )
                print("\n")
            continue

        # if we have an index, try to provision it
        if len(devices) <= i:
            print("This index is not present in our list of unprovsioned devices\n")
        else:
            res = provisioner.provision_distant_node(devices[i])
            if res:
                print("Successfully provisionned device\n")
            else:
                print("Failed to provision deviced...\n")


except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
