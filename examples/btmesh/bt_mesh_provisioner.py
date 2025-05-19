from whad.scapy.layers.btmesh import *
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connectors.provisioner import Provisioner

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

    # event to get signals from callback on adv msg receieved
    provisioner = Provisioner(dev)
    provisioner.profile.auto_provision()
    provisioner.start()
    print("PROVISIONER STARTED")

    provisioner.start_listening_beacons()

    while True:
        i = input("Press any key to see unprovisioned devices :")
        devices = provisioner.get_unprovisioned_devices()
        for device in d



except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
