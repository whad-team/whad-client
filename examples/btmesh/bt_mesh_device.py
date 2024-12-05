from whad.scapy.layers.btmesh import *
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connectors.provisionee import Provisionee
from time import sleep

from scapy.all import EIR_Hdr


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

beacon_data = BTMesh_Unprovisioned_Device_Beacon(
    device_uuid="7462d668-bc88-3473-0000-000000000012", uri_hash=1
)

pkt_beacon = EIR_Hdr(type=0x2B) / EIR_BTMesh_Beacon(
    mesh_beacon_type=0x00, unprovisioned_device_beacon_data=beacon_data
)
try:
    dev = WhadDevice.create(interface)
    provisionee = Provisionee(dev)
    provisionee.configure(advertisements=True, connection=False)
    provisionee.start()
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)
    provisionee.send_raw(pkt_beacon)

    while True:
        # provisionee.send_raw(pkt_beacon)

        provisionee.polling_rx_packets()
        sleep(0.1)
except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
