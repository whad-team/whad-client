from whad.scapy.layers.bt_mesh import EIR_BTMesh_Beacon
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from time import sleep
from whad.bt_mesh.connectors import BTMeshHCI
from whad.ble import Peripheral

from whad.ble.profile.advdata import (
    AdvCompleteLocalName,
    AdvDataFieldList,
    AdvFlagsField,
    AdvMeshBeacon,
)
from scapy.all import raw

from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV_NONCONN_IND


def show(packet):
    print(packet.metadata, repr(packet))


if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [provisionee]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

pkt = BTLE(
    bytes.fromhex(
        "d6be898e421fa3e80189fa1d182b007462d668bc8834730110000000000000000000000000e36c5c"
    )
)
adv_data = b"".join([bytes(record) for record in pkt[BTLE_ADV_NONCONN_IND].data])

adv_data = AdvDataFieldList(AdvMeshBeacon(raw(pkt.getlayer(EIR_BTMesh_Beacon))))

try:
    dev = WhadDevice.create(interface)
    hci = BTMeshHCI(dev)
    hci.attach_callback(callback=show)
    print(hci.enable_adv_mode(adv_data=adv_data))
    print(hci.start())
    while True:
        pass
except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
