from whad.btmesh.stack.gen_prov import (
    GenericProvisioningLayerProvisioner,
    GenericProvisioningMessage,
)
from whad.btmesh.stack.provisioning import ProvisioningLayerProvisioner
from whad.btmesh.stack.pb_adv import PBAdvBearerLayer
from whad.common.stack.tests import Sandbox, LayerMessage
from whad.scapy.layers.btmesh import *
from whad.common.stack import alias
from pprint import pprint
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.btmesh.connectors.provisioner import Provisioner
from time import sleep
from threading import Event

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


link_open = BTMesh_Generic_Provisioning_Link_Open(
    bearer_opcode=0,
    generic_provisioning_control_format=3,
    device_uuid="7462d668-bc88-3473-0000-000000000000",
)

pkt = EIR_Hdr(type=0x29) / EIR_PB_ADV_PDU(
    link_id=b"abcd", transaction_number=0, data=link_open
)

try:
    dev = WhadDevice.create(interface)

    # event to get signals from callback on adv msg receieved
    provisioner = Provisioner(dev, auto_provision=True)
    provisioner.configure(advertisements=True, connection=False)
    provisioner.start()
    print("PROVISIONER STARTED")

    provisioner.polling_rx_packets()

except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
