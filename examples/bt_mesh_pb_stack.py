from whad.bt_mesh.stack.gen_prov import (
    GenericProvisioningLayerProvisioner,
    GenericProvisioningMessage,
)
from whad.bt_mesh.stack.provisioning import ProvisioningLayerProvisioner
from whad.bt_mesh.stack.pb_adv import PBAdvBearerLayer
from whad.common.stack.tests import Sandbox, LayerMessage
from whad.scapy.layers.bt_mesh import *
from whad.common.stack import alias
from pprint import pprint
from whad.exceptions import WhadDeviceNotFound

from whad.device import WhadDevice
from whad.ble.exceptions import ConnectionLostException
import sys
from whad.bt_mesh.connectors.provisioner import Provisioner
from time import sleep

from whad.scapy.layers.bt_mesh import *

from scapy.all import (
    BTLE_ADV,
    BTLE_ADV_NONCONN_IND,
    BTLE,
    BTLE_CTRL,
    LL_UNKNOWN_RSP,
    LL_REJECT_IND,
    BTLE_DATA,
    L2CAP_Hdr,
    ATT_Hdr,
    ATT_Write_Request,
    ATT_Read_Request,
    ATT_Read_Response,
    SM_Hdr,
    SM_Pairing_Response,
    LL_ENC_REQ,
    EIR_Hdr,
)

from random import randbytes

if len(sys.argv) != 2:
    # Retrieve target interface
    print("Usage: %s [device]" % sys.argv[0])
    exit(1)


interface = sys.argv[1]

pkt = (
    EIR_Hdr(type=0x29)
    / EIR_PB_ADV_PDU(link_id=0xC72DB67A, transaction_number=0)
    / BTMesh_Generic_Provisioning_Transaction_Start(
        segment_number=0, generic_provisioning_control_format=0
    )
    / BTMesh_Provisioning_Hdr(type=0, message=BTMesh_Provisioning_Invite())
)
try:
    dev = WhadDevice.create(interface)
    provisioner = Provisioner(dev)
    provisioner.configure(advertisements=True, connection=False)
    provisioner.start()

    while True:
        provisioner.send_raw(pkt)
        sleep(1)
except ConnectionLostException as e:
    print("Connection lost", e)

except (KeyboardInterrupt, SystemExit):
    dev.close()

except WhadDeviceNotFound:
    print("[e] Device not found")
    exit(1)
while True:
    pass
