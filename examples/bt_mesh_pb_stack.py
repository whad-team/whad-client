from whad.bt_mesh.stack.gen_prov import GenericProvisioningLayerProvisioner, GenericProvisioningMessage
from whad.bt_mesh.stack.provisioning import ProvisioningLayerProvisioner
from whad.bt_mesh.stack.pb_adv import PBAdvBearerLayer
from whad.common.stack.tests import Sandbox, LayerMessage
from whad.scapy.layers.bt_mesh import *
from whad.common.stack import alias
from pprint import pprint


from random import randbytes


@alias("phy")
class PhySandbox(Sandbox):
    pass

transaction_number = 0x00


def get_transaction_nb():
    global transaction_number
    transaction_number += 1
    return transaction_number


PhySandbox.add(PBAdvBearerLayer)

link_id1 = randbytes(4)
link_id2 = randbytes(4)
dev_uuid = "7462d668-bc88-3473-0000-000000000000"


packets = [
    EIR_PB_ADV_PDU(
        link_id=link_id1, transaction_number=get_transaction_nb()
    )
    / BTMesh_Generic_Provisioning_Link_Open(device_uuid=dev_uuid)
]

my_stack = PhySandbox(options={"role": "device"})


for packet in packets:
    my_stack.send("pb_adv",packet)


for message in my_stack.messages:
    if isinstance(message.data, GenericProvisioningMessage):
        message.data.gen_prov_pkt.show()
    else:
        message.data.show()
#pprint(my_stack.save())
