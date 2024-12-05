"""
Provisioning Layer State

Stores the information about the current Provisoning process instanced by the Generic Provisoning Layer (or the used if we launch it as an unprovisioned device)
"""

from whad.common.stack import Layer, LayerState, ContextualLayer, alias, source, state, instance
from whad.btmesh.crypto import ProvisioningBearerAdvCryptoManager
from whad.scapy.layers.btmesh import (
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Capabilities,
    BTMesh_Provisioning_Start,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Confirmation,
    BTMesh_Provisioning_Random,
    BTMesh_Provisioning_Data,
    BTMesh_Provisioning_Complete,
)

# Status of the Provisioning protocol
# set when the Transaction Ack has been notified to the Layer
# stores the class of last provisioning state done

PROV_INVITE_DONE =  BTMesh_Provisioning_Invite
PROV_CAPABILTIES_DONE = BTMesh_Provisioning_Capabilities
PROV_START_DONE =BTMesh_Provisioning_Start
PROV_PUB_KEY_DONE = BTMesh_Provisioning_Public_Key
PROV_CONFIRMATION_DONE =BTMesh_Provisioning_Confirmation
PROV_RANDOM_DONE = BTMesh_Provisioning_Random
PROV_DATA_DONE = BTMesh_Provisioning_Data
PROV_COMPLETE_DONE = BTMesh_Provisioning_Complete


class ProvisioningState(LayerState):
    """
    State (DB) of the Provisioning layer, instance by the associated Generic Provisioner
    """

    def __init__(self):
        super().__init__()

        self.capabilities = dict(
            alg = 0b11, #default support 2 algs
            public_key_type = 0x00, #default no OOB public key support
            static_oob_type = 0x00, #default no static OOB info available
            output_oob_type = 0x00, # default no output OOB action available
            output_oob_size = 0x00,
            input_oob_type = 0x00, # default no input OOB a available
            input_oob_size = 0x00
        )

        self.chosen_parameters = dict(
            alg = 0b11, #default 2 algs
            public_key_type = 0x00, #default no OOB public key
            authentication_method = 0x00, # no OOB auth default
            authentication_action = 0x00, # no OOB auth default
            authentication_size = 0x00
        )


        self.crypto_manager = None

        self.status = None



    def set_crypto_manager(self, crypto_manager):
        self.crypto_manager = crypto_manager
