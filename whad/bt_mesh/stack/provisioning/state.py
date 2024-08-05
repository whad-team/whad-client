"""
Provisioning Layer State

Stores the information about the current Provisoning process instanced by the Generic Provisoning Layer (or the used if we launch it as an unprovisioned device)
"""

from whad.common.stack import Layer, LayerState, ContextualLayer, alias, source, state, instance
from whad.bt_mesh.crypto import ProvisioningBearerAdvCryptoManager


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


    @property
    def capabilities(self):
        return self._capabilities


    def set_crypto_manager(self, crypto_manager):
        self.crypto_manager = crypto_manager
