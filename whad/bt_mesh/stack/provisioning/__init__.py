"""
BT Mesh Provisioning Layer (Provisioning Protocol, common to all Bearers)

Manages the actual exchange of information between the Provisioner and the Device.
Implements both the Provisioner and Device side.
"""

import logging

from whad.scapy.layers.bt_mesh import (
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Capabilities,
    BTMesh_Provisioning_Start,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Input_Complete,
    BTMesh_Provisioning_Confirmation,
    BTMesh_Provisioning_Random,
    BTMesh_Provisioning_Data,
    BTMesh_Provisioning_Complete,
    BTMesh_Provisioning_Failed,
    BTMesh_Provisioning_Record_Request,
    BTMesh_Provisioning_Records_Get,
    BTMesh_Provisioning_Records_List,
    BTMesh_Provisioning_Record_Response,
    BTMesh_Provisioning_Hdr,
)
from whad.common.stack import Layer, alias, instance, state
from whad.bt_mesh.stack.provisioning.state import ProvisioningState
from whad.exceptions import UnsupportedCapability, RequiredImplementation
from whad.bt_mesh.stack.exceptions import (
    UnknownParameterValueSend,
    FailedProvisioningReceived,
    UnknownProvisioningPacketType,
    UncompatibleAlgorithmsAvailable,
)
from whad.bt_mesh.crypto import ProvisioningBearerAdvCryptoManager

logger = logging.getLogger(__name__)


@state(ProvisioningState)
@alias("provisioning")
class ProvisioningLayer(Layer):
    """Provisioning Provisioner/Device base class"""

    def configure(self, options):
        """Configure the Provisioning Layer"""

        self._handlers = {
            BTMesh_Provisioning_Invite: self.on_invite,
            BTMesh_Provisioning_Capabilities: self.on_capabilities,
            BTMesh_Provisioning_Start: self.on_start,
            BTMesh_Provisioning_Public_Key: self.on_public_key,
            BTMesh_Provisioning_Input_Complete: self.on_input_complete,
            BTMesh_Provisioning_Confirmation: self.on_confirmation,
            BTMesh_Provisioning_Random: self.on_random,
            BTMesh_Provisioning_Data: self.on_data,
            BTMesh_Provisioning_Complete: self.on_complete,
            BTMesh_Provisioning_Failed: self.on_failed,
            BTMesh_Provisioning_Record_Request: self.on_record_request,
            BTMesh_Provisioning_Records_Get: self.on_records_get,
            BTMesh_Provisioning_Records_List: self.on_records_list,
            BTMesh_Provisioning_Record_Response: self.on_record_response,
        }

    def send_error_response(self, error_code):
        """Sends a BTMesh_Provisioning_Failed to other device. Error code defined in scapy layer"""
        if error_code < 0x1 or error_code > 0x09:
            raise UnknownParameterValueSend(
                "BTMesh_Provisioning_Failed.error_code", error_code
            )
        self.send("gen_prov", BTMesh_Provisioning_Failed(error_code=error_code))

    @instance("gen_prov")
    def on_packet_received(self, packet):
        """Process incoming packets from the Generic Provisioning Layer"""
        packet_type = type(packet)
        if packet_type not in self._handlers:
            raise UnknownProvisioningPacketType(packet_type)
        self._handlers[packet_type](packet)

        # All handlers except Failed return errors here since we are in the generic layer. Needs implement in Provisioner/Device classes.

    def on_failed(self, packet):
        raise FailedProvisioningReceived(packet.error_code)

    def on_invite(self, packet):
        self.send_error_response(0x07)

    def on_start(self, packet):
        self.send_error_response(0x07)

    def on_capabilities(self, packet):
        self.send_error_response(0x07)

    def on_public_key(self, packet):
        self.send_error_response(0x07)

    def on_input_complete(self, packet):
        self.send_error_response(0x07)

    def on_confirmation(self, packet):
        self.send_error_response(0x07)

    def on_random(self, packet):
        self.send_error_response(0x07)

    def on_data(self, packet):
        self.send_error_response(0x07)

    def on_complete(self, packet):
        self.send_error_response(0x07)

    def on_record_request(self, packet):
        self.send_error_response(0x07)

    def on_records_get(self, packet):
        self.send_error_response(0x07)

    def on_records_list(self, packet):
        self.send_error_response(0x07)

    def on_record_response(self, packet):
        self.send_error_response(0x07)


def ProvisioningLayerProvisioner(ProvisioningLayer):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    def configure(self, options):
        super().configure(options)

    def on_capabilities(self, packet):
        """
        Retrieve capabilities of Device to choose what we want
        (for now static choice)
        Send Start pdu after
        """

        if packet.algorithms & 0x10 and self.state.capabilities & 0x10:
            self.state.chosen_parameters.alg = "BTM_ECDH_P256_HMAC_SHA256_AES_CCM"
        elif packet.algorithms & 0x01 and self.state.capabilities & 0x01:
            self.state.chosen_parameters.alg = "BTM_ECDH_P256_CMAC_AES128_AES_CCM"
        else:
            raise UncompatibleAlgorithmsAvailable

        # the rest is static for now, already set in state init
        params = self.state.chosen_parameters

        self.send(
            "gen_prov",
            BTMesh_Provisioning_Start(
                algorithms=params.alg,
                public_key_type=params.public_key_type,
                authencation_method=params.authencation_method,
                authencation_action=params.authencation_action,
                authencation_size=params.authencation_size,
            ),
        )



class ProvisioningLayerDevice(ProvisioningLayer):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    def configure(self, options):
        super().configure(options)


    def on_invite(self, packet):
        """
        Responds to an invite to connect to network with capablities
        """
        capabilities = self.state.capabilities

