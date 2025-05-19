"""BT Mesh protocol layer unit tests.

This module provides 2 set of tests  :

- TestProvisioningLayerProvisioner: checks the layer behavior when in Provisioner mode

- TestProvisioningLayerProvisionee: checks the layer behavior when in Provisionee mode

"""

import pytest
from whad.common.stack import instance, alias
from whad.common.stack.tests import Sandbox, LayerMessage
from whad.btmesh.stack.provisioning import (
    ProvisioningLayerProvisionee,
)
from scapy.all import raw


@alias("gen_prov")
class GenericProvisioningMock(Sandbox):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)


GenericProvisioningMock.add(ProvisioningLayerProvisionee)


class ProvisioningLayerTest(object):
    @pytest.fixture
    def gen_prov(self):
        return GenericProvisioningMock()


"""
class TestProvisioningLayerProvisionee(ProvisioningLayerTest):
    def test_on_invite(self, gen_prov):
        # Send a Provisioning Invite PDU
        packet = BTMesh_Provisioning_Hdr(
            type=0x00, message=BTMesh_Provisioning_Invite()
        )

        expected_result = BTMesh_Provisioning_Hdr(
            bytes(
                BTMesh_Provisioning_Hdr(
                    type=0x01, message=BTMesh_Provisioning_Capabilities()
                )
            )
        )

        gen_prov.send("gen_prov", packet)

        assert gen_prov.expect(
            LayerMessage(
                source="provisioning",
                destination="gen_prov",
                data=expected_result,
                tag="default",
            )
        )

"""
