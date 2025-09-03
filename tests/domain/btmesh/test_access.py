"""BTMesh stack Upper Transport Layer unit testing

This module provides 2 sets of test (so far):

TO CHANGE
- TestBTMeshStackLowerTransportAccess: check that Access messages are correcly forwarded and processed
- TestBTMeshStackLowerTransportControl: check that Control messages are correcly processed

"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.access import AccessLayer
from whad.btmesh.stack.upper_transport import UpperTransportLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Model_Generic_OnOff_Set,
    BTMesh_Model_Generic_OnOff_Status,
    BTMesh_Model_Message,
    BTMesh_Model_Config_Composition_Data_Get,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw


# Create our sandboxed lower transport layer (mock network and upper transport layers)
@alias("upper_transport")
class UpperTransportMock(Sandbox):
    def __init__(self, parent=None, layer_name=None, options={}):
        profile = BaseMeshProfile(
            auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
            auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_unicast_addr=2,
        )
        profile.auto_provision()
        options = {
            "profile": profile,
            "access": {"profile": profile},
        }
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    pass


UpperTransportMock.add(AccessLayer)


class BTMeshAccessTest(object):

    @pytest.fixture
    def upper_transport(self):
        return UpperTransportMock()


# Test management for control messages
class TestBTMeshStackAccess(BTMeshAccessTest):

    # tests if a Generic OnOff message for the primary element gets forwarded to the model and send a status in return
    def test_rx_status_response(self, upper_transport):
        onoff_pkt = BTMesh_Model_Message(opcode=33282) / BTMesh_Model_Generic_OnOff_Set(
            onoff=1, transaction_id=1
        )
        onoff_ctx = MeshMessageContext()
        onoff_ctx.src_addr = 4
        onoff_ctx.dest_addr = 2
        onoff_ctx.seq_number = 0
        onoff_ctx.application_key_index = 0
        onoff_ctx.aid = 38
        onoff_ctx.net_key_id = 0
        onoff_ctx.ttl = 127
        onoff_ctx.seq_auth = 0

        expected_pkt = BTMesh_Model_Message(
            opcode=33284
        ) / BTMesh_Model_Generic_OnOff_Status(present_onoff=1)
        expected_ctx = MeshMessageContext()
        expected_ctx.src_addr = 2
        expected_ctx.dest_addr = 4
        expected_ctx.aid = 38
        expected_ctx.application_key_index = 0
        expected_ctx.net_key_id = 0
        expected_ctx.ttl = 127

        upper_transport.send("access", (onoff_pkt, onoff_ctx))
        sleep(0.05)

        assert upper_transport.expect(
            LayerMessage("access", "upper_transport", (expected_pkt, expected_ctx))
        )

    # tests if a Generic OnOff Set message is sent properly when asked
    def test_tx_onoff(self, upper_transport):
        onoff_pkt = BTMesh_Model_Message(opcode=33282) / BTMesh_Model_Generic_OnOff_Set(
            onoff=1, transaction_id=1
        )
        onoff_ctx = MeshMessageContext()
        onoff_ctx.src_addr = 4
        onoff_ctx.dest_addr = 2
        onoff_ctx.application_key_index = 0
        onoff_ctx.net_key_id = 0
        onoff_ctx.ttl = 127

        # really ugly but because we are in test context ...
        model = (
            upper_transport.get_layer("access")
            .state.profile.local_node.get_element(0)
            .get_model_by_id(0x1001)
        )

        upper_transport.get_layer("access").send_access_message(
            model, (onoff_pkt, onoff_ctx)
        )
        sleep(0.05)

        assert upper_transport.expect(
            LayerMessage("access", "upper_transport", (onoff_pkt, onoff_ctx))
        )
