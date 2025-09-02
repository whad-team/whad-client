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
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
    BTMesh_Upper_Transport_Control_Heartbeat,
    BTMesh_Model_Generic_OnOff_Set,
    BTMesh_Model_Message,
    BTMesh_Model_Config_Composition_Data_Get,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw


UpperTransportLayer.remove(AccessLayer)


# Create our sandboxed lower transport layer (mock network and upper transport layers)
@alias("lower_transport")
class LowerTransportMock(Sandbox):
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
            "upper_transport": {
                "profile": profile,
                "access": {"profile": profile},
            },
        }
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    pass


LowerTransportMock.add(UpperTransportLayer)


class BTMeshUpperTransportTest(object):

    @pytest.fixture
    def lower_transport(self):
        return LowerTransportMock()


# Test management for control messages
class TestBTMeshStackUpperTransportControl(BTMeshUpperTransportTest):

    # tests if a control message is forwarded to lower transport when sent
    def test_tx_control_success(self, lower_transport):
        ctl_message = BTMesh_Upper_Transport_Control_Heartbeat(init_ttl=127, features=0)
        ctl_ctx = MeshMessageContext()
        ctl_ctx.src_addr = 4
        ctl_ctx.dest_addr = 2
        ctl_ctx.seq_number = 50
        ctl_ctx.application_key_index = 0
        ctl_ctx.net_key_id = 0
        ctl_ctx.ttl = 127
        ctl_ctx.is_ctl = True

        expected_ctx = copy(ctl_ctx)
        expected_ctx.seq_auth = 50

        lower_transport.get_layer("upper_transport").send_control_message(
            (ctl_message, ctl_ctx)
        )
        sleep(0.05)

        assert lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (ctl_message, expected_ctx)
            )
        )


# test handling of access messages
class TestBTMeshStackUpperTransportAccess(BTMeshUpperTransportTest):

    # test the receiving of a valid access message for which we have the app key
    def test_tx_access_app_key_success(self, lower_transport):
        access_pkt = BTMesh_Model_Message(
            opcode=33282
        ) / BTMesh_Model_Generic_OnOff_Set(onoff=1, transaction_id=1)
        access_ctx = MeshMessageContext()
        access_ctx.src_addr = 4
        access_ctx.dest_addr = 2
        access_ctx.application_key_index = 0
        access_ctx.net_key_id = 0
        access_ctx.ttl = 127
        access_ctx.aszmic = 0

        lower_transport.send_from("access", "upper_transport", (access_pkt, access_ctx))
        sleep(0.05)

        expected_pkt = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("3befde02bf084bde")
        )
        expected_ctx = copy(access_ctx)
        expected_ctx.seq_number = 0
        expected_ctx.aid = 38

        assert lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (expected_pkt, expected_ctx)
            )
        )

    # test the sending of a valid access message for which we have no app key (app key index non existing))
    def test_tx_access_no_app_key(self, lower_transport):
        access_pkt = BTMesh_Model_Message(
            opcode=33282
        ) / BTMesh_Model_Generic_OnOff_Set(onoff=1, transaction_id=1)
        access_ctx = MeshMessageContext()
        access_ctx.src_addr = 4
        access_ctx.dest_addr = 2
        access_ctx.application_key_index = 1
        access_ctx.net_key_id = 0
        access_ctx.ttl = 127
        access_ctx.aszmic = 0

        lower_transport.send_from("access", "upper_transport", (access_pkt, access_ctx))
        sleep(0.05)

        expected_pkt = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("3befde02bf084bde")
        )
        expected_ctx = copy(access_ctx)
        expected_ctx.seq_number = 0
        expected_ctx.aid = 38

        assert not lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (expected_pkt, expected_ctx)
            )
        )

    # test the sending of a valid access message for which we have the dev key
    def test_tx_access_dev_key_success(self, lower_transport):
        access_pkt = BTMesh_Model_Message(
            opcode=32776
        ) / BTMesh_Model_Config_Composition_Data_Get(page=0)
        access_ctx = MeshMessageContext()
        access_ctx.src_addr = 4
        access_ctx.dest_addr = 2
        access_ctx.application_key_index = -1
        access_ctx.net_key_id = 0
        access_ctx.dev_key_address = 2
        access_ctx.ttl = 127
        access_ctx.aszmic = 0

        lower_transport.send_from("access", "upper_transport", (access_pkt, access_ctx))
        sleep(0.05)

        expected_pkt = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("9785dbc321c5f6")
        )
        expected_ctx = copy(access_ctx)
        expected_ctx.seq_number = 0
        expected_ctx.aid = -1

        assert lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (expected_pkt, expected_ctx)
            )
        )

    # test the sending of a valid access message for which we have no dev key
    def test_tx_access_no_dev_key(self, lower_transport):
        access_pkt = BTMesh_Model_Message(
            opcode=32776
        ) / BTMesh_Model_Config_Composition_Data_Get(page=0)
        access_ctx = MeshMessageContext()
        access_ctx.src_addr = 4
        access_ctx.dest_addr = 2
        access_ctx.application_key_index = -1
        access_ctx.net_key_id = 0
        access_ctx.dev_key_address = 8
        access_ctx.ttl = 127
        access_ctx.aszmic = 0

        lower_transport.send_from("access", "upper_transport", (access_pkt, access_ctx))
        sleep(0.05)

        expected_pkt = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("9785dbc321c5f6")
        )
        expected_ctx = copy(access_ctx)
        expected_ctx.seq_number = 0
        expected_ctx.aid = -1

        assert not lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (expected_pkt, expected_ctx)
            )
        )

    """
    # test the receiving of a valid access message for which we have the dev key
    def test_rx_access_dev_key_success(self, lower_transport):
        lower_pkt = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("9785dbc321c5f6")
        )
        access_pkt = BTMesh_Model_Message(
            opcode=32776
        ) / BTMesh_Model_Config_Composition_Data_Get(page=0)
        access_ctx = MeshMessageContext()
        access_ctx.src_addr = 4
        access_ctx.dest_addr = 2
        access_ctx.application_key_index = -1
        access_ctx.net_key_id = 0
        access_ctx.dev_key_address = 2
        access_ctx.ttl = 127
        access_ctx.aszmic = 0

        lower_transport.send_from("access", "upper_transport", (access_pkt, access_ctx))
        sleep(0.05)

        expected_ctx = copy(access_ctx)
        expected_ctx.seq_number = 0
        expected_ctx.aid = -1

        assert lower_transport.expect(
            LayerMessage(
                "upper_transport", "lower_transport", (expected_pkt, expected_ctx)
            )
        )
    """
