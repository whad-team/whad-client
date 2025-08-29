"""BTMesh stack Lower Transport Layer unit testing

This module provides 2 sets of test (so far):

TO CHANGE
- TestBTMeshStackLowerTransportAccess: check that Access messages are correcly forwarded and acknowlegded
- TestBTMeshStackLowerTransportControl: check that Control messages are correcly forwarded and acknowlegded

"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.lower_transport import LowerTransportLayer
from whad.btmesh.stack.network import NetworkLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias, source
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Obfuscated_Network_PDU,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw

NetworkLayer.remove(LowerTransportLayer)


# The network layer "talks" with the connector, but we overwrite it so the connector is not needed and we can hook messages with sandbox
# via a fictional "connector_layer" layer
@alias("network")
class NetworkLayerModified(NetworkLayer):

    # redefine init so that this layer can be an intermediate layer ...
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(connector=None, options=options)

    def sending_thread(self, pkt):
        self.send("connector_layer", pkt)

    @source("connector_layer")
    def on_net_pdu_received(self, net_pdu):
        super().on_net_pdu_received(net_pdu, 0)


# Create our sandboxed network layer via a fake "connector" layer
@alias("connector_layer")
class ConnectorLayerMock(Sandbox):
    def __init__(self, parent=None, layer_name=None, options={}):
        profile = BaseMeshProfile(
            auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
            auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_unicast_addr=2,
        )
        profile.auto_provision()
        options = {
            "network": {
                "profile": profile,
                "lower_transport": {
                    "profile": profile,
                    "upper_transport": {
                        "profile": profile,
                        "access": {"profile": profile},
                    },
                },
            }
        }
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    pass


ConnectorLayerMock.add(NetworkLayerModified)


class BTMeshNetworkLayerTest(object):

    @pytest.fixture
    def connector_layer(self):
        return ConnectorLayerMock()


# Test network layer
class TestBTMeshStackLowerTransportAccess(BTMeshNetworkLayerTest):

    # Test the receiving of a valid message for which we have the net key
    def test_rx_network_success(self, connector_layer):
        rx_pkt = BTMesh_Obfuscated_Network_PDU(
            ivi=0,
            nid=127,
            obfuscated_data=b"\xf1}\xa0\x0ey\x9d",
            enc_dst_enc_transport_pdu_mic=b"Xk\xf8\xecq\x19\x84\x99q\x19d\xe6\xa5)^",
        )

        connector_layer.send("network", rx_pkt)

        expected_pkt = BTMesh_Lower_Transport_Access_Message(
            seg=0, application_key_flag=1, application_key_id=38
        ) / BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("3befde02bf084bde")
        )
        expected_ctx = MeshMessageContext()
        expected_ctx.src_addr = 4
        expected_ctx.dest_addr = 2
        expected_ctx.application_key_index = 0
        expected_ctx.net_key_id = 0
        expected_ctx.ttl = 127
        sleep(0.1)

        connector_layer.expect(
            LayerMessage("network", "lower_transport", (expected_pkt, expected_ctx))
        )
        pass
