"""BTMesh stack PBAdv Layer (provisionning) unit testing


Not done yet (a bit tricky since it acts as a bridge between layers and connector...)

"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.pb_adv import PBAdvBearerLayer
from whad.common.stack import alias, source, instance
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Obfuscated_Network_PDU,
    EIR_Hdr,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw
from uuid import UUID


# Fake GenericProvisioning layer, needed since instanciated dynamically...
@instance("gen_prov")
class GenericProvisioningSandbox(Sandbox):
    def __init__(self, parent=None, layer_name=None, options=..., target=None):
        super().__init__(parent, layer_name, options, target)


# The pb_adv layer "talks" with the connector, but we overwrite it so the connector is not needed and we can hook messages with sandbox
# via a fictional "connector_layer" layer
@alias("pb_adv")
class PBAdvModified(PBAdvBearerLayer):

    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(connector=None, parent=parent, options=options)
        self.state.generic_prov_layer_class = GenericProvisioningSandbox

    def sending_thread(self, pkt):
        pkt.show()
        self.send("connector_layer", pkt)

    @source("connector_layer")
    def on_net_pdu_received(self, net_pdu):
        super().on_net_pdu_received(net_pdu, 0)


# Create our sandboxed pb_adv layer via a fake "connector" layer for provisionee
@alias("connector_layer")
class ConnectorLayerProvisioneeMock(Sandbox):
    def __init__(self, parent=None, layer_name="connector_layer", options={}):
        profile = BaseMeshProfile(
            auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
            auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_unicast_addr=2,
        )
        profile.is_provisioner = False
        super().__init__(parent=parent, layer_name=layer_name, options=options)


# We create fake connector and profile objects and define only what is accessed by the stack in order to fill in the gaps


class ConnectorMock(object):
    def __init__(self, profile):
        self.profile = profile
        self.uuid = (UUID("ddddaaaa-aaaa-aa01-0000-000000000000"),)

    def stop_unprovisioned_beacons(self):
        pass


class BTMeshNetworkLayerTest(object):

    @pytest.fixture
    def connector_layer(self):
        return ConnectorLayerMock()


"""
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
        expected_ctx.seq_number = 0
        sleep(0.1)

        assert connector_layer.expect(
            LayerMessage("network", "lower_transport", (expected_pkt, expected_ctx))
        )

    # Test the sending of a valid message for which we have the net key
    def test_tx_network_success(self, connector_layer):
        tx_pkt = BTMesh_Lower_Transport_Access_Message(
            seg=0, application_key_flag=1, application_key_id=38
        ) / BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("3befde02bf084bde")
        )
        tx_ctx = MeshMessageContext()
        tx_ctx.src_addr = 4
        tx_ctx.dest_addr = 2
        tx_ctx.application_key_index = 0
        tx_ctx.net_key_id = 0
        tx_ctx.ttl = 127
        tx_ctx.seq_number = 0

        expected_pkt = EIR_Hdr(type=0x2A) / BTMesh_Obfuscated_Network_PDU(
            ivi=0,
            nid=127,
            obfuscated_data=b"\xf1}\xa0\x0ey\x9d",
            enc_dst_enc_transport_pdu_mic=b"Xk\xf8\xecq\x19\x84\x99q\x19d\xe6\xa5)^",
        )

        connector_layer.send_from("lower_transport", "network", (tx_pkt, tx_ctx))
        sleep(0.1)

        assert connector_layer.expect(
            LayerMessage("network", "connector_layer", expected_pkt)
        )

    # Test the receiving of a valid message for which we have no netkey
    def test_rx_network_no_netkey(self, connector_layer):
        rx_pkt = BTMesh_Obfuscated_Network_PDU(
            ivi=0,
            nid=128,
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
        expected_ctx.seq_number = 0
        sleep(0.1)

        assert not connector_layer.expect(
            LayerMessage("network", "lower_transport", (expected_pkt, expected_ctx))
        )

    # Test the receiving of an invalid message for which we have a netkey
    def test_rx_network_invalid(self, connector_layer):
        rx_pkt = BTMesh_Obfuscated_Network_PDU(
            ivi=0,
            nid=127,
            obfuscated_data=b"\xf1}\xa0\x0ey\x9e",
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
        expected_ctx.seq_number = 0
        sleep(0.1)

        assert not connector_layer.expect(
            LayerMessage("network", "lower_transport", (expected_pkt, expected_ctx))
        )

"""
