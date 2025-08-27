"""BTMesh stack Lower Transport Layer unit testing

This module provides 1 sets of test (so far):

TO CHANGE
- TestBleStackL2CAPForwarding: check that data PDU are forwarded to L2CAP layer

"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.lower_transport import LowerTransportLayer
from whad.btmesh.stack.upper_transport import UpperTransportLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Control_Message,
    BTMesh_Lower_Transport_Segmented_Access_Message,
    BTMesh_Lower_Transport_Segment_Acknoledgment_Message,
    BTMesh_Upper_Transport_Access_PDU,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw


LowerTransportLayer.remove(UpperTransportLayer)


# Create our sandboxed lower transport layer (mock network and upper transport layers)
@alias("network")
class NetworkLayerMock(Sandbox):
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
            "lower_transport": {
                "profile": profile,
                "upper_transport": {
                    "profile": profile,
                    "access": {"profile": profile},
                },
            },
        }
        super().__init__(parent=parent, layer_name=layer_name, options=options)

    pass


NetworkLayerMock.add(LowerTransportLayer)


class BTMeshLowerTransportTest(object):

    @pytest.fixture
    def network_layer(self):
        return NetworkLayerMock()


# Test supported control PDUs
class TestBTMeshStackLowerTransportTest(BTMeshLowerTransportTest):

    def test_segmentation_acknowledgment(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=2
            )
            / Raw(b"\x15\x8d\xdb\x94\x86\x966\x0f\x1d\xcb\x9b~"),
        )
        ctx1 = MeshMessageContext()
        ctx1.src_addr = 4
        ctx1.dest_addr = 2
        ctx1.seq_number = 0
        ctx1.aid = 0
        ctx1.application_key_index = -1
        ctx1.net_key_id = 0
        ctx1.aszmic = 0
        ctx1.is_ctl = False

        seg2 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=1, last_seg_number=2
            )
            / Raw(load=b"d\x95o\xda\xbb\xae\xa5\xaf\x1c\xe5\xabb"),
        )
        ctx2 = copy(ctx1)
        ctx2.seq_number = 1

        seg3 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=2, last_seg_number=2
            )
            / Raw(load=b'\x80\x00\x00"d\x95o\xda\xbb\xae\xa5\xaf\x1c\xe5\xabb'),
        )
        ctx3 = copy(ctx1)
        ctx3.seq_number = 1

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        network_layer.send("lower_transport", (seg3, ctx3))

        # expected ack
        ack = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=0
        ) / BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
            obo=0, seq_zero=0, acked_segments=7
        )
        ctx_ack = copy(ctx1)
        ctx_ack.src_addr = 2
        ctx_ack.dest_addr = 4
        ctx_ack.seq_number = 0
        ctx_ack.is_ctl = True



        sleep(0.2)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (ack, ctx_ack)),
        )

    def test_segmentation_reassembly(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=2
            )
            / Raw(b"\x15\x8d\xdb\x94\x86\x966\x0f\x1d\xcb\x9b~"),
        )
        ctx1 = MeshMessageContext()
        ctx1.src_addr = 4
        ctx1.dest_addr = 2
        ctx1.seq_number = 0
        ctx1.aid = 0
        ctx1.application_key_index = -1
        ctx1.net_key_id = 0
        ctx1.aszmic = 0
        ctx1.is_ctl = False

        seg2 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=1, last_seg_number=2
            )
            / Raw(load=b"d\x95o\xda\xbb\xae\xa5\xaf\x1c\xe5\xabb"),
        )
        ctx2 = copy(ctx1)
        ctx2.seq_number = 1

        seg3 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=2, last_seg_number=2
            )
            / Raw(load=b'\x80\x00\x00"d\x95o\xda\xbb\xae\xa5\xaf\x1c\xe5\xabb'),
        )
        ctx3 = copy(ctx1)
        ctx3.seq_number = 1

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        network_layer.send("lower_transport", (seg3, ctx3))

        ctx_access = copy(ctx1)
        # expected message sent to upper transport
        access_message = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex(
                "158ddb948696360f1dcb9b7e64956fdabbaea5af1ce5ab628000002264956fdabbaea5af1ce5ab62"
            )
        )
        access_message.show()


 
        sleep(0.2)

        assert network_layer.expect(
            LayerMessage("lower_transport", "upper_transport", (access_message, ctx_access)),
        )
