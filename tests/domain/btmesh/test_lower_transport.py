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
from whad.btmesh.stack.upper_transport import UpperTransportLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Control_Message,
    BTMesh_Lower_Transport_Segmented_Access_Message,
    BTMesh_Lower_Transport_Segmented_Control_Message,
    BTMesh_Lower_Transport_Segment_Acknoledgment_Message,
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
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
        sar_state_tx = profile.get_configuration_server_model().get_state(
            "sar_transmitter"
        )

        # no retransmissions for tests to not halt the tests
        sar_state_tx.get_sub_state("sar_multicast_retransmissions_count").set_value(1)
        sar_state_tx.get_sub_state("sar_unicast_retransmissions_count").set_value(1)
        sar_state_tx.get_sub_state(
            "sar_unicast_retransmissions_interval_step"
        ).set_value(0)
        sar_state_tx.get_sub_state(
            "sar_multicast_retransmissions_interval_step"
        ).set_value(0)

        sar_state_rx = profile.get_configuration_server_model().get_state(
            "sar_receiver"
        )

        sar_state_rx.get_sub_state(
            "sar_acknowledgment_retransmissions_count"
        ).set_value(0)
        sar_state_rx.get_sub_state("sar_receiver_segment_interval_step").set_value(0)

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


# Test management for access messages
class TestBTMeshStackLowerTransportAccess(BTMeshLowerTransportTest):

    # tests if an unsegmented access message is forwarded to network
    def test_tx_unsegmented_access(self, network_layer):
        access_message = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("85e82794d5199da0")
        )
        ctx = MeshMessageContext()
        ctx.src_addr = 2
        ctx.dest_addr = 4
        ctx.seq_number = 0
        ctx.aid = 38
        ctx.application_key_index = 0
        ctx.net_key_id = 0
        ctx.aszmic = 0
        ctx.ttl = 127
        ctx.is_ctl = False
        ctx.seq_auth = 0

        network_layer.send_from(
            "upper_transport", "lower_transport", (access_message, ctx)
        )

        ctx_network = copy(ctx)
        network_message = BTMesh_Lower_Transport_Access_Message(
            seg=0, application_key_flag=1, application_key_id=38
        ) / BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("85e82794d5199da0")
        )

        sleep(0.1)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (network_message, ctx_network)),
        )

    # Test the sending of a segmented access message, if segmented forwarded to network layer
    def test_tx_segmented_access(self, network_layer):

        access_message = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex(
                "158ddb948696360f1dcb9b7e64956fdabbaea5af1ce5ab628000002264956fdabbaea5af1ce5ab62"
            )
        )
        ctx_access = MeshMessageContext()
        ctx_access.src_addr = 2
        ctx_access.dest_addr = 4
        ctx_access.seq_number = 0
        ctx_access.aid = 0
        ctx_access.application_key_index = -1
        ctx_access.net_key_id = 0
        ctx_access.aszmic = 0
        ctx_access.is_ctl = False
        ctx_access.seq_auth = 0
        ctx_access.ttl = 127

        network_layer.send_from(
            "upper_transport", "lower_transport", (access_message, ctx_access)
        )

        # expected forwarded segments to network layer
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=3
            )
            / Raw(b"\x15\x8d\xdb\x94\x86\x966\x0f\x1d\xcb\x9b~"),
        )
        ctx1 = copy(ctx_access)
        ctx1.segment_number = 0

        seg2 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=1, last_seg_number=3
            )
            / Raw(load=b"d\x95o\xda\xbb\xae\xa5\xaf\x1c\xe5\xabb"),
        )
        ctx2 = copy(ctx1)
        ctx2.seq_number = 1
        ctx2.segment_number = 1

        seg3 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=2, last_seg_number=3
            )
            / Raw(load=b'\x80\x00\x00"d\x95o\xda\xbb\xae\xa5\xaf'),
        )
        ctx3 = copy(ctx1)
        ctx3.seq_number = 2
        ctx3.segment_number = 2

        seg4 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=3, last_seg_number=3
            )
            / Raw(load=b"\x1c\xe5\xabb"),
        )
        ctx4 = copy(ctx1)
        ctx4.seq_number = 3
        ctx4.segment_number = 3

        sleep(0.2)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg1, ctx1)),
        )
        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg2, ctx2)),
        )
        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg3, ctx3)),
        )
        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg4, ctx4)),
        )

    # Tests if an unsegemented access message is forwarded
    def test_rx_unsegmented_access(self, network_layer):
        pkt = BTMesh_Lower_Transport_Access_Message(
            seg=0, application_key_flag=1, application_key_id=38
        ) / BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("85e82794d5199da0")
        )
        ctx = MeshMessageContext()
        ctx.src_addr = 4
        ctx.dest_addr = 2
        ctx.seq_number = 4
        ctx.aid = 38
        ctx.application_key_index = 0
        ctx.net_key_id = 0
        ctx.aszmic = 0
        ctx.ttl = 127
        ctx.is_ctl = False

        network_layer.send("lower_transport", (pkt, ctx))

        ctx_access = copy(ctx)
        ctx_access.seq_auth = 4
        access_message = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex("85e82794d5199da0")
        )

        sleep(0.1)
        assert network_layer.expect(
            LayerMessage(
                "lower_transport", "upper_transport", (access_message, ctx_access)
            ),
        )

    # Tests if a segmented access message is acknowledged
    def test_rx_segmentation_acknowledgment_access(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=3
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
                aszmic=0, seq_zero=0, seg_offset=1, last_seg_number=3
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
                aszmic=0, seq_zero=0, seg_offset=2, last_seg_number=3
            )
            / Raw(load=b'\x80\x00\x00"d\x95o\xda\xbb\xae\xa5\xaf'),
        )
        ctx3 = copy(ctx1)
        ctx3.seq_number = 2

        seg4 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=3, last_seg_number=3
            )
            / Raw(load=b"\x1c\xe5\xabb"),
        )
        ctx4 = copy(ctx1)
        ctx4.seq_number = 3

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        network_layer.send("lower_transport", (seg3, ctx3))
        network_layer.send("lower_transport", (seg4, ctx4))

        ack = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=0
        ) / BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
            obo=0, seq_zero=0, acked_segments=15
        )
        ctx_ack = copy(ctx1)
        ctx_ack.src_addr = 2
        ctx_ack.dest_addr = 4
        ctx_ack.seq_number = 0
        ctx_ack.is_ctl = True
        ctx_ack.seq_auth = 0

        sleep(0.2)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (ack, ctx_ack)),
        )

    # Tests if a segemented access message is forwarded
    def test_rx_segmentation_reassembly_access(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=3
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
                aszmic=0, seq_zero=0, seg_offset=1, last_seg_number=3
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
                aszmic=0, seq_zero=0, seg_offset=2, last_seg_number=3
            )
            / Raw(load=b'\x80\x00\x00"d\x95o\xda\xbb\xae\xa5\xaf'),
        )
        ctx3 = copy(ctx1)
        ctx3.seq_number = 2

        seg4 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=3, last_seg_number=3
            )
            / Raw(load=b"\x1c\xe5\xabb"),
        )
        ctx4 = copy(ctx1)
        ctx4.seq_number = 3

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        network_layer.send("lower_transport", (seg3, ctx3))
        network_layer.send("lower_transport", (seg4, ctx4))

        ctx_access = copy(ctx1)
        # expected message sent to upper transport
        access_message = BTMesh_Upper_Transport_Access_PDU(
            enc_access_message_and_mic=bytes.fromhex(
                "158ddb948696360f1dcb9b7e64956fdabbaea5af1ce5ab628000002264956fdabbaea5af1ce5ab62"
            )
        )
        sleep(0.1)

        assert network_layer.expect(
            LayerMessage(
                "lower_transport", "upper_transport", (access_message, ctx_access)
            ),
        )

    # Received only 1 out of 3 segments for access message, should send ack with appropriate args
    def test_rx_segmentation_incomplete_access(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Access_Message(
            seg=1,
            application_key_flag=0,
            application_key_id=0,
            payload_field=BTMesh_Lower_Transport_Segmented_Access_Message(
                aszmic=0, seq_zero=0, seg_offset=0, last_seg_number=2
            )
            / Raw(load=b"\x15\x8d\xdb\x94\x86\x966\x0f\x1d\xcb\x9b~"),
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

        network_layer.send("lower_transport", (seg1, ctx1))

        # expected ack
        ack = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=0
        ) / BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
            obo=0, seq_zero=0, acked_segments=1
        )
        ctx_ack = copy(ctx1)
        ctx_ack.src_addr = 2
        ctx_ack.dest_addr = 4
        ctx_ack.seq_number = 0
        ctx_ack.is_ctl = True
        ctx_ack.seq_auth = 0

        sleep(0.2)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (ack, ctx_ack)),
        )


# Tests for the management of control messages
class TestBTMeshStackLowerTransportControl(BTMeshLowerTransportTest):

    # Tests if a segemented control message is forwarded to the network layer in rx
    def test_tx_segmentated_control(self, network_layer):

        control_message = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[1, 5, 6, 7, 8, 9]
        )
        control_ctx = MeshMessageContext()
        control_ctx.src_addr = 2
        control_ctx.dest_addr = 4
        control_ctx.net_key_id = 0
        control_ctx.is_ctl = True
        control_ctx.ttl = 127
        control_ctx.seq_number = 0
        control_ctx.seq_auth = 0

        network_layer.send_from(
            "upper_transport", "lower_transport", (control_message, control_ctx)
        )
        sleep(0.1)

        seg1 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=0, last_seg_number=1
            )
            / Raw(load=b"\x00\x01\x00\x05\x00\x06\x00\x07"),
        )

        ctx1 = copy(control_ctx)
        ctx1.seq_number = 0
        ctx1.segment_number = 0

        seg2 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=1, last_seg_number=1
            )
            / Raw(load=b"\x00\x08\x00\t"),
        )
        ctx2 = copy(control_ctx)
        ctx2.seq_number = 1
        ctx2.segment_number = 1

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg1, ctx1)),
        )
        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (seg2, ctx2)),
        )

    # Tests if an unsegmented control message is forwarded
    def test_tx_unsegmented_control(self, network_layer):
        control_message = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[0x1, 0x2]
        )
        control_ctx = MeshMessageContext()
        control_ctx.src_addr = 2
        control_ctx.dest_addr = 0xFFFB
        control_ctx.creds = 2
        control_ctx.seq_number = 0
        control_ctx.application_key_index = 0
        control_ctx.net_key_id = 0
        control_ctx.aszmic = 0
        control_ctx.ttl = 127
        control_ctx.is_ctl = True
        control_ctx.seq_auth = 0

        network_layer.send_from(
            "upper_transport", "lower_transport", (control_message, control_ctx)
        )
        sleep(0.1)

        pkt = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=17
        ) / BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[0x1, 0x2]
        )
        ctx = copy(control_ctx)

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (pkt, ctx)),
        )

    # Tests if an unsegmented control message is forwarded
    def test_rx_unsegmented_control(self, network_layer):
        pkt = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=17
        ) / BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[0x1, 0x2]
        )
        ctx = MeshMessageContext()
        ctx.src_addr = 4
        ctx.dest_addr = 0xFFFB
        ctx.creds = 2
        ctx.seq_number = 5
        ctx.application_key_index = 0
        ctx.net_key_id = 0
        ctx.aszmic = 0
        ctx.ttl = 127
        ctx.is_ctl = True

        network_layer.send("lower_transport", (pkt, ctx))

        control_message = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[0x1, 0x2]
        )
        control_ctx = copy(ctx)
        ctx.seq_auth = 5

        assert network_layer.expect(
            LayerMessage(
                "lower_transport", "upper_transport", (control_message, control_ctx)
            ),
        )

    # Tests if a segmented control message is acknowledged
    def test_segmentation_acknowledgment_control(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=0, last_seg_number=1
            )
            / Raw(load=b"\x00\x01\x00\x05\x00\x06\x00\x07"),
        )

        ctx1 = MeshMessageContext()
        ctx1.src_addr = 0x4
        ctx1.dest_addr = 0x2
        ctx1.seq_number = 1
        ctx1.application_key_index = 0
        ctx1.net_key_id = 0
        ctx1.aszmic = 0
        ctx1.ttl = 127
        ctx1.is_ctl = True

        seg2 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=1, last_seg_number=1
            )
            / Raw(load=b"\x00\x08\x00\t"),
        )
        ctx2 = copy(ctx1)
        ctx2.seq_number = 2

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        sleep(0.2)

        # expected ack
        ack = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=0
        ) / BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
            obo=0, seq_zero=0, acked_segments=3
        )
        ctx_ack = copy(ctx1)
        ctx_ack.src_addr = 2
        ctx_ack.dest_addr = 4
        ctx_ack.seq_number = 0
        ctx_ack.is_ctl = True
        ctx_ack.seq_auth = 0

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (ack, ctx_ack)),
        )

    # Tests if a segemented control message is forwarded
    def test_segmentation_reassembly_control(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=0, last_seg_number=1
            )
            / Raw(load=b"\x00\x01\x00\x05\x00\x06\x00\x07"),
        )

        ctx1 = MeshMessageContext()
        ctx1.src_addr = 0x4
        ctx1.dest_addr = 0x2
        ctx1.seq_number = 0
        ctx1.application_key_index = 0
        ctx1.net_key_id = 0
        ctx1.aszmic = 0
        ctx1.ttl = 127
        ctx1.is_ctl = True

        seg2 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=1, last_seg_number=1
            )
            / Raw(load=b"\x00\x08\x00\t"),
        )
        ctx2 = copy(ctx1)
        ctx2.seq_number = 1

        network_layer.send("lower_transport", (seg1, ctx1))
        network_layer.send("lower_transport", (seg2, ctx2))
        sleep(0.1)

        control_message = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=[1, 5, 6, 7, 8, 9]
        )
        control_ctx = copy(ctx1)
        control_ctx.src_addr = 4
        control_ctx.dest_addr = 2
        control_ctx.seq_number = 0
        control_ctx.is_ctl = True
        control_ctx.seq_auth = 0

        assert network_layer.expect(
            LayerMessage(
                "lower_transport", "upper_transport", (control_message, control_ctx)
            ),
        )

    # Received only 1 out of 3 segments for control message, should send ack with appropriate args
    def test_segmentation_incomplete_control(self, network_layer):
        seg1 = BTMesh_Lower_Transport_Control_Message(
            seg=1,
            opcode=17,
            payload_field=BTMesh_Lower_Transport_Segmented_Control_Message(
                seq_zero=0, seg_offset=0, last_seg_number=2
            )
            / Raw(load=b"\x00\x01\x00\x05\x00\x06\x00\x07"),
        )

        ctx1 = MeshMessageContext()
        ctx1.src_addr = 0x4
        ctx1.dest_addr = 0x2
        ctx1.seq_number = 0
        ctx1.application_key_index = 0
        ctx1.net_key_id = 0
        ctx1.aszmic = 0
        ctx1.ttl = 127
        ctx1.is_ctl = True

        network_layer.send("lower_transport", (seg1, ctx1))
        sleep(0.2)

        # expected ack
        ack = BTMesh_Lower_Transport_Control_Message(
            seg=0, opcode=0
        ) / BTMesh_Lower_Transport_Segment_Acknoledgment_Message(
            obo=0, seq_zero=0, acked_segments=1
        )
        ctx_ack = copy(ctx1)
        ctx_ack.src_addr = 2
        ctx_ack.dest_addr = 4
        ctx_ack.seq_number = 0
        ctx_ack.is_ctl = True
        ctx_ack.seq_auth = 0

        assert network_layer.expect(
            LayerMessage("lower_transport", "network", (ack, ctx_ack)),
        )
        pass
