"""BTMesh stack Lower Transport Layer unit testing

This module provides 2 sets of test (so far):

TO CHANGE
- TestBTMeshStackLowerTransportAccess: check that Access messages are correcly forwarded and acknowlegded
- TestBTMeshStackLowerTransportControl: check that Control messages are correcly forwarded and acknowlegded

"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.gen_prov import (
    GenericProvisioningLayerProvisionee,
)
from whad.btmesh.stack.gen_prov.message import GenericProvisioningMessage
from whad.btmesh.stack.provisioning import ProvisioningLayerProvisionee
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias
from whad.common.stack.layer import Layer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Generic_Provisioning_Link_Ack,
    BTMesh_Generic_Provisioning_Link_Open,
    BTMesh_Generic_Provisioning_Transaction_Ack,
    BTMesh_Generic_Provisioning_Transaction_Continuation,
    BTMesh_Generic_Provisioning_Transaction_Start,
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Hdr,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Capabilities,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from scapy.packet import Raw
from uuid import UUID


GenericProvisioningLayerProvisionee.remove(ProvisioningLayerProvisionee)


# Create our sandboxed pb_adv layer instantiating the gen_prov layer
@alias("pb_adv")
class PBAdvMock(Sandbox):
    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        self.__gen_prov = self.instantiate(GenericProvisioningLayerProvisionee)
        self.__gen_prov.state.tx_packet_attempts = (
            1  # only a single try to send a packet...
        )
        self.target = self.gen_prov.name

    @property
    def gen_prov(self):
        return self.__gen_prov


class BTMeshGenericProvisioningTest(object):

    @pytest.fixture(scope="class")
    def pb_adv_layer(self):
        return PBAdvMock()


class TestBTMeshGenericProvisioning(BTMeshGenericProvisioningTest):

    # On link open receive, send link_ack
    def test_rx_link_open(self, pb_adv_layer):
        rx_pkt = BTMesh_Generic_Provisioning_Link_Open(
            device_uuid=UUID("ddddaaaa-aaaa-aa01-0000-000000000000")
        )
        rx_trans_nb = 0

        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt, rx_trans_nb)
        )
        sleep(0.1)

        expected_pkt = BTMesh_Generic_Provisioning_Link_Ack()
        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(expected_pkt, rx_trans_nb),
            )
        )

    # test if provisioning packet forwarded to provisioning layer for unsegmented packet
    def test_rx_forward_unsegmented(self, pb_adv_layer):
        rx_pkt = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=0, total_length=2, frame_check_sequence=0x5B
        ) / BTMesh_Provisioning_Hdr(
            message=BTMesh_Provisioning_Invite(attention_duration=100)
        )
        rx_trans_nb = 0
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt, rx_trans_nb)
        )
        sleep(0.1)

        expected_pkt = rx_pkt[1]

        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "provisioning",
                expected_pkt,
            )
        )

    # when receiving an invite (a transaction start without any continuation), we ack it
    def test_rx_invite(self, pb_adv_layer):
        rx_pkt = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=0, total_length=2, frame_check_sequence=0x5B
        ) / BTMesh_Provisioning_Hdr(
            message=BTMesh_Provisioning_Invite(attention_duration=100)
        )
        rx_trans_nb = 0

        pb_adv_layer.flush_messages()
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt, rx_trans_nb)
        )
        sleep(0.1)

        expected_pkt = BTMesh_Generic_Provisioning_Transaction_Ack()

        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(expected_pkt, rx_trans_nb),
            )
        )

    # reception of a segmented message, expect the forward
    def test_rx_forward_segmented(self, pb_adv_layer):
        rx_pkt1 = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=2, total_length=65, frame_check_sequence=0xFB
        ) / Raw(load=b"\x03\xf8\xa1\x1d;0\x8a\x7f\xc8\xf5\t\xff\x96jN2\xcf-\xb5\x8e")

        rx_pkt2 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=1,
            generic_provisioning_payload_fragment=b"G\x11\x85\x1c\x1f\x11(\x81'If_\xf6d\xbeq8m~QYIb",
        )

        rx_pkt3 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=2,
            generic_provisioning_payload_fragment=b"\xb7B\x8f\x1bQ\xbd\xc4\xf0\x86h\x01o\x06<\x1a]\x0b}\xa27!\x06",
        )
        rx_trans_nb = 2

        pb_adv_layer.flush_messages()

        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt1, rx_trans_nb)
        )
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt2, rx_trans_nb)
        )
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt3, rx_trans_nb)
        )
        sleep(0.1)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"\xf8\xa1\x1d;0\x8a\x7f\xc8\xf5\t\xff\x96jN2\xcf-\xb5\x8eG\x11\x85\x1c\x1f\x11(\x81'If_\xf6",
                public_key_y=b"d\xbeq8m~QYIb\xb7B\x8f\x1bQ\xbd\xc4\xf0\x86h\x01o\x06<\x1a]\x0b}\xa27!\x06",
            ),
        )

        expected_pkt.show()
        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "provisioning",
                expected_pkt,
            )
        )

    # reception of a segmented message, expect the ack
    def test_rx_continuation(self, pb_adv_layer):
        rx_pkt1 = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=2, total_length=65, frame_check_sequence=0xFB
        ) / Raw(load=b"\x03\xf8\xa1\x1d;0\x8a\x7f\xc8\xf5\t\xff\x96jN2\xcf-\xb5\x8e")

        rx_pkt2 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=1,
            generic_provisioning_payload_fragment=b"G\x11\x85\x1c\x1f\x11(\x81'If_\xf6d\xbeq8m~QYIb",
        )

        rx_pkt3 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=2,
            generic_provisioning_payload_fragment=b"\xb7B\x8f\x1bQ\xbd\xc4\xf0\x86h\x01o\x06<\x1a]\x0b}\xa27!\x06",
        )
        rx_trans_nb = 2

        pb_adv_layer.flush_messages()

        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt1, rx_trans_nb)
        )
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt2, rx_trans_nb)
        )
        pb_adv_layer.send(
            pb_adv_layer.target, GenericProvisioningMessage(rx_pkt3, rx_trans_nb)
        )
        sleep(0.1)

        expected_pkt = BTMesh_Generic_Provisioning_Transaction_Ack()

        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(expected_pkt, rx_trans_nb),
            )
        )

    # test the sending of a small provisioning message (unsegmented)
    def test_tx_unsegmented(self, pb_adv_layer):
        provisioning_packet = BTMesh_Provisioning_Hdr(
            type=1,
            message=BTMesh_Provisioning_Capabilities(
                number_of_elements=2,
                algorithms=0b11,
                public_key_type=0,
                oob_type=0,
                output_oob_action=0,
                input_oob_size=0,
                output_oob_size=0,
                input_oob_action=0,
            ),
        )

        pb_adv_layer.send_from("provisioning", pb_adv_layer.target, provisioning_packet)

        tx_pkt = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=0, total_length=12, frame_check_sequence=0x90
        ) / Raw(load=b"\x01\x02\x00\x03\x00\x00\x00\x00\x00\x00\x00\x00")
        trans_nb = 128

        sleep(0.1)
        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(tx_pkt, trans_nb),
            )
        )

        # Send the ack to complte the transaction for rest of tests
        pb_adv_layer.send(
            pb_adv_layer.target,
            GenericProvisioningMessage(
                BTMesh_Generic_Provisioning_Transaction_Ack(), 128
            ),
        )

    # test the sending of a small provisioning message (unsegmented)
    def test_tx_segmented(self, pb_adv_layer):
        provisioning_packet = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"wr\xa2\xa1t\xfa?p\x01\xb0\xe9\xd9$\xa6\xd0@h\xdc\xc2\xc0\xd7\x9f'\x1a\xb1}K\x90\xf7\x87b\x03",
                public_key_y=b"\xb8\x87\x96\xbf#\xc8\t\xa7\xd3\x13l\xd0\xbc\x89sGz\xe5\x1c\xa30b\xe7\xd7\xf01S\xbc\xe3Z\xa6\xa8",
            ),
        )

        pb_adv_layer.send_from("provisioning", pb_adv_layer.target, provisioning_packet)

        tx_pkt1 = BTMesh_Generic_Provisioning_Transaction_Start(
            segment_number=2, total_length=65, frame_check_sequence=0xCD
        ) / Raw(load=b"\x03wr\xa2\xa1t\xfa?p\x01\xb0\xe9\xd9$\xa6\xd0@h\xdc\xc2")

        tx_pkt2 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=1,
            generic_provisioning_payload_fragment=b"\xc0\xd7\x9f'\x1a\xb1}K\x90\xf7\x87b\x03\xb8\x87\x96\xbf#\xc8\t\xa7\xd3\x13",
        )

        tx_pkt3 = BTMesh_Generic_Provisioning_Transaction_Continuation(
            segment_index=2,
            generic_provisioning_payload_fragment=b"l\xd0\xbc\x89sGz\xe5\x1c\xa30b\xe7\xd7\xf01S\xbc\xe3Z\xa6\xa8",
        )
        trans_nb = 129

        sleep(0.1)

        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(tx_pkt1, trans_nb),
            )
        )
        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(tx_pkt2, trans_nb),
            )
        )
        assert pb_adv_layer.expect(
            LayerMessage(
                pb_adv_layer.target,
                "pb_adv",
                GenericProvisioningMessage(tx_pkt3, trans_nb),
            )
        )
        # Send the ack to complete the transaction for rest of tests
        pb_adv_layer.send(
            pb_adv_layer.target,
            GenericProvisioningMessage(
                BTMesh_Generic_Provisioning_Transaction_Ack(), 129
            ),
        )