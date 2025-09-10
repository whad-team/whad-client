"""BTMesh stack Provisioning Layer unit testing

Does not test the auth or the complete messages (need the connector for it, too much hassle)

This module provides 2 sets of tests :

- TestBTMeshProvisioningProvisionee: Message processing and responses, provisionee node
- TestBTMeshProvisioningProvisioner: Message processing and responses, provisioner node
"""

from copy import copy
from time import sleep
import pytest

from whad.btmesh.stack.gen_prov import (
    GenericProvisioningLayerProvisionee,
)
from whad.btmesh.stack.gen_prov.message import GenericProvisioningMessage
from whad.btmesh.stack.provisioning import (
    ProvisioningLayerProvisionee,
    ProvisioningLayerProvisioner,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.common.stack import alias, instance
from whad.common.stack.layer import Layer, ContextualLayer
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.scapy.layers.btmesh import (
    BTMesh_Provisioning_Invite,
    BTMesh_Provisioning_Hdr,
    BTMesh_Provisioning_Public_Key,
    BTMesh_Provisioning_Capabilities,
    BTMesh_Provisioning_Start,
    BTMesh_Provisioning_Confirmation,
    BTMesh_Provisioning_Random,
    BTMesh_Provisioning_Data,
    BTMesh_Provisioning_Complete,
)
from whad.zigbee.profile.network import Network
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.models.configuration import (
    ConfigurationModelClient,
    ConfigurationModelServer,
)
from whad.btmesh.models.generic_on_off import GenericOnOffClient, GenericOnOffServer
from whad.btmesh.models import Element
from scapy.packet import Raw
from uuid import UUID


@alias("gen_prov")
class GenProvProvisionerMock(Sandbox, ContextualLayer):
    pass


@alias("gen_prov")
class GenProvProvisioneeMock(Sandbox, ContextualLayer):
    pass


class CustomProfile(BaseMeshProfile):
    elements = [
        Element(
            index=0,
            is_primary=True,
            models=[
                GenericOnOffClient(),
                GenericOnOffServer(),
                ConfigurationModelClient(),
                ConfigurationModelServer(),
            ],
        ),
        Element(
            index=1,
            is_primary=False,
            models=[GenericOnOffClient(), GenericOnOffServer()],
        ),
    ]


# Create our sandboxed pb_adv layer instantiating the gen_prov layer (needed since Provisioning layer accesses this layer...)
@alias("pb_adv")
class PBAdvMock(Sandbox):
    def __init__(self, is_provisioner=False, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        if is_provisioner:
            self.__gen_prov = self.instantiate(GenProvProvisionerMock)
        else:
            self.__gen_prov = self.instantiate(GenProvProvisioneeMock)
        self.target = self.gen_prov.name

        self.gen_prov.get_layer("provisioning").state.test_mode = True
        profile = CustomProfile(
            auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
            auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
            auto_prov_unicast_addr=2,
        )
        profile.capabilities["algorithms"] = 0b10
        profile.is_provisioner = is_provisioner
        if is_provisioner:
            profile.auto_provision()
        self.state.connector = ConnectorMock(profile=profile)

    @property
    def gen_prov(self):
        return self.__gen_prov


class ConnectorMock(object):
    def __init__(self, profile):
        self.profile = profile
        self.uuid = (UUID("ddddaaaa-aaaa-aa01-0000-000000000000"),)

    def on_provisioning_complete(self, prov_data):
        pass

    # based on default values for profile
    def get_prov_data(self, prov_data):
        net_key = self.profile.get_net_key(0)
        prov_data.net_key = net_key.net_key
        prov_data.key_index = net_key.key_index
        prov_data.flags = b"\x00"
        prov_data.iv_index = self.profile.iv_index

        prov_data.unicast_addr = 4


GenProvProvisioneeMock.add(ProvisioningLayerProvisionee)
GenProvProvisionerMock.add(ProvisioningLayerProvisioner)


class BTMeshProvisioningProvisioneeTest(object):

    @pytest.fixture(scope="class")
    def pb_adv_layer(self):
        return PBAdvMock(is_provisioner=False)


class BTMeshProvisioningProvisionerTest(object):

    @pytest.fixture(scope="class")
    def pb_adv_layer(self):
        return PBAdvMock(is_provisioner=True)


class TestBTMeshProvisioningProvisionee(BTMeshProvisioningProvisioneeTest):

    def test_rx_invite(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=0, message=BTMesh_Provisioning_Invite(attention_duration=100)
        )

        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        # recreate the capabilites packes, in case we change the hardcoded one
        # at least this doesnt fail
        profile = pb_adv_layer.state.connector.profile
        capabilities = profile.capabilities
        number_of_elements = len(profile.local_node.get_all_elements())

        # store for Confirmation Inputs
        expected_packet = BTMesh_Provisioning_Hdr(
            type=1,
            message=BTMesh_Provisioning_Capabilities(
                number_of_elements=number_of_elements, **capabilities
            ),
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_packet)
        )

    def test_rx_start(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=2,
            message=BTMesh_Provisioning_Start(
                algorithms=0x01,
                public_key_type=0,
                authentication_method=0,
                authentication_action=0,
                authentication_size=0,
            ),
        )

        pb_adv_layer.gen_prov.flush_messages()

        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        assert pb_adv_layer.gen_prov.expect([])

    def test_rx_public_key(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"k\x17\xd1\xf2\xe1,BG\xf8\xbc\xe6\xe5c\xa4@\xf2w\x03}\x81-\xeb3\xa0\xf4\xa19E\xd8\x98\xc2\x96",
                public_key_y=b"O\xe3B\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xebJ|\x0f\x9e\x16+\xce3Wk1^\xce\xcb\xb6@h7\xbfQ\xf5",
            ),
        )

        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"k\x17\xd1\xf2\xe1,BG\xf8\xbc\xe6\xe5c\xa4@\xf2w\x03}\x81-\xeb3\xa0\xf4\xa19E\xd8\x98\xc2\x96",
                public_key_y=b"O\xe3B\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xebJ|\x0f\x9e\x16+\xce3Wk1^\xce\xcb\xb6@h7\xbfQ\xf5",
            ),
        )

        # in test mode, we have hard coded values for keys generated
        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_confirmation(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=5,
            message=BTMesh_Provisioning_Confirmation(
                b"l\xf7N\xa6\xe7jV}6\x96V.\xec\xa8\x9cr\xe4\xaf\xad\x83\x89\x9aF\xe6\x04q\x9a$\xb1\xde\xa1\xcd"
            ),
        )
        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=5,
            message=BTMesh_Provisioning_Confirmation(
                b"l\xf7N\xa6\xe7jV}6\x96V.\xec\xa8\x9cr\xe4\xaf\xad\x83\x89\x9aF\xe6\x04q\x9a$\xb1\xde\xa1\xcd"
            ),
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_random(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=6,
            message=BTMesh_Provisioning_Random(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
        )
        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=6,
            message=BTMesh_Provisioning_Random(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
        )
        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_data(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=7,
            message=BTMesh_Provisioning_Data(
                encrypted_provisioning_data=bytes.fromhex(
                    "61bf302d6a0f376f6ad6215ffcf22976c56592908c2de9aa54"
                ),
                provisioning_data_mic=bytes.fromhex("805d405631e3b753"),
            ),
        )

        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=8, message=BTMesh_Provisioning_Complete()
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )


class TestBTMeshProvisioningProvisioner(BTMeshProvisioningProvisionerTest):

    def test_prov_init(self, pb_adv_layer):
        pb_adv_layer.gen_prov.get_layer("provisioning").initiate_provisioning()

        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=0, message=BTMesh_Provisioning_Invite(attention_duration=100)
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_capabilities(self, pb_adv_layer):
        # recreate the capabilites packet, in case we change the hardcoded one
        # at least this doesnt fail
        profile = pb_adv_layer.state.connector.profile
        capabilities = profile.capabilities
        number_of_elements = len(profile.local_node.get_all_elements())

        # store for Confirmation Inputs
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=1,
            message=BTMesh_Provisioning_Capabilities(
                number_of_elements=number_of_elements, **capabilities
            ),
        )
        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=2,
            message=BTMesh_Provisioning_Start(
                algorithms=0x01,
                public_key_type=0,
                authentication_method=0,
                authentication_action=0,
                authentication_size=0,
            ),
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"k\x17\xd1\xf2\xe1,BG\xf8\xbc\xe6\xe5c\xa4@\xf2w\x03}\x81-\xeb3\xa0\xf4\xa19E\xd8\x98\xc2\x96",
                public_key_y=b"O\xe3B\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xebJ|\x0f\x9e\x16+\xce3Wk1^\xce\xcb\xb6@h7\xbfQ\xf5",
            ),
        )
        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_public_key(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=3,
            message=BTMesh_Provisioning_Public_Key(
                public_key_x=b"k\x17\xd1\xf2\xe1,BG\xf8\xbc\xe6\xe5c\xa4@\xf2w\x03}\x81-\xeb3\xa0\xf4\xa19E\xd8\x98\xc2\x96",
                public_key_y=b"O\xe3B\xe2\xfe\x1a\x7f\x9b\x8e\xe7\xebJ|\x0f\x9e\x16+\xce3Wk1^\xce\xcb\xb6@h7\xbfQ\xf5",
            ),
        )

        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=5,
            message=BTMesh_Provisioning_Confirmation(
                b"l\xf7N\xa6\xe7jV}6\x96V.\xec\xa8\x9cr\xe4\xaf\xad\x83\x89\x9aF\xe6\x04q\x9a$\xb1\xde\xa1\xcd"
            ),
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_confirmation(self, pb_adv_layer):
        rx_pkt = BTMesh_Provisioning_Hdr(
            type=5,
            message=BTMesh_Provisioning_Confirmation(
                b"l\xf7N\xa6\xe7jV}6\x96V.\xec\xa8\x9cr\xe4\xaf\xad\x83\x89\x9aF\xe6\x04q\x9a$\xb1\xde\xa1\xcd"
            ),
        )
        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=6,
            message=BTMesh_Provisioning_Random(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
        )
        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )

    def test_rx_random(self, pb_adv_layer):

        rx_pkt = BTMesh_Provisioning_Hdr(
            type=6,
            message=BTMesh_Provisioning_Random(
                b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"
            ),
        )
        pb_adv_layer.gen_prov.flush_messages()
        pb_adv_layer.gen_prov.send("provisioning", rx_pkt)
        sleep(0.05)

        expected_pkt = BTMesh_Provisioning_Hdr(
            type=7,
            message=BTMesh_Provisioning_Data(
                encrypted_provisioning_data=bytes.fromhex(
                    "61bf302d6a0f376f6ad6215ffcf22976c56592908c2de9aa54"
                ),
                provisioning_data_mic=bytes.fromhex("805d405631e3b753"),
            ),
        )

        assert pb_adv_layer.gen_prov.expect(
            LayerMessage("provisioning", "gen_prov", expected_pkt)
        )
