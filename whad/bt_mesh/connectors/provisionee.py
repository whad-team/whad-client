"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""

from whad.bt_mesh.stack import PBAdvBearerLayer
from whad.bt_mesh.connectors import BTMesh
from whad.bt_mesh.stack.utils import ProvisioningCompleteData

from whad.scapy.layers.bt_mesh import *
from whad.bt_mesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerAppKeyCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
    ProvisioningBearerAdvCryptoManagerProvisionee,
)
from whad.bt_mesh.models.states import *
from whad.bt_mesh.models.configuration import ConfigurationModelServer
from whad.bt_mesh.models import GlobalStatesManager, Element
from whad.bt_mesh.stack.network import NetworkLayer


class Provisionee(BTMesh):
    def __init__(self, device):
        super().__init__(
            device, stack=PBAdvBearerLayer, options={"role": "provisionee"}
        )

        self.is_provisioned = False

    def process_rx_packets(self, packet):
        """
        Process a received Mesh Packet. Sends to stack if provisioning PDU

        :param packet: Packet received
        :type packet: Packet
        """
        if not self.is_provisioned:
            if packet.haslayer(EIR_PB_ADV_PDU):
                self._stack.on_provisioning_pdu(packet.getlayer(EIR_PB_ADV_PDU))
        elif packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            print("YEEEESSSSSSSS")
            self._main_stack.on_net_pdu_received(
                packet.getlayer(BTMesh_Obfuscated_Network_PDU)
            )

    def provisionning_complete(self, prov_data):
        """
        When Provisionning is complete, we received the information to setup the node and start normal behavior with main stack

        :param prov_data: The provisionning data content
        :type prov_data: ProvisioningCompleteData
        """

        # setup the main states and models
        primary_element = Element(addr=prov_data.unicast_addr, is_primary=True)
        primary_net_key = NetworkLayerCryptoManager(
            key_index=prov_data.key_index, net_key=prov_data.net_key
        )

        dev_key = UpperTransportLayerDevKeyCryptoManager(
            provisioning_crypto_manager=prov_data.provisionning_crypto_manager
        )

        global_states = GlobalStatesManager()

        conf_model = ConfigurationModelServer(element_addr=primary_element.addr)

        # Instance of all states and models for the ConfigurationModelServer
        conf_publish_state = ModelPublicationCompositeState()
        global_states.add_state(
            conf_publish_state,
            element_addr=primary_element.addr,
            model_id=conf_model.model_id,
        )

        conf_sub_state = SubscriptionListState()
        global_states.add_state(
            conf_sub_state,
            element_addr=primary_element.addr,
            model_id=conf_model.model_id,
        )

        conf_net_key_state = NetKeyListState()
        global_states.add_state(conf_net_key_state)
        conf_net_key_state.set_value(
            field_name=primary_net_key.key_index, value=primary_net_key
        )

        conf_app_key_state = AppKeyListState()
        conf_app_key_state.set_value(field_name=-1, value=dev_key)
        global_states.add_state(conf_app_key_state)

        conf_model_to_app_key = ModelToAppKeyListState()
        conf_model_to_app_key.set_value(field_name=0, value=[-1])
        global_states.add_state(conf_model_to_app_key)

        conf_ttl = DefaultTLLState()
        global_states.add_state(conf_ttl)

        conf_relay = RelayState()
        global_states.add_state(conf_relay)

        conf_attention = AttentionTimeState()
        global_states.add_state(conf_attention)

        conf_secure_net_beacon = SecureNetworkBeaconState()
        global_states.add_state(conf_secure_net_beacon)

        conf_gatt_proxy = GattProxyState()
        global_states.add_state(conf_gatt_proxy)

        conf_node_id = NodeIdentityState()
        global_states.add_state(conf_node_id, net_key_index=primary_net_key.key_index)

        conf_hb_pub = HeartbeatPublicationCompositeState()
        global_states.add_state(conf_hb_pub)

        conf_hb_sub = HeartbeatSubscriptionCompositeState()
        global_states.add_state(conf_hb_sub)

        sar_receiver = SARReceiverCompositeState()
        global_states.add_state(sar_receiver)

        sar_transmitter = SARTransmitterCompositeState()
        global_states.add_state(sar_transmitter)

        primary_element.register_model(conf_model)

        self._main_stack = NetworkLayer()
        self.is_provisioned = True
