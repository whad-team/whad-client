"""
PB-ADV bearer Layer

Mostly instanciate a generic provisioning layer. Only once for a device, and one per peer for a provisioner (one per link id)
"""

import logging
from whad.common.stack import Layer, alias, source, instance
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU
from whad.bt_mesh.stack.gen_prov import (
    GenericProvisioningLayerDevice,
    GenericProvisioningLayerProvisioner,
)
from whad.bt_mesh.stack.gen_prov.message import GenericProvisioningMessage


@alias("pb_adv")
class PBAdvBearerLayer(Layer):
    def configure(self, options):
        # list of Generic provisioning layers for each link_id
        self.state.gen_prov_dict = {}
        if "role" in options and options["role"] == "provisioner":
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisioner
        else:
            self.state.generic_prov_layer_class = GenericProvisioningLayerDevice

    def send_to_gen_prov(self, packet: EIR_PB_ADV_PDU):
        transaction_number = packet.transaction_number
        link_id = packet.link_id
        message = GenericProvisioningMessage(packet[1], transaction_number)
        self.send(self.state.gen_prov_dict[link_id].name, message)

    def get_link_id_from_instance_name(self, search_instance_name):
        for link_id, gen_prov_instance in self.state.gen_prov_dict.items():
            if gen_prov_instance.name == search_instance_name:
                return link_id

    def on_packet_received(self, packet):
        if packet.link_id in self.state.gen_prov_dict:
            self.send_to_gen_prov(packet)
        else:
            new_gen_prov = self.instantiate(self.state.generic_prov_layer_class)
            self.state.gen_prov_dict[packet.link_id] = new_gen_prov
            self.send_to_gen_prov(packet)

    @instance("gen_prov")
    def on_gen_prov_received(self, source, message: GenericProvisioningMessage):
        packet = message.gen_prov_pkt
        transaction_number = message.transaction_number
        link_id = self.get_link_id_from_instance_name(source)
        self.send(
            "phy",
            EIR_PB_ADV_PDU(link_id=link_id, transaction_number=transaction_number)
            / packet,
        )

