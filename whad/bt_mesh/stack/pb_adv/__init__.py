"""
PB-ADV bearer Layer

Mostly instanciate a generic provisioning layer. Only once for a provisionee, and one per peer for a provisioner (one per link id)
"""

from random import randbytes
from whad.common.stack import Layer, alias, instance
from whad.scapy.layers.bt_mesh import EIR_PB_ADV_PDU
from scapy.layers.bluetooth import EIR_Hdr
from whad.bt_mesh.stack.gen_prov import (
    GenericProvisioningLayerProvisionee,
    GenericProvisioningLayerProvisioner,
)
from whad.bt_mesh.stack.gen_prov.message import GenericProvisioningMessage


@alias("pb_adv")
class PBAdvBearerLayer(Layer):
    def __init__(self, connector, options={}):
        # list of Generic provisioning layers for each link_id
        super().__init__(options=options)
        self.state.gen_prov_dict = {}

        # save connector (BLE Phy stack, send RAW adv pdu)
        self.__connector = connector

        if "role" in options and options["role"] == "provisioner":
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisioner
        else:
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisionee

    def send_to_gen_prov(self, packet: EIR_PB_ADV_PDU):
        """
        Sent packet to Upper layer. Instance chosen based on packet's link_id field

        :param packet: [TODO:description]
        """
        transaction_number = packet.transaction_number
        link_id = packet.link_id
        message = GenericProvisioningMessage(packet.data, transaction_number)
        self.send(self.state.gen_prov_dict[link_id].name, message)

    def get_link_id_from_instance_name(self, search_instance_name):
        """
        Reverse search of link_id/gen_prov_instances dictionnary

        :param search_instance_name: Generic Provisining Instance name
        :type search_instance_name: [TODO:type]
        """
        for link_id, gen_prov_instance in self.state.gen_prov_dict.items():
            if gen_prov_instance.name == search_instance_name:
                return link_id

    def instantiate_gen_prov(self, link_id, peer_uuid=None):
        new_gen_prov = self.instantiate(self.state.generic_prov_layer_class)
        new_gen_prov.state.peer_uuid = peer_uuid
        self.state.gen_prov_dict[link_id] = new_gen_prov
        return new_gen_prov

    def on_provisioning_pdu(self, packet):
        """
        Process an advertising packet containing a PB-ADV pdu

        :param packet: [TODO:description]
        :type packet: EIR_PB_ADV_PDU
        """
        if packet.link_id not in self.state.gen_prov_dict:
            self.instantiate_gen_prov(packet.link_id)
        self.send_to_gen_prov(packet)

    def on_new_unprovisoned_device(self, peer_uuid):
        """
        Initiate the Provisining process for a peer device from whom we received an BTMesh_Unprovisioned_Device_Beacon (and accepted to provision it)
        ONLY IN PROVISIONER ROLE

        :param peer_uuid: UUID of peer
        :type peer_uuid: str
        """
        link_id = randbytes(4)
        new_gen_prov = self.instantiate_gen_prov(link_id, peer_uuid)
        new_gen_prov.get_layer("provisioning").initiate_provisioning()

    @instance("gen_prov")
    def on_gen_prov_received(self, source, message: GenericProvisioningMessage):
        """
        Provess a packet sent by a Generic Provisining Layer Instance to be sent to peer

        :param self: [TODO:description]
        :type self: [TODO:type]
        :param source: [TODO:description]
        :type source: [TODO:type]
        :param message: [TODO:description]
        """
        packet = message.gen_prov_pkt
        transaction_number = message.transaction_number
        link_id = self.get_link_id_from_instance_name(source)
        self.__connector.send_raw(
            EIR_Hdr(type=0x29)
            / EIR_PB_ADV_PDU(link_id=link_id, transaction_number=transaction_number, data=packet)
        )
