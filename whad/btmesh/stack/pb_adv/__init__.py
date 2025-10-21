"""
PB-ADV bearer Layer

Mostly instanciate a generic provisioning layer. Only once for a provisionee, and one per peer for a provisioner (one per link id)
Also used as a relay from other upper layers to the profile/connector
"""

from os import urandom
from whad.common.stack import Layer, alias, instance
from whad.btmesh.stack.utils import (
    ProvisioningData,
    ProvisioningAuthenticationData,
)
from whad.scapy.layers.btmesh import (
    EIR_PB_ADV_PDU,
    BTMesh_Generic_Provisioning_Link_Open,
)
from scapy.layers.bluetooth import EIR_Hdr
from whad.btmesh.stack.gen_prov import (
    GenericProvisioningLayerProvisionee,
    GenericProvisioningLayerProvisioner,
)
from whad.btmesh.stack.gen_prov.message import GenericProvisioningMessage
from threading import Thread


@alias("pb_adv")
class PBAdvBearerLayer(Layer):
    def __init__(
        self,
        connector,
        options={},
    ):
        """
        Initiates the PB-ADV layer.

        :param connector: The connector that creates this layer
        :type connector: BTMesh
        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """
        # list of Generic provisioning layers for each link_id
        super().__init__(options=options)

        # Custom handler for packets received from parent layer
        # Should take the message as argument
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

        # Current link_id (the current Provisining process running)
        self.state.current_link_id = None

        # Current instance of the GenericProvisioningLayer used
        self.state.gen_prov_layer = None

        # save connector (send RAW adv pdu)
        self.state.connector = connector

        self.state.is_provisioner = self.state.connector.profile.is_provisioner

        if self.state.is_provisioner:
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisioner
        else:
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisionee

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Access Message with class (Scapy packet) specified
        If long processing, creating a handler that launches a seperate thread is advised.

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking (Packet | MeshMessageContext) as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_handler(self, clazz):
        """
        Unregisters a previously registerd custom callback for an Access message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def send_to_gen_prov(self, packet):
        """
        Sent packet to Upper layer. Instance chosen based on packet's link_id field

        :param packet: [TODO:description]
        :type packet: EIR_PB_ADV_PDU | ProvisioningAuthenticationData
        """
        if isinstance(packet, EIR_PB_ADV_PDU):
            transaction_number = packet.transaction_number
            message = GenericProvisioningMessage(packet.data, transaction_number)
        elif isinstance(packet, ProvisioningAuthenticationData):
            message = packet

        self.send(self.state.gen_prov_layer.name, message)

    def instantiate_gen_prov(self, link_id, peer_uuid=None):
        """
        Create an Instance of GenericProvisioningLayer when a provisioning process is started
        A new one is created for each provisioning process.

        :param link_id: link_id of the provisioning process
        :type link_id: str
        :param peer_uuid: The uuid of the peer node, defaults to None
        :type peer_uuid: str, optional
        """
        if self.state.gen_prov_layer is not None:
            self.destroy(self.state.gen_prov_layer)

        self.state.gen_prov_layer = self.instantiate(
            self.state.generic_prov_layer_class
        )
        self.state.gen_prov_layer.state.peer_uuid = peer_uuid
        self.state.current_link_id = link_id
    
        return self.state.gen_prov_layer

    def on_provisioning_pdu(self, packet):
        """
        Process an advertising packet containing a PB-ADV pdu

        :param packet: [TODO:description]
        :type packet: EIR_PB_ADV_PDU
        """
        # if custom handler, use it
        if type(packet) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(packet)](packet)
            # if custom handler says to return after itself
            if not continue_processing:
                return

        # if provisionee node and already provisionned, ignore
        if (
            not self.state.is_provisioner
            and self.state.connector.profile.is_provisioned
        ):
            return

        if self.state.gen_prov_layer is None:
            # If no gen_prov layer existing and Provisioner mode, somthing went wrong ...
            if self.state.is_provisioner:
                return

            else:
                # We check that the packet is,a Link Open corresponding to out uuid if provisionee mode
                if (
                    packet.transaction_number == 0
                    and isinstance(packet.data, BTMesh_Generic_Provisioning_Link_Open)
                    and packet.data.device_uuid == self.state.connector.uuid
                ):
                    self.instantiate_gen_prov(packet.link_id)

                    # if a provisionee, stop beacons
                    if not self.state.is_provisioner:
                        self.state.connector.stop_unprovisioned_beacons()

                else:
                    return

        self.send_to_gen_prov(packet)

    def on_new_unprovisoned_device(self, peer_uuid):
        """
        Initiate the Provisining process for a peer device from whom we received an BTMesh_Unprovisioned_Device_Beacon (and accepted to provision it)
        ONLY IN PROVISIONER ROLE

        :param peer_uuid: UUID of peer
        :type peer_uuid: str
        """
        link_id = urandom(4)
        self.state.gen_prov_layer = self.instantiate_gen_prov(link_id, peer_uuid)
        self.state.current_link_id = link_id
        self.state.gen_prov_layer.get_layer("provisioning").initiate_provisioning()

    def on_provisioning_auth_data(self, prov_data):
        """
        Called by connector when auth data is given for the Provisining layer
        Have to go through this layer since connector doesnt know instance name

        :param prov_data: [TODO:description]
        """
        self.state.gen_prov_layer.get_layer("provisioning").on_provisioning_auth_data(
            prov_data
        )

    @instance("gen_prov")
    def on_gen_prov_received(self, source, message):
        """
        Process a packet sent by a Generic Provisining Layer Instance to be sent to peer

        :param self: [TODO:description]
        :type self: [TODO:type]
        :param source: [TODO:description]
        :type source: [TODO:type]
        :param message: [TODO:description]
        """
        packet = message.gen_prov_pkt
        transaction_number = message.transaction_number
        pkt = EIR_Hdr(type=0x29) / EIR_PB_ADV_PDU(
            link_id=self.state.current_link_id,
            transaction_number=transaction_number,
            data=packet,
        )

        thread = Thread(
            target=self.sending_thread,
            args=(pkt),
        )

        thread.start()

    def sending_thread(self, pkt):
        self.state.connector.send(pkt)
