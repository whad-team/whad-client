"""
PB-ADV bearer Layer

Mostly instanciate a generic provisioning layer. Only once for a provisionee, and one per peer for a provisioner (one per link id)
"""

from os import urandom
from whad.common.stack import Layer, alias, instance
from whad.btmesh.stack.utils import (
    ProvisioningCompleteData,
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
        is_provisioner=False,
        options={},
    ):
        """
        Initiates the PB-ADV layer.

        :param connector: The connector that creates this layer
        :type connector: BTMesh
        :param is_provisioner: Is the device a provisioner node ?, defaults to False
        :type is_provisioner: bool, optional
        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """
        # list of Generic provisioning layers for each link_id
        super().__init__(options=options)

        # Current link_id (the current Provisining process running)
        self.state.current_link_id = None

        # Current instance of the GenericProvisioningLayer used
        self.state.gen_prov_layer = None

        # save connector (BLE Phy stack, send RAW adv pdu)
        self.__connector = connector

        self.state.is_provisioner = is_provisioner

        if self.state.is_provisioner:
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisioner
        else:
            self.state.generic_prov_layer_class = GenericProvisioningLayerProvisionee

        # Capabilities of the Device, set via shell or user function in this class. Passed to Provisioning layer when GenericProvisioningLayer instanciated
        self.state.capabilities = dict(
            algorithms=0b11,  # default support 2 algs
            public_key_type=0x00,  # default no OOB public key support
            oob_type=0b00,  # no static OOB supported
            output_oob_size=0x00,
            output_oob_action=0b00000,  # default no output OOB action available
            input_oob_size=0x00,
            input_oob_action=0b0000,  # default no input OOB a available
        )

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
        new_gen_prov = self.instantiate(self.state.generic_prov_layer_class)
        new_gen_prov.state.peer_uuid = peer_uuid
        new_gen_prov.get_layer("provisioning").set_capabilities(self.state.capabilities)

        if self.state.gen_prov_layer is not None:
            self.state.gen_prov_layer.destroy()

        self.state.gen_prov_layer = new_gen_prov
        self.state.current_link_id = link_id
        return new_gen_prov

    def on_provisioning_pdu(self, packet):
        """
        Process an advertising packet containing a PB-ADV pdu

        :param packet: [TODO:description]
        :type packet: EIR_PB_ADV_PDU
        """
        if self.state.gen_prov_layer is None:
            # If no gen_prov layer existing and Provisioner mode, somthing went wrong ...
            if self.state.is_provisioner:
                return

            else:
                # We check that the packet is,a Link Open corresponding to out uuid if provisionee mode
                if (
                    packet.transaction_number == 0
                    and isinstance(packet.data, BTMesh_Generic_Provisioning_Link_Open)
                    and packet.data.device_uuid == self.__connector.uuid
                ):
                    self.instantiate_gen_prov(packet.link_id)

                    # if a provisionee, stop beacons
                    if not self.state.is_provisioner:
                        self.__connector.stop_unprovisioned_beacons()

                else:
                    return

        self.send_to_gen_prov(packet)

    def on_auth_data(self, auth_data):
        """
        Process a ProvisioningAuthenticationData sent by the connector when the user typed an auth value (interactive shell or cli)

        :param auth_data: The auth data
        :type auth_data: ProvisioningAuthenticationData
        """
        self.send_to_gen_prov(auth_data)

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

        # In provisioner mode only, we finished the provisininning of the target node
        # We add its dev_key to
        if message == "FINISHED_PROV":
            self.__connector.distant_node_provisioned = True
            if self.__connector.prov_event is not None:
                self.__connector.prov_event.set()

            return

        # if message is ProvisioningCompleteData, we complete the provisonning of our node
        if isinstance(message, ProvisioningCompleteData):
            self._is_provisioning = False
            self.__connector.provisionning_complete(message)
            return

        # If Authentication data needed
        if isinstance(message, ProvisioningAuthenticationData):
            self.__connector.provisonning_auth_data(message)
            return

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
        self.__connector.send_raw(pkt)

    def set_capability(self, name, value):
        """
        Sets the capablity whose key is name arg with the value. Used when instanciating a new GenericProvisioningLayer and Provisioning layers
        Need to be set before the provisioning started ...

        :param name: Name (key in the dict) of the capablity
        :type name: str
        :param value: Value to set
        :type value: int
        :returns: True if success, False if fail
        :rtype: bool
        """

        if name not in self.state.capabilities.keys():
            return False

        self.state.capabilities[name] = value
        return True

    def get_capabilities(self):
        """
        Returns the dict of capablities that will be used/has been used when instanciating a new GenericProvisioningLayer and Provisining layers.

        :returns: The dict of capablities in ProvisioningState
        :rtype: dict
        """
        return self.state.capabilities
