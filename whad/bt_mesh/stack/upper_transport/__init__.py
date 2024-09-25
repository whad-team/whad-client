"""
Upper Transport Layer

Performs encryption and decryption at application level for Access Messages
Sends and respondes to UpperLayer Control messages (no application encryption)
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.models import GlobalStatesManager
from whad.bt_mesh.stack.utils import (
    get_address_type,
    VIRTUAL_ADDR_TYPE,
)
from whad.scapy.layers.bt_mesh import (
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Model_Message,
)
from whad.bt_mesh.stack.access import AccessLayer
from scapy.all import raw
from whad.bt_mesh.crypto import UpperTransportLayerAppKeyCryptoManager

logger = logging.getLogger(__name__)


@alias("upper_transport")
class UpperTransportLayer(Layer):
    def configure(self, options={}):
        """
        UpperTransportlayer. One for all the networks.
        For now we just discard the control messages since we dont support any of the features
        """
        super().configure(options=options)
        self.state.global_states_manager = GlobalStatesManager()

        self.__handlers = {}

        # we dont wrap around ataumatically, shouldnt be used for real applications thus should never overlflow
        self.state.seq_num = 0

    def send_to_lower_transport(self, message):
        """
        Sends an encrypted Upper Layer Access PDU and its context to the Lower Transport Layer

        :param message: The PDU and its context
        :type message: (BTMesh_Upper_Transport_Access_PDU, MeshMessageContext)
        """
        self.send("lower_transport", message)

    def send_to_access_layer(self, message):
        """
        Sends the decrypted Access PDU to the Access Layer with its context

        :param message: The PDU and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        self.send("access", message)

    @source("access")
    def on_access_message(self, message):
        """
        Process an Access message sent by the Access layer

        :param message: Message and its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message

        # encrypt the message with the key
        key = self.state.global_states_manager.get_state("app_key_list").get_value(
            ctx.application_key_id
        )

        # set the PDU sequence number
        # max 4 fragments !
        ctx.seq_number = self.state.global_states_manager.get_next_seq_number(inc=4)
        print("SENDING ACCESS MSG WITH SEQ_NUMBER " + str(ctx.seq_number))
        if get_address_type(ctx.dest_addr) == VIRTUAL_ADDR_TYPE:
            encrypted_message, ctx.seq_auth = key.encrypt(
                access_message=raw(pkt),
                aszmic=0,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.global_states_manager.iv_index,
                label_uuid=ctx.uuid,
            )
        else:
            encrypted_message, ctx.seq_auth = key.encrypt(
                access_message=raw(pkt),
                aszmic=0,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.global_states_manager.iv_index,
            )
        pkt = BTMesh_Upper_Transport_Access_PDU(encrypted_message)
        self.send_to_lower_transport((pkt, ctx))

    @source("lower_transport")
    def on_lower_transport_message(self, message):
        """
        Process a message sent by the Lower Transport Layer with its context
        Can be a control message OR an encrypted Access message
        For now control messages are discarded

        :param message: Message and its context
        :type message: (Packet, MeshMessageContext)
        """
        pkt, ctx = message
        pkt.show()

        # if control message, just show it and bye
        if not isinstance(pkt, BTMesh_Upper_Transport_Access_PDU):
            pkt.show()
            return

        # get the application or device key for the message
        key = self.state.global_states_manager.get_state("app_key_list").get_value(
            ctx.application_key_id
        )
        if get_address_type(ctx.dest_addr) == VIRTUAL_ADDR_TYPE:
            (plaintext_message, is_auth_valid) = key.decrypt(
                enc_data=raw(pkt),
                aszmic=ctx,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.global_states_manager.iv_index,
                label_uuid=ctx.uuid,
            )
        else:
            (plaintext_message, is_auth_valid) = key.decrypt(
                enc_data=raw(pkt),
                aszmic=0,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
                dst_addr=ctx.dest_addr,
                iv_index=self.state.global_states_manager.iv_index,
            )

        if not is_auth_valid:
            logger.warn("WRONG AUTHENTICATION VALUE IN UpperTransportlayer")
            print(key)
            print(is_auth_valid)
            print(plaintext_message)
            return

        pkt = BTMesh_Model_Message(plaintext_message)
        self.send_to_access_layer((pkt, ctx))


UpperTransportLayer.add(AccessLayer)
