"""
Accces Layer

Manages which Element, Model gets a Message and forwards it to the Model handler.
Manages checks on whether or not the conditions of a message to a Model in an Element are ok (which key is used, addr...)
Allows other layers to internally fetch State data from Foundation Models (SAR informations, keys, ...)
"""

import logging
from whad.common.stack import alias
from whad.btmesh.stack.access import AccessLayer
from whad.btmesh.stack.utils import MeshMessageContext, MANAGED_FLOODING_CREDS
from whad.scapy.layers.btmesh import (
    BTMesh_Model_Directed_Forwarding_Control_Set,
    BTMesh_Model_Message,
)


logger = logging.getLogger(__name__)


@alias("access")
class DFAttacksAccessLayer(AccessLayer):
    def configure(self, options={}):
        """
        AccessLayer. One for all the networks.
        """
        super().configure(options=options)

    def df_set(self, app_key_index):
        """
        Used to set the Directed Forwarding in all nodes by sending a DIRECTED_CONTROL_SET message

        :param app_key_index: App key index chosen
        :type app_key_index: int
        :returns: True if success, False if fail (no app key with specified app key index)
        """
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(app_key_index)
        )

        if app_key is None:
            return False

        pkt = BTMesh_Model_Directed_Forwarding_Control_Set(
            net_key_index=0,
            directed_forwarding=1,
            directed_relay=1,
            directed_proxy=0xFF,
            directed_proxy_use_directed_default=0xFF,
            directed_friend=0xFF,
        )
        ctx = MeshMessageContext()

        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = b"\xff\xff"
        ctx.ttl = 127
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = app_key.key_index
        ctx.aid = app_key.aid

        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
        return True
