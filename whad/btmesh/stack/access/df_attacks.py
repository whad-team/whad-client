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
    BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Set,
    BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set,
    BTMesh_Model_Directed_Forwarding_Path_Metric_Set,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Get,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Status,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status,
    BTMesh_Model_Message,
)
from copy import copy
from time import sleep


logger = logging.getLogger(__name__)


@alias("access")
class DFAttacksAccessLayer(AccessLayer):
    def configure(self, options={}):
        """
        AccessLayer. One for all the networks.
        """
        super().configure(options=options)

        self._custom_handlers[BTMesh_Model_Directed_Forwarding_Table_Entries_Status] = (
            self.show_packet
        )
        self._custom_handlers[
            BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status,
        ] = self.show_packet

    def show_packet(self, message):
        pkt, ctx = message
        pkt.show()

    def df_set(self, app_key_index):
        """
        Used to set the Directed Forwarding in all nodes by sending a DIRECTED_CONTROL_SET message

        It sets up the network so that :

        - All nodes have directed forwarding enabled
        - All nodes are relay nodes
        - All nodes want to create 2 lanes per path
        - All nodes have a unicast echo interval of 1 percent of the path lifetime
        -Lane lifetime of 12 min

        (worst case scenario for the attacks basically)

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

        # Set DF
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
        sleep(0.3)

        # Wanted lanes
        ctx = copy(ctx)
        pkt = BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Set(
            net_key_index=0, wanted_lanes=2
        )
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
        sleep(0.3)

        # Echo interval
        ctx = copy(ctx)
        pkt = BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set(
            net_key_index=0, unicast_echo_interval=5, multicast_echo_interval=5
        )
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
        sleep(0.3)

        # Lane lifetime
        ctx = copy(ctx)
        pkt = BTMesh_Model_Directed_Forwarding_Path_Metric_Set(
            net_key_index=0, path_lifetime=0, path_metric_type=0
        )
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))

        return True

    def df_entry(self, dest, fw_update_id):
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return

        pkt = BTMesh_Model_Directed_Forwarding_Table_Entries_Get(
            filter_mask=0b0010,
            net_key_index=0,
            start_index=0,
            forwarding_table_update_identifier=fw_update_id,
        )
        ctx = MeshMessageContext()

        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = dest.to_bytes(2, "big")
        ctx.ttl = 127
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = 0
        ctx.aid = app_key.aid

        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))

    def df_dependents(self, dest, fw_update_id, po, pt):
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return

        pkt = BTMesh_Model_Directed_Forwarding_Table_Dependents_Get(
            fixed_path_flag=0,
            dependents_list_mask=0b11,
            net_key_index=0,
            start_index=0,
            path_origin=po,
            destination=pt,
            forwarding_table_update_identifier=fw_update_id,
        )
        ctx = MeshMessageContext()
        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = dest.to_bytes(2, "big")
        ctx.ttl = 127
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = 0
        ctx.aid = app_key.aid

        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))

    def df_reset(self, addr):
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return False

        pkt = BTMesh_Model_Directed_Forwarding_Control_Set(
            net_key_index=0,
            directed_forwarding=0,
            directed_relay=1,
            directed_proxy=0xFF,
            directed_proxy_use_directed_default=0xFF,
            directed_friend=0xFF,
        )
        ctx = MeshMessageContext()

        ctx.creds = MANAGED_FLOODING_CREDS
        ctx.src_addr = self.state.profile.primary_element_addr.to_bytes(2, "big")
        ctx.dest_addr = addr.to_bytes(2, "big")
        ctx.ttl = 127
        ctx.is_ctl = False
        ctx.net_key_id = 0
        ctx.application_key_index = app_key.key_index
        ctx.aid = app_key.aid

        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
