"""
Accces Layer

Manages which Element, Model gets a Message and forwards it to the Model handler.
Manages checks on whether or not the conditions of a message to a Model in an Element are ok (which key is used, addr...)
Allows other layers to internally fetch State data from Foundation Models (SAR informations, keys, ...)
"""

import logging
from whad.common.stack import alias
from whad.btmesh.stack.access import AccessLayer
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import (
    MANAGED_FLOODING_CREDS,
    DIRECTED_FORWARDING_CREDS,
)
from whad.scapy.layers.btmesh import (
    BTMesh_Model_Directed_Forwarding_Control_Set,
    BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Set,
    BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set,
    BTMesh_Model_Directed_Forwarding_Path_Metric_Set,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Get,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Status,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status,
    BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set,
    BTMesh_Model_Generic_OnOff_Set,
    BTMesh_Model_Generic_OnOff_Set_Unacknowledged,
    BTMesh_Model_Message,
    ForwardingTableEntry,
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

        # Used to set TID in Generic On/Off (unrelated to the client ...)
        self.transaction_id = 0

        # Stores the last fw_update_id received from addresses. Key is addr (int)
        self.fw_update_ids = {}

    def show_packet(self, message):
        pkt, ctx = message
        pkt.show()

    def df_set(self, dest):
        """
        Used to set the Directed Forwarding in all nodes by sending a DIRECTED_CONTROL_SET message

        It sets up the network so that :

        - All nodes have directed forwarding enabled
        - All nodes are relay nodes
        - All nodes want to create 2 lanes per path
        - All nodes have a unicast echo interval of 1 percent of the path lifetime
        -Lane lifetime of 12 min

        (worst case scenario for the attacks basically)

        :param dest: Destination address
        :type dest: int
        """
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
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
        ctx.dest_addr = dest.to_bytes(2, "big")
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
            net_key_index=0, wanted_lanes=1
        )
        pkt = BTMesh_Model_Message() / pkt
        # self.process_new_message((pkt, ctx))
        sleep(0.3)

        # Echo interval
        ctx = copy(ctx)
        pkt = BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set(
            net_key_index=0, unicast_echo_interval=5, multicast_echo_interval=5
        )
        pkt = BTMesh_Model_Message() / pkt
        # self.process_new_message((pkt, ctx))
        sleep(0.3)

        # Lane lifetime
        ctx = copy(ctx)
        pkt = BTMesh_Model_Directed_Forwarding_Path_Metric_Set(
            net_key_index=0, path_lifetime=2, path_metric_type=0
        )
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))

        return True

    def df_table(self, dest):
        """
        Asks the dest node for its forwarding table.
        Returns the BTMesh_Model_Directed_Forwarding_Table_Entries_Status resulting message if received.
        None otherwise (after 2 seconds timeout)

        :param dest: Destination address
        :type dest: int
        """
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return

        # First message to get the Update Number
        pkt = BTMesh_Model_Directed_Forwarding_Table_Entries_Get(
            filter_mask=0b0010,
            net_key_index=0,
            start_index=0,
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

        # We wait for the response to this message ...
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))

        self.wait_for_message(BTMesh_Model_Directed_Forwarding_Table_Entries_Status)

        message = self.state.received_message
        if message is None:
            return None

        # Second message to get the FW Table
        resp_pkt, resp_ctx = self.state.received_message
        pkt = BTMesh_Model_Directed_Forwarding_Table_Entries_Get(
            filter_mask=0b0010,
            net_key_index=0,
            start_index=0,
            forwarding_table_update_identifier=resp_pkt.forwarding_table_update_identifier,
        )
        # We wait for the response to this message ...
        pkt = BTMesh_Model_Message() / pkt
        self.process_new_message((pkt, ctx))
        self.wait_for_message(BTMesh_Model_Directed_Forwarding_Table_Entries_Status)

        if self.state.received_message is None:
            return None

        # Update the stored FW Table
        resp_pkt, resp_ctx = self.state.received_message
        self.fw_update_ids[dest] = resp_pkt.forwarding_table_update_identifier
        return resp_pkt.forwarding_table_entry_list

    def df_dependents(self, dest, po, pt):
        """
        Retrives the Dependent nodes of the specified path.
        Returns the BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status received if received, or None

        Recursive !

        :param dest: Address of the node we retrive the dependent nodes from
        :type dest: int
        :param po: Path origin of the path
        :type po: int
        :param pt: Path target of the path
        :type pt: int
        """
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return

        if dest in self.fw_update_ids:
            fw_update_id = self.fw_update_ids[dest]
        else:
            fw_update_id = 0

        # Try with fw_update_id stores/ or 0
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

        self.wait_for_message(
            BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status
        )

        message = self.state.received_message
        if message is None:
            return None

        resp_pkt, resp_ctx = message

        # Check if status is not Obsolete Information, return directly
        if resp_pkt.status != 0x14:
            return resp_pkt

        # If status is Obsolete Information retrieve fw_update_id, and redo the same with updated fw_update_id
        self.fw_update_ids[dest] = resp_pkt.forwarding_table_update_identifier
        return self.df_dependents(dest, po, pt)

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
            directed_relay=0,
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

    def do_2way(self, action):
        """
        Activates or deactivates 2way paths creation of the network

        :param action: On or off
        :type action: bool
        """
        app_key = (
            self.state.profile.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(0)
        )

        if app_key is None:
            return False

        pkt = BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set(
            net_key_index=0, two_way_path=int(action)
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
