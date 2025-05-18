"""
Bluetooth Mesh PB-ADV Device connector
=========================================

This connector implements a simple PB-ADV enable device. Both algorithms supported
Can be provisioned by a PB-ADV enabled provisioner
It used the BLE core stack.

It then behaves like a Generic On/Off Server.

The connector provides some callbacks such as :meth:`Peripheral.on_connected` to
react on specific events.
"""


# Add arguments to connector for models/states

from whad.btmesh.connectors.provisionee import Provisionee

from whad.scapy.layers.btmesh import *
from whad.btmesh.stack.network import NetworkLayer

from whad.btmesh.profile import BaseMeshProfile

from threading import Thread


class DFAttacks(Provisionee):
    def __init__(
        self,
        device,
        profile=BaseMeshProfile(),
    ):
        """
        Contructor of a Provisionee (node) device with Directed forwarding attacks capabilities

        :param device: Device object
        :type device: Device
        :param profile: Profile class used for the node (elements and models layout), defaults to BaseMeshProfile
        """
        super().__init__(
            device,
            profile,
        )

        self.whitelist = []

        # Add the df_attacks for the upper_transport
        self.options = {
            "profile": self.profile,
            "lower_transport": {
                "profile": self.profile,
                "df_attacks": True,
                "upper_transport": {
                    "profile": self.profile,
                    "access": {"profile": self.profile},
                },
            },
        }

        self._main_stack = NetworkLayer(connector=self, options=self.options)

    def do_network_discovery(self, addr_low, addr_high, delay=3.5):
        """
        launch the discovery attack

        :param addr_low: Lowest address to test
        :type addr_low: int
        :param addr_high: Highest address to test
        :type addr_high: int
        :param delay: Delay between 2 Path Requests, defaults to 3.5
        :type delay: float, optional
        """
        thread = Thread(
            target=self._main_stack.get_layer(
                "upper_transport"
            ).discover_topology_thread,
            args=[addr_low, addr_high, delay],
        )
        thread.start()

    def do_get_hops(self):
        """
        Get the distance between attacker to discovred node via network discovery attack
        """
        thread = Thread(
            target=self._main_stack.get_layer("upper_transport").discovery_get_hops
        )
        thread.start()

    def get_network_topology(self):
        """
        Returns the Topology dictionary
        """
        return self._main_stack.get_layer("upper_transport").get_network_topology()

    def df_set(self, dest):
        """
        Activates DF via a DIRECTED_CONTROL_SET (Access message) to the destination specified

        :param dest: Target addr
        :type dest: int
        """
        return self._main_stack.get_layer("access").df_set(dest)

    def a3_attack(self, victim_addr):
        """
        Perform the A5 attack

        :param victim_addr: Addr of the victim
        :type victim_addr: int
        """
        return self._main_stack.get_layer("upper_transport").a5_attack(victim_addr)

    def a4_attack(self, addr_list):
        """
        Perform the A4 attack

        :param addr_list: List of addr to put in the Path Request Solicitation message
        :type addr_list: List[int]
        """
        self._main_stack.get_layer("upper_transport").a4_attack(addr_list)

    def a2_attack(self, action):
        """
        Activate or not the A2 attack reaction to Path request messages

        :param action: True to activate, False to deactivate
        :type action: Bool
        """
        self._main_stack.get_layer("upper_transport").a2_attack(action)

    def df_table(self, dest):
        """
        Sends a FORWARDING_TABLE_ENTRIES_GET message and waits for the reponse (in Access layer, DFAttacks style)
        """
        return self._main_stack.get_layer("access").df_table(dest)

    def df_dependents(self, dest, po, pt):
        """
        Sends a FORWARDING_TABLE_ENTRIES_GET message and waits for the response (in Access later, DFAttacks style)
        """
        return self._main_stack.get_layer("access").df_dependents(dest, po, pt)

    def df_reset(self, addr):
        """
        Resets the DF of the specified addr

        :param addr: Target addr
        :type addr: int
        """
        self._main_stack.get_layer("access").df_reset(addr)

    def do_2way(self, action):
        """
        Activates or deactivates 2way paths creation of the network

        :param action: On or off
        :type action: bool
        """
        self._main_stack.get_layer("access").do_2way(action)
