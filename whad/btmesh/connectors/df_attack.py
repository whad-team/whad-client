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
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.stack.constants import (
    MANAGED_FLOODING_CREDS,
    DIRECTED_FORWARDING_CREDS,
)

from whad.btmesh.profile import BaseMeshProfile

from threading import Thread


class DFAttacks(Provisionee):
    def __init__(
        self,
        device,
        profile=BaseMeshProfile(),
        auto_provision=False,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=b"\x00\x02",
    ):
        """
        Contructor of a Provisionee (node) device
        Support for only one element per node

        :param device: Device object
        :type device: Device
        :param profile: Profile class used for the node (elements and models layout), defaults to BaseMeshProfile
        :param auto_provision: Is the node auto provisioned ?, defaults to False
        :type auto_provision: Bool, optional
        :param net_key: If auto provisioned : primary NetKey , defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type net_key: Bytes, optional
        :param app_key: If auto provisioned : primary app key and dev key, defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type app_key: Bytes, optional
        :param unicast_addr: If auto provisioned, unicast addr, defaults to b"\x00\x02"
        :type unicast_addr: Bytes, optional
        """
        super().__init__(
            device,
            profile,
            auto_provision=False,
            net_key=net_key,
            app_key=app_key,
            unicast_addr=unicast_addr,
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

        if auto_provision:
            self.auto_provision(net_key, app_key, unicast_addr)

    def do_network_discovery(self, addr_low, addr_high):
        """
        launch the discovery attack

        :param addr_low: Lowest address to test
        :type addr_low: int
        :param addr_high: Highest address to test
        :type addr_high: int
        """
        thread = Thread(
            target=self._main_stack.get_layer(
                "upper_transport"
            ).discover_topology_thread,
            args=[addr_low, addr_high],
        )
        thread.start()

    def do_get_hops(self):
        """
        Get the distance between attacker to discovred node via network discovery attack
        """
        self._main_stack.get_layer("upper_transport").discovery_get_hops()

    def reset_whitelist(self):
        """
        Resets the whitelist
        """
        self.whitelist = []

    def add_whitelist(self, addr):
        """
        Adds an address to the whitelist

        :param addr: BD Addr to add
        :type addr: str
        """
        addr = addr.lower()
        if addr not in self.whitelist:
            self.whitelist.append(addr)

    def remove_whitelist(self, addr):
        """
        Removes an address from the whitelist

        :param addr: BD Addr to remove
        :type addr: str
        """
        try:
            index = self.whitelist.index(addr.lower())
        except ValueError:
            return
        self.whitelist.pop(index)

    def get_network_topology(self):
        """
        Returns the Topology dictionary
        """
        return self._main_stack.get_layer("upper_transport").get_network_topology()

    def df_set(self, app_key_index):
        """
        Activates DF via a DIRECTED_CONTROL_SET (Access message) to all nodes

        :param app_key_index: App key index to use
        :type app_key_index: int
        :returns: True is success, False otherwise
        """
        return self._main_stack.get_layer("access").df_set(app_key_index)

    def a5_attack(self, victim_addr):
        """
        Perform the A5 attack

        :param victim_addr: Addr of the victim
        :type victim_addr: int
        """
        self._main_stack.get_layer("upper_transport").a5_attack(victim_addr)

    def a3_attack(self, addr_list):
        """
        Perform the A3 attack

        :param addr_list: List of addr to put in the Path Request Solicitation message
        :type addr_list: List[int]
        """
        self._main_stack.get_layer("upper_transport").a3_attack(addr_list)

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

    def do_onoff(self, value, addr, acked):
        """
        Sends a Generic On/Off set message (acked or unacked)

        :param value: Value to be set (0 or 1)
        :type value: int
        :param addr: Destination addr
        :type addr: int
        :param acked: Whether the messages is acked or not
        :type acked: Bool
        """
        self._main_stack.get_layer("access").do_onoff(value, addr, acked)
