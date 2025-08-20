"""
Base attacker object for the Bluetooth Mesh stack.

Using an existing provisioned local node and all its information, we override its protocol stack with the appropriate one
to conduct attacks.
"""

import logging

from dataclasses import dataclass, field
from threading import Thread, Event


logger = logging.getLogger(__name__)


@dataclass
class AttackerConfiguration:
    """
    Configuration for an Attack


    :param victim: address of the victim (placeholder for example) (v)
    """

    victim: int = 0x0005


from copy import deepcopy


class Attacker:
    """Base attacker object for the Bluetooth Mesh stack.

        Using an existing provisioned local node (or unprovisionned if not needed) and all its information, we override its protocol stack with the appropriate one
    to conduct attacks.

    This is an interface class, no attacks performed here.

    While an attack is running, the local node does not keep its normal behaviour (attack dependent).
    """

    def __init__(self, connector, configuration=AttackerConfiguration()):
        """Initializes the attacker object with the given connector.

        Saves the context of the connector before conducting the attack.
        The attacker object can change some values after the attack (seq numbers for example)
        depending on the attack performed.

        A configuration object specific to that Attacker object might be passed

        :param connector: The btmesh connector to use
        :type connector: BTMesh
        :param configuration: The configuration to use
        :type configuration: AttackerConfiguration
        """
        # The snapshot of the connector we will use for the attack (can be modified, and is affected by changes to the original profile)
        self._connector = connector

        # has the connector, profile and stacks been setup for the attack ? (_setup function)
        self._is_setup = False

        # Set to true when launching the attack, can be used in custom handlers to keep normal functionnality when non started
        self._is_attack_running = False

        self._configuration = configuration

        # After launching, is the attack a success ? (from the information we can gather...)
        self._success = None

        # Even set when attack is finished/failed/timeoudout or used to stop it
        self._event = Event()

        self._name = "Default Attacker"

        self._setup()

    @property
    def event(self):
        return self._event

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def success(self):
        return self._success

    @success.setter
    def success(self, value):
        self._success = value

    def _setup(self):
        """Setup of the connector, profile, stack handlers... for the attack.
        Need to be programmed in tandem with self.restore to restore what we change here (and during the attack) if needed.

        Called in init function
        """
        self._connector.stop()
        # Example of setting the seq number to another (here). We first stash the value
        self._backup_seq_num = self._connector.profile.seqnum
        self._connector.profile.seqnum = 0x1
        self._connector.start()
        self._is_setup = True

    def restore(self):
        """
        Restored the original connector and all its attributes to the way it was before creating the Attacker object
        Each attack class need to know what is could possibly change that needs to be reversed.
        As an example here, we restore the original stack.
        """
        self._is_setup = False
        self._connector.profile.seqnum = self._backup_seq_num

    def configure(self, configuration):
        """
        Configure the Attacker with the proper parameters in the Configuration object

        :param configuration: The configuration to use
        """
        self._configuration = configuration

    def _attack_runner(self):
        """
        The heart of the attack (where the logic should be implemented)
        If the attack is only on react to other messages, this might do nothing.
        """
        self._is_attack_running = True
        logging.debug(
            "Attacking with placeholder attack victim %x" % self._configuration.victim
        )
        self._success = True
        self._is_attack_running = False

    def launch(self, asynch=False):
        """Launches the attack with the configured parameters.

        The function can be overidden in subclasses with only a call to super().run(async) to set the most appropriate default value

        :param asynch: Is the attack running in async mode (for long attacks, might be better not to block the cli ?), defaults to False
        :type asynch: bool, optional
        """
        if not self._is_setup:
            return False

        if asynch:
            self._event.set()
            thread = Thread(target=self._attack_runner)
            thread.start()
            return True
        else:
            self._attack_runner()
            return self._success

    def stop(self):
        """If the attack is in async mode and still running, stops the attack from running."""
        self._is_attack_running = False
        self.event.clear()
