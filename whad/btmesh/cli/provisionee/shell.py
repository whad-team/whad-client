from whad.cli.shell import category
from whad.btmesh.cli.base.shell import BTMeshBaseShell
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connector.provisionee import Provisionee
from whad.btmesh.stack.utils import ProvisioningAuthenticationData
from whad.btmesh.stack.constants import (
    INPUT_OOB_AUTH,
)

from prompt_toolkit import HTML


INTRO = """
wbtmesh-provisionee, the WHAD Bluetooth Mesh Provisionee utility
"""

PROV_CAT = "Provisioning utilities"
CONF_CAT = "Node configuration node"
MESSAGE_CAT = "Message sending utilities"
ELEMENT_CAT = "Element edit mode"
ATTACK_CAT = "Attacks"
MISC_CAT = "Misc"



class BTMeshProvisioneeShell(BTMeshBaseShell):
    MODE_NORMAL = 0
    MODE_STARTED = 1
    MODE_ELEMENT_EDIT = 2

    def __init__(self, interface=None, profile=BaseMeshProfile):
        super().__init__(interface, profile, HTML("<b>wbtmesh-provisionee></b> "))

        self.intro = INTRO

        # Instanciate our Peripheral
        self._connector = Provisionee(self.interface, profile=self.profile)

        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state"""
        # Are we in element edit mode ?
        if self._current_mode == self.MODE_ELEMENT_EDIT:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-provisionee | <ansicyan>element(%d)</ansicyan>></b> "
                    % (self._selected_element)
                ),
                force,
            )
        elif self._current_mode == self.MODE_NORMAL:
            self.set_prompt(HTML("<b>wbtmesh-provisionee></b> "), force)
        elif self._current_mode == self.MODE_STARTED:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-provisionee<ansimagenta> [running]</ansimagenta>></b> "
                )
            )

    def complete_prov(self):
        """autocomplete wireshark command"""
        completions = {}
        completions["start"] = {}
        completions["auth"] = {}
        completions["uuid"] = {}
        return completions

    @category(PROV_CAT)
    def do_prov(self, args):
        """Manages the provisioning process of the node (when not auto provisioned)

        <ansicyan><b>prov</b> <i>ACTION</i> <i>VALUE</i></ansicyan>

        The actions are :

        - <b>start</b> : Start the provisioning process by sending beacons first and proceding with the provisioning if invited
        - <b>uuid</b> : Changes the value of the node's UUID if given, or prints it if no value. If uuid shorter than 16 bytes, zero padding added.
        - <b>auth</b> : If input authentication needed, sends the value to the stack

        If no argument, "start" by default

        """
        if self._current_mode != self.MODE_NORMAL:
            self.error("Cannot reprovision a node, please reset")
            return

        action = args[0].lower() if len(args) >= 1 else "start"

        if action == "start":
            self.warning(
                "Starting sending Unprovisioned Device Beacons, please wait ..."
            )
            res = self._connector.start_provisioning()

            if isinstance(res, ProvisioningAuthenticationData):
                if res.auth_method == INPUT_OOB_AUTH:
                    self.warning(
                        "You need to type the authentication value provided by the Provisioner via OOB canal. Use command 'prov auth VALUE' to resume provisioning"
                    )
                return

            elif res:
                self.success("Node is provisioned")
                self._current_mode = self.MODE_STARTED
            else:
                self.error("Provisioning failed")

            return

        elif action == "uuid":
            if len(args) < 2:
                self.success("UUID of the node is : %s" % str(self._connector.uuid))
                return

            uuid = args[1]
            if len(uuid) < 32:
                uuid = uuid.ljust(32, "0")
            if len(uuid) > 32:
                self.error("UUID too long, 16 bytes hex string required")
                return

            res = self._connector.set_uuid(uuid)
            if res:
                self.success("Successfully set the UUID of the node")
            else:
                self.error("Failed to set the UUID of the node, check format")

            return

        elif action == "auth":
            if len(args) < 2:
                self.error("You need to specify the auth value")
                return

            try:
                value = int(args[1], 0)
            except ValueError:
                value = args[1]

            res = self._connector.resume_provisioning_with_auth(value)
            if res:
                self.success("Node is provisioned")
                self._current_mode = self.MODE_STARTED
            else:
                self.error("Provisioning failed")
        else:
            self.error("This action for this command does not exist")
