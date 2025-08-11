from whad.cli.shell import category
from whad.btmesh.cli.base.shell import BTMeshBaseShell
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connector.provisioner import Provisioner
from whad.btmesh.stack.utils import (
    ProvisioningAuthenticationData,
)
from whad.btmesh.stack.constants import OUTPUT_OOB_AUTH
from prompt_toolkit import HTML, print_formatted_text


INTRO = """
wbtmesh-provisioner, the WHAD Bluetooth Mesh Provisioner utility
"""

SETUP_CAT = "Setup node"
ELEMENT_CAT = "Element edit"
ATTACK_CAT = "Attacks"
MISC = "Miscellaneous"


class BTMeshProvisionerShell(BTMeshBaseShell):
    MODE_NORMAL = 0
    MODE_STARTED = 1
    MODE_ELEMENT_EDIT = 2

    def __init__(self, interface=None, profile=BaseMeshProfile):
        super().__init__(interface, profile, HTML("<b>wbtmesh-provisioner></b> "))

        self.intro = INTRO

        # Instanciate our Peripheral
        self._connector = Provisioner(self.interface, profile=self.profile)

        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state"""
        # Are we in element edit mode ?
        if self._current_mode == self.MODE_ELEMENT_EDIT:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-provisioner | <ansicyan>element(%d)</ansicyan>></b> "
                    % (self._selected_element)
                ),
                force,
            )
        elif self._current_mode == self.MODE_NORMAL:
            self.set_prompt(HTML("<b>wbtmesh-provisioner></b> "), force)
        elif self._current_mode == self.MODE_STARTED:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-provisioner<ansimagenta> [running]</ansimagenta>></b> "
                )
            )

    def complete_listen_beacons(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["on"] = {}
        completions["off"] = {}
        return completions


    @category(MISC)
    def do_listen_beacons(self, args):
        """Starts/stops the listening for Unprovisioned Device Beacons for nodes that want to be provisioned and stores them.


        <ansicyan><b>listen_beacons</b> [<i>"on"/"off"</i>]</ansicyan>

        > listen_beacons on
        """

        if self._current_mode != self.MODE_STARTED:
            self.error("You need to auto provision the provisioner before anything.")
            return

        action = "on"
        if len(args) >= 1:
            action = args[0].lower()

        if action == "off":
            self._connector.stop_listening_beacons()
            self.success("Successfully stopped the beacons listening")

        else:
            self._connector.start_listening_beacons()
            self.success("Successfully started the beacons listening")

        return

    def do_list_unprov(self, args):
        """Lists the Unprovisioned devices that sent an Unprovisioned device beacon


        <ansicyan><b>list_unprov</b></ansicyan>
        """

        if self._current_mode != self.MODE_STARTED:
            self.error("You need to auto provision the provisioner before")
            return

        devices = self._connector.get_unprovisioned_devices()
        if len(devices) == 0:
            print_formatted_text(
                HTML("<ansimagenta>No Unprovisioned beacons received</ansimagenta>")
            )
            return

        print_formatted_text(HTML("<ansimagenta>Index | Device UUID</ansimagenta>"))
        for index in range(len(devices)):
            print_formatted_text(
                HTML(
                    "|─ <ansicyan>%d : %s</ansicyan>" % (index, str(devices[index])),
                )
            )

    def complete_prov(self):
        """autocomplete wireshark command"""
        completions = {}
        completions["start"] = {}
        completions["auth"] = {}
        return completions


    @category(MISC)
    def do_prov(self, args):
        """Provisions the device at index specified in the list (via command list_unprov)

        <ansicyan><b>prov <i>["start"|"auth"]</i> <i>index|value</i></b></ansicyan>

        To start provisioning :

        > prov start 1

        If auth value needs to be input (when prompted)
        > prov auth 1234
        """
        if self._current_mode != self.MODE_STARTED:
            self.error("You need to auto provision the provisioner before")
            return

        if len(args) < 1:
            self.error("You need to specify an action (start, auth)")
            return

        action = args[0].lower()

        if action == "start":
            if len(args) < 2:
                self.error(
                    "Specify the index of the node you want to specify (obtained via 'list_unprov' command)"
                )
                return

            try:
                index = int(args[1], 0)
            except ValueError:
                self.error("The index is an int")
                return

            devices = self._connector.get_unprovisioned_devices()
            if len(devices) <= index:
                self.error("Index too large, device does not exist")
                return

            res = self._connector.provision_distant_node(devices[index])
            if isinstance(res, ProvisioningAuthenticationData):
                if res.auth_method == OUTPUT_OOB_AUTH:
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
                self.success("Distant Node is provisioned")
                self._current_mode = self.MODE_STARTED
            else:
                self.error("Provisioning failed")

        else:
            self.error("This action does not exist")


        @category(MISC)
        def do_bind_app_key(self, args):
            """Binding of models to app keys of distant nodes.

            <ansicyan><b>bind_app_keys <i>["start"|"auth"]</i> <i>index|value</i></b></ansicyan>
            """
            pass
