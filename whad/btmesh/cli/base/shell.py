from whad.cli.shell import InteractiveShell, category
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connector.node import BTMeshNode
from whad.btmesh.models import CompositeModelState
from whad.btmesh.stack.utils import MeshMessageContext, Node
from whad.btmesh.stack.constants import (
    MANAGED_FLOODING_CREDS,
    DIRECTED_FORWARDING_CREDS,
    FRIEND_CREDS,
)
from whad.scapy.layers.btmesh import (
    BTMesh_Model_Message,
)

from prompt_toolkit import HTML, print_formatted_text

from whad.exceptions import ExternalToolNotFound

from whad.common.monitors import WiresharkMonitor
from re import match, compile

INTRO = """
wbtmesh-base, the WHAD Bluetooth Mesh Base utility (not usable as is)
"""

SETUP_CAT = "Setup node"
ELEMENT_CAT = "Element edit"
ATTACK_CAT = "Attacks"
MISC = "Miscellaneous"


class BTMeshBaseShell(InteractiveShell):
    MODE_NORMAL = 0
    MODE_STARTED = 1
    MODE_ELEMENT_EDIT = 2

    def __init__(
        self,
        interface=None,
        profile=BaseMeshProfile,
        base_prompt=HTML("<b>wbtmesh-base></b>"),
    ):
        super().__init__(base_prompt)

        self._current_mode = self.MODE_NORMAL

        # Device parameters
        self._complete_name = "WhadDev"
        self._shortened_name = None

        #        self._main_stack = NetworkLayer(connector=self, options=self.options) If interface is None, pick the first matching our needs
        self.interface = interface

        # Profile
        self.profile = profile()

        # Index of element in MODE_ELEMENT_EDIT and MODE_MODEL_EDIT modes
        self._selected_element = None

        # Model id of the selected model in MODE_MODEL_EDIT
        self._selected_model = None

        self._connector = None
        self._wireshark = None
        self.intro = INTRO

        # Parameters/context to send access-send and control-send messages
        self._src_addr = 0x0000
        self._dst_addr = 0xFFFF
        self._net_key_index = 0
        self._app_key_index = 0
        self._dev_key_address = 0x0000
        self._seq_num = (
            None  # use intended one for this node (even if source address differs)
        )
        self._credentials = 0
        self._ttl = 127

        # Instanciate our Peripheral
        # PLACEHOLDER, OVERWRITE IN SUBCLASSES WITH OTHER CONNECTOR
        self._connector = BTMeshNode(self.interface, profile=self.profile)

    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        PLACEHOLDER FOR BASE SHELL, OVERWRITTEN IN SUBCLASSES
        """
        self.set_prompt(
            HTML(
                "<b>wbtmesh-base<ansimagenta> BTMeshBaseShell SHOULD NOT BE USED AS IS</ansimagenta>></b> "
            )
        )

    def create_msg_context(self, is_ctl):
        """
        Creates a MeshMessageContext object based on the context parameters (command msg_context) and returns it.
        None if error

        :param is_ctl: Is the message a control message ?
        :type is_ctl: boolean
        :returns: MeshMessageContext
        """
        if not self.profile.is_provisioned:
            return None

        ctx = MeshMessageContext()

        # if src_addr has the 0 value, the msg_context has not been init since provisioning
        if self._src_addr == 0x0000:
            self._src_addr = self.profile.get_primary_element_addr()
            subnets = self.profile.get_all_subnets()
            if subnets is None:
                self.error("No NetKey after provisioning, fatal error, need to reset")
                return
            self._net_key_index = subnets[0].net_key_index
            self._dev_key_address = self.profile.get_primary_element_addr()
            # Set to 0 for convenience for now, but we need to check !
            self._app_key_index = 0

        ctx.src_addr = self._src_addr
        ctx.dest_addr = self._dst_addr
        ctx.dev_key_address = self._dev_key_address
        ctx.net_key_id = self._net_key_index
        ctx.application_key_index = self._app_key_index
        ctx.seq_number = self._seq_num
        ctx.creds = self._credentials
        ctx.ttl = self._ttl
        ctx.is_ctl = is_ctl

        return ctx

    def complete_auto_prov(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["net_key"] = {}
        completions["dev_key"] = {}
        completions["app_key"] = {}
        completions["unicast_addr"] = {}
        completions["start"] = {}
        return completions

    @category(SETUP_CAT)
    def do_auto_prov(self, args):
        """Start the provisionee or provisioner with preset of provisioning data and manages this data.
        Recalling it will reset the node.

        <ansicyan><b>auto_prov</b> <i>["net_key"|"dev_key"|"app_key"|"unicast_addr"|"start"]</i> <i>VALUE</i></ansicyan>

        Sets the values for auto_provision and starts it when ready.

        Netkey and appkey are at key_index 0

        If no values for keys, default one used (in constructor of the BTmesh profile used)
        If no value for unicast_addr, address set to 0x0002.

        Actions are :

        - <b>net_key</b> : sets the primary net_key (index 0) for provisioning to the value (hexstring)
        - <b>dev_key</b> : sets the dev_key of the node for provisioning to the value (hexstring)
        - <b>app_key</b> : sets the app_key at index 0 for provisioning to the value (hexstring) and binded to all elements
        - <b>unicast_addr</b> : sets the unicast_addr of the node for provisioning to the value (int)
        - <b>start</b> : auto_provisions the node with what we have for the values


        > auto_prov net_key f7a2a44f8e8a8029064f173ddc1e2b00
        > auto_prov dev_key abcda44f8e8a8029064f173ddc1e2b00
        > auto_prov app_key faa2a44f8e8a8029064f173ddc178587
        > auto_prov unicast_addr 0x05
        > auto_prov start
        """

        if len(args) < 1:
            self.error("Please provide an action to perform")
            return

        action = args[0].lower()

        if action == "start":
            res = self.profile.auto_provision()

            if res:
                self.success("Node has been successfully auto provisioned")
            else:
                self.error("Node has not been auto provisioned, error.")
                return

            self._connector.start()

            self._src_addr = self.profile.get_primary_element_addr()
            subnets = self.profile.get_all_subnets()
            if subnets is None:
                self.error("No NetKey after provisioning, fatal error, need to reset")
                return

            self._net_key_index = subnets[0].net_key_index
            self._dev_key_address = self.profile.get_primary_element_addr()
            # Set to 0 for convenience for now, but we need to check !
            self._app_key_index = 0

            self._current_mode = self.MODE_STARTED
            self.update_prompt()
            return

        if len(args) < 2:
            self.error(
                "Wrong action or no value specified for auto_provision parameters"
            )
            return

        if action == "unicast_addr":
            try:
                unicast_addr = int(args[1], 0) & 0xFFFF
            except ValueError:
                self.error("Address is a 2 bytes int")
                return

            self.profile.set_auto_prov_unicast_addr(unicast_addr)
            self.success("Set the auto_provision unicast_addr to 0x%x" % unicast_addr)
            return

        # If action is app_key, net_key or dev_key
        try:
            key = bytes.fromhex(args[1])
        except ValueError:
            self.error("Keys are hex strings")
            return

        if action == "net_key":
            self.profile.set_auto_prov_net_key(key)
            self.success("Successfully set the primary net key for auto_provision.")
            return

        elif action == "app_key":
            self.profile.set_auto_prov_app_key(key)
            self.success("Successfully set the app_key for auto_provision.")
            return

        elif action == "dev_key":
            self.profile.set_auto_prov_dev_key(key)
            self.success("Successfully set the dev_key for auto_provision.")
            return

        else:
            self.error("Wrong action chosen")
            return

    def complete_prov_capabilities(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["algorithms"] = {}
        completions["public_key_type"] = {}
        completions["oob_type"] = {}
        completions["output_oob_size"] = {}
        completions["output_oob_action"] = {}
        completions["input_oob_size"] = {}
        completions["input_oob_action"] = {}
        return completions

    @category(SETUP_CAT)
    def do_prov_capabilities(self, args):
        """Manages the capabilities of the node when being provisioned/provisionnes a node

        <ansicyan><b>prov_capabilities</b> <i>["algorithms"|"public_key_type"|"oob_type"|"output_oob_size"|"output_oob_action"|"input_oob_size"|"input_oob_action"]</i> <i>VALUE</i></ansicyan>

        > prov_capabilities
        > prov_capabilities set algorithms 0b11

        With no argument, list the values

        """

        if len(args) < 1:
            capablities = self._connector.profile.capabilities
            print_formatted_text(
                HTML("<ansicyan><b>Provisioning Capabilities</b></ansicyan>")
            )
            for name, value in capablities.items():
                print_formatted_text(
                    HTML("|─ <ansimagenta>%s : %d</ansimagenta>" % (name, value))
                )

        elif len(args) >= 2:
            name = args[0].lower()
            try:
                value = int(args[1], 0)
            except ValueError:
                self.error("Value needs to be an int.")
                return

            self._connector.profile.capabilities[name] = value
            self.success("Successfully set %s to value %d" % (name, value))

    @category(SETUP_CAT)
    def do_address(self, arg):
        """Manages the device's primary unicast address and range

        <ansicyan><b>address</b> <i>value</i></ansicyan>

        This command will set the primary unicast address of the device to 0x05 :

        > address 0x0005

        By default, will print de device's address
        """

        if (
            self._current_mode != self.MODE_STARTED
            and self._current_mode != self.MODE_ELEMENT_EDIT
        ):
            self.error("Need to have the devices started and provisioned")
            return

        if len(args) >= 1:
            try:
                addr = int(args[0], 0) & 0xFFFF
            except ValueError:
                self.error("Address is an integer")
                return

            # If msg_context for src_addr or dst_addr, or dev_key_addr was the previous addr of the node, update
            if self._src_addr == self.profile.get_primary_element_addr():
                self._src_addr = addr
            if self._dst_addr == self.profile.get_primary_element_addr():
                self._dst_addr = addr
            if self._dev_key_address == self.profile.get_primary_element_addr():
                self._dev_key_address = addr

            self.profile.set_primary_element_addr(addr)

            self.success("Address of the device is now : 0x%x" % addr)
        else:
            self.success(
                "The primary unicast address of the node is 0x%x"
                % self.profile.get_primary_element_addr()
            )

    def complete_relay(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["on"] = {}
        completions["off"] = {}
        return completions

    @category(SETUP_CAT)
    def do_relay(self, arg):
        """Activate or deactivate the relaying of messages by the device (should be provisioned)

        <ansicyan><b>relay</b>  [<i>"on"|"off"</i>]</ansicyan>

        Activate : <b>relay</b> <i>on</i>

        By default, this command shows the relay status of the node
        """

        if (
            self._current_mode != self.MODE_STARTED
            and self._current_mode != self.MODE_ELEMENT_EDIT
        ):
            self.error("Can only managed relaying on a provisioned node.")
            return

        if len(arg) < 1:
            relay = self._connector.get_relaying_status()
            if relay:
                self.success("Relay is activated on the node.")
            else:
                self.success("Relay is deactivated on the node")

        else:
            relay = arg[0].lower()
            if relay == "on":
                self._connector.set_relay(True)
                self.success("Relay is now activated on the node.")
            elif relay == "off":
                self._connector.set_relay(False)
                self.success("Relays is now deactivated on the node")
            else:
                self.error("Wrong argument, should be on/off")

    @category(SETUP_CAT)
    def do_resume(self, arg):
        """Resumes the normal behaviour of a provisioned node (after editing an element)

        <ansicyan><b>resume</b></ansicyan>
        """

        self._connector.start()
        self._current_mode = self.MODE_STARTED
        self.update_prompt()

    def complete_element(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["remove"] = {}
        completions["add"] = {}
        completions["edit"] = {}
        return completions

    @category(SETUP_CAT)
    def do_element(self, args):
        """Manage device's elements

        <ansicyan><b>element</b> [<i>ACTION</i> <i>[PARAMS]</i>]</ansicyan>

        - <b>remove</b>: remove an element (cannot remove the primary element ...)
        - <b>add</b>: adds an element
        - <b>edit</b>: choose an element to edit (and stops the node while editing)

        To remove an element : <b>element</b> <i>remove</i> <i>index</i>
        It will reoganize the indexes of the elements to be contiguous.

        To add an element : <b>element</b> <i>add</i>

        To edit an element : <b>element</b> <i>edit</i> <i>index</i>

        By default, this command lists the elements with its models.

        After provisioning, only editing states will function (cannot add or remove).
        """

        if len(args) > 0:
            action = args[0].lower()
            if action == "add":
                if self._current_mode != self.MODE_NORMAL:
                    self.error("Cannot add elements after provisioning")
                    return

                index = self.profile.register_element(is_primary=False)

                self.success("Element %d successfully added." % index)

            elif action == "remove":
                if self._current_mode != self.MODE_NORMAL:
                    self.error("Cannot remove elements after provisioning")
                    return

                if len(args) >= 2:
                    try:
                        index = int(args[1], 0) & 0xFF
                    except ValueError:
                        self.error("Index needs to be an int")
                        return

                    if index == 0:
                        self.error("Cannot delete primary element")

                    elif self.profile.remove_elements(index):
                        self.success(
                            "Successfully removed element at index %d." % index
                        )
                    else:
                        self.error("Cannot remove element at index %d." % index)

                else:
                    self.error("You need to provide a valide element index.")

            elif action == "edit":
                if len(args) >= 2:
                    try:
                        index = int(args[1], 0)
                    except ValueError:
                        self.error("Index needs to be an int")
                        return

                    element = self.profile.get_element(index)
                    if element is None:
                        self.error(
                            "Invalid element index, element %d does not exist." % index
                        )
                        return

                    if self._connector is not None:
                        self._connector.stop()

                    self._selected_element = index
                    self._current_mode = self.MODE_ELEMENT_EDIT

                else:
                    self.error("Need to specify an element index to edit")

        else:
            elements = self.profile.get_all_elements()

            for element in elements:
                print_formatted_text(
                    HTML("<ansicyan><b>Element %d</b></ansicyan>:" % element.index)
                )
                if len(element.models) > 0:
                    for model in element.models:
                        print_formatted_text(
                            HTML(
                                "|─ <ansimagenta><b>Model %s</b> (0x%x)</ansimagenta>"
                                % (model.name, model.model_id)
                            )
                        )
                else:
                    print_formatted_text(HTML(" <i>No models defined</i>"))

        self.update_prompt()

    def complete_model(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["read"] = {}
        completions["write"] = {}
        return completions

    @category(SETUP_CAT)
    def do_model(self, args):
        """Manage device's models (in an element), specifically its bounded states (and those of its base models). Only functions on Server models !

        <ansicyan><b>model</b> [<i>ACTION</i>] [<i>MODEL_ID</i>] <i>[PARAMS]</i>]</ansicyan>

        <ansimagenta>Need To Be In ELEMENT EDIT Mode.</ansimagenta>

        - <b>read</b>: reads the value of the state of an element. if no state specified lists all states of the model.
        - <b>write</b>: write in the state's value

        To read a state of the model : <b>model</b> <i>read</i> <i>MODEL_ID</i> <i>STATE_NAME</i>

        To read all states of the model : <b>model</b> <i>read</i> <i>MODEL_ID</i>

        To write to the state of the model : <b>model</b> <i>write</i> <i>MODEL_ID</i> <i>STATE_NAME</i> <i>FIELD_NAME</i> <i>VALUES</i>

        Writing/reading of NetKeyList, AppKeyList, ModelToAppKeyList uses other commands.


        Names of composite states are <i>BASE_STATE.SUB_STATE</i>
        Ex : <i>health_fault.current_fault</i>

        If no <i>FIELD_NAME</i>, "default" field is used.

        To write different types of values (<i>VALUES</i>):

        int : 7 -> value is int 7
        int : 0xA -> value is 0xA (hex) (10)
        int : 0b11 -> value is 3 (binary)
        float : 14.5 -> value is 14.5
        bytes : 0574 -> value is b'\\x05\\x74' (always give raw bytes)
        List of the above  : 7 4 8 5 -> [7,4,8,5]

        Logic is not checked, state values should follow specification format.

        Examples :

        > model read 0x02 current_health.health_fault
        > model write 0x02 current_health.health_fault test_id 1
        > model write 0x02 current_health.health_fast_period_division default 2
        > model write 0x02 current_health.health_fault fault_array 0x02 0x03 0xC

        By default lists the models of the current element
        """

        if self._current_mode != self.MODE_ELEMENT_EDIT:
            self.error("Can only edit models whilst in Element edit mode.")
            return

        element = self.profile.get_element(self._selected_element)

        if len(args) >= 2:
            try:
                model_id = int(args[1], 0) & 0xFFFF
            except ValueError:
                self.error("Model id is an int.")
                return
            model = element.get_model_by_id(model_id)

            if model is None:
                self.error(
                    "Model with id %d does not exist in this element." % model_id
                )
                return

            action = args[0].lower()

            if action == "read":
                # Read all states
                if len(args) < 3:
                    print_formatted_text(
                        HTML(
                            "<ansimagenta><b>States of the Model 0x%x</b></ansimagenta> :"
                            % (model.model_id)
                        )
                    )
                    for state in model.get_all_states():
                        self._show_state(state)
                    return

                # Show a particular state, specified
                else:
                    print_formatted_text(
                        HTML(
                            "<ansimagenta><b>In Model 0x%x</b></ansimagenta> :"
                            % (model.model_id)
                        )
                    )
                    state_arg = args[2].lower().split(".")
                    state_name = state_arg[0]
                    sub_state_name = None
                    if len(state_arg) > 1:
                        sub_state_name = state_arg[1]

                    state = model.get_state(state_name)

                    if state is None:
                        self.error(
                            "State %s does not exists in model %d."
                            % (state_name, model_id)
                        )
                        return

                    self._show_state(state, sub_state_name)
                    return

            elif action == "write":
                if len(args) < 4:
                    self.error("Need to specify the state name and value")
                    return

                state_arg = args[2].lower().split(".")
                state_name = state_arg[0]
                sub_state_name = None
                if len(state_arg) > 1:
                    sub_state_name = state_arg[1]

                state = model.get_state(state_name)

                if state is None:
                    self.error(
                        "State %s does not exists in model %d." % (state_name, model_id)
                    )
                    return

                if model.model_id == 0 and (
                    state_name == "net_key_list" or state_name == "app_key_list"
                ):
                    self.error(
                        "Cannot write to net_key_list and app_key_list states, use net_keys or app_keys commands"
                    )
                    return

                try:
                    if len(args) >= 5:
                        values = self._parse_args(args[4:])
                        field_name = args[3].lower()
                    else:
                        values = self._parse_args(args[3:])
                        field_name = "default"
                except ValueError:
                    return

                if isinstance(state, CompositeModelState):
                    if sub_state_name is None:
                        self.error(
                            "State %s is a composite state, specify sub state."
                            % state.name
                        )
                        return

                    state = state.get_sub_state(sub_state_name)
                    if state is None:
                        self.error(
                            "Substate %s does not exist in state %s"
                            % (sub_state_name, state_name)
                        )
                        return

                # If the values have only a single element, no list
                if len(values) == 1:
                    values = values[0]

                state.set_value(field_name=field_name, value=values)
                self.success("Successfully set the value for the state.")

        else:
            if len(element.models) > 0:
                for model in element.models:
                    print_formatted_text(
                        HTML(
                            "|─ <ansimagenta><b>Model %s</b> (0x%x)</ansimagenta>"
                            % (model.name, model.model_id)
                        )
                    )
            else:
                print_formatted_text(HTML(" <i>No models defined</i>"))

    def complete_whitelist(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["add"] = {}
        completions["remove"] = {}
        completions["reset"] = {}
        return completions

    @category(SETUP_CAT)
    def do_whitelist(self, args):
        """Manages the whitelist of the node.

        <ansicyan><b>whitelist</b> [<i>ACTION</i>] [<i>BD_ADDR</i>]</ansicyan>


        - <b>add</b> : Adds an address to the whitelist and activates it
        - <b>remove</b> : Removes an address from the whitelist. If empty, deactivates it.
        - <b>reset</b> : Resets the whitelist and deactivates it.

        By default, shows the whitelist

        - To add an address to the whitelist : whitelist add 66:55:44:33:22:AA

        - To remove an address from the whitelist : whitelist remove 66:55:44:33:22:AA

        - To reset the whitelist : whitelist reset
        """

        if (
            self._current_mode != self.MODE_STARTED
            and self._current_mode != self.MODE_ELEMENT_EDIT
        ):
            self.error(
                "Need to have a provisioned node/not in element edit to manage whitelist"
            )
            return

        if len(args) < 1:
            whitelist = self._connector.whitelist
            if len(whitelist) == 0:
                print_formatted_text(
                    HTML("|─ <ansimagenta><b>Empty Whitelist</b></ansimagenta>")
                )
            else:
                for addr in self._connector.whitelist:
                    print_formatted_text(
                        HTML("|─ <ansimagenta><b>%s</b></ansimagenta>" % addr)
                    )

        else:
            action = args[0].lower()
            if action == "reset":
                self._connector.reset_whitelist()
                self.success("Successfully reset the whitelist")

            elif action == "add" or action == "remove":
                if len(args) < 2:
                    self.error("You need to specifiy an address to add/remove")
                    return

                addr = args[1].lower()
                if not bool(match(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$", addr)):
                    self.error("BD addr needs to be in MAC addr format.")
                    return

                if action == "add":
                    self._connector.add_whitelist(addr)
                    self.success("Successfully added addr %s to the whitelist." % addr)

                elif action == "remove":
                    self._connector.remove_whitelist(addr)
                    self.success(
                        "Successfully removed addr %s from the whitelist." % addr
                    )

    @category(SETUP_CAT)
    def do_seqnum(self, arg):
        """Manages the sequence number of the node (proper sequence number of the node)

        <ansicyan><b>seqnum</b> [<i>seqnum</i>]</ansicyan>

        By default, prints the current sequence number.

        To set the sequence number :

        > seqnum 0xA10010
        """

        if (
            self._current_mode != self.MODE_STARTED
            and self._current_mode != self.MODE_ELEMENT_EDIT
        ):
            self.error("Can only set the sequence number of a provisioned node.")
            return

        if len(arg) == 0:
            print_formatted_text(
                HTML(
                    "<ansigreen><b>Sequence number : 0x%x</b></ansigreen>"
                    % (self._connector.profile.seqnum)
                )
            )
        else:
            try:
                seqnum = int(arg[0], 0) & 0xFFFFFF
            except ValueError:
                self.error("Sequence number should be an int.")
                return

            self._connector.profile.set_seq_number(seqnum)
            self.success("Successfully set the sequence number to 0x%x." % seqnum)

    @category(MISC)
    def do_onoff(self, args):
        """Sends an onoff (acked) message
        <ansicyan><b>onoff</b> [<i>"1"|"0"</i>] [<i>TID</i>]</ansicyan>

        > onoff 1 82

        Uses the parameters from the message context (msg_context command).
        By default uses TID (transaction ID) incremented of this node if not specified.
        """
        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Can only send a message from a provisioned node and not in element edit mode."
            )
            return

        tid = None

        if len(args) < 1:
            self.error("Need to specify value to send (0 or 1)")
            return

        try:
            value = abs(int(args[0], 0))
        except ValueError:
            self.error("Value is either '0' or '1'")
            return

        if len(args) >= 2:
            try:
                tid = int(args[1], 0) & 0xFF
            except ValueError:
                self.error("TID is an integer bewteen 0 and 255.")
                return

        ctx = self.create_msg_context(False)
        self._connector.do_onoff(value, ctx, tid)
        self.success("Successfully sent onoff message.")

    # TODO : send control message (need to have an opcode argument ?)
    @category(MISC)
    def do_send_raw_access(self, args):
        """Sends an Access message based on message context (msg_context command) and a hex string of the raw Packet

        <ansicyan><b>send_raw_access</b> <i>RAW_MESSAGE</i></ansicyan>

        The raw_message is a hex string of the Model message.

        > send_raw_access 04000000010703
        """
        if self._current_mode != self.MODE_STARTED:
            self.error("Cannot send message if node in edit mode or not provisioned")
            return

        if len(args) < 1:
            self.error("You need to specify the message to send (hex string)")
            return

        raw = args[0]

        message = BTMesh_Model_Message(bytes.fromhex(raw))
        ctx = self.create_msg_context(False)
        self._connector.send_raw_access((message, ctx))
        self.success("Successfully sent the message below.")
        message.show()

    def complete_nodes(self):
        """Autocomplete nodes command"""
        completions = {}
        completions["list"] = {}
        completions["add"] = {}
        completions["remove"] = {}
        completions["dev_key"] = {}
        return completions

    @category(SETUP_CAT)
    def do_nodes(self, args):
        """Manages the information specific to each distant/local Node that we possess (namely their dev_key,elements and addresses)

        <ansicyan><b>nodes</b> [<i>ACTION</i>] [<i>PRIMARY_NODE_ADDR</i>] [<i>VALUES</i>]</ansicyan>

        All actions are performed to update information stored on the local node, no messages are sent on the network
        If no PRIMARY_NODE_ADDR specified, affects the local node !
        If PRIMARY_NODE_ADDR specified, affects a distant node (in the case of spoofing, local and a distant node can share an address)

        For the <i>ACTION</i> field :

        - <b>list</b> : Lists the distant nodes (and our own) we are aware of, and the information we have
        - <b>add</b> : Adds a distant node (need address, optional address range). If already present, does nothing. Adds a default value for dev_key as placeholder (invalid for real use)
        - <b>remove</b> : Remove a distant node from the list
        - <b>dev_key</b> : Update the dev_key of the given node (only in local database !). If no address given, changes the dev_key of the local node.

        > To list : nodes list

        > To add (node address 0x0005, address range 3) : nodes add 0x0005

        > To remove a node : nodes remove 0x0005

        > To change/add dev_key of a node: nodes dev_key 0x0005 63964771734fbd76e3b40519d1d94a48
        Change dev_key of local node : nodes dev_key 77964771734fbd76e3b40519d1d94a89

        By default, lists information.
        """
        if self._current_mode != self.MODE_STARTED:
            self.error("Cannot manage nodes on an unprovisionned device or in element edit mode")
            return

        action = args[0].lower() if len(args) >= 1 else "list"
        if action == "list":
            nodes = self.profile.get_all_nodes()
            for node in nodes.values():
                print_formatted_text(
                    HTML(
                        "|─ <ansimagenta><b>Address: 0x%x DevKey : %s</b></ansimagenta>"
                        % (node.address, node.dev_key.device_key.hex())
                    )
                )
            return
        elif action == "dev_key":
            if len(args) < 2:
                self.error("Specify value of the key")
                return

            try:
                if len(args) >= 3:
                    address = int(args[1], 0) & 0xFFFF
                    key = bytes.fromhex(args[2])
                else:
                    address = None
                    key = bytes.fromhex(args[2])
            except ValueError:
                self.error("The address is 2 bytes int and the key is a hex string.")
                return

            success = self.profile.update_dev_key(address=address, dev_key=key)

            if not success:
                self.error(
                    "Update of dev_key failed. If you want to change the local node device_key, do not specify its address."
                )
                return
            else:
                self.success("Update of dev_key successfull")

        elif action == "add":
            if len(args) < 2:
                self.error("Specify primary unicast address of the node to add")
                return

            addr_range = 0
            try:
                address = int(args[1], 0) & 0xFFFF
                if len(args) >= 3:
                    addr_range = int(args[2], 0) & 0xFFFF
            except ValueError:
                self.error("The address and range are 2 bytes int.")
                return

            added_node = Node(address=address, addr_range=addr_range)
            success = self.profile.add_distant_node(added_node)

            if not success:
                self.error("Addition of new distant node failed")
                return
            else:
                self.success("Addition of new distant node successfull")

        elif action == "remove":
            if len(args) < 2:
                self.error(
                    "Need to specify address of distant node to remove from local database"
                )
                return

            try:
                address = int(args[1], 0) & 0xFFFF
            except ValueError:
                self.error("The address is a 2 bytes int")
                return

            if self._dev_key_address == address:
                self.error(
                    "Cannot delete this node for now, address used in message context as dev_key address ! "
                )
                return

            removed_node = self.profile.remove_distant_node(address)

            if removed_node is None:
                self.error(
                    "Removal of node %x failed, does it exist ? Or maybe trying to delete our node"
                    % address
                )
                return
            self.success(
                "Successfully removed Node %x from list" % removed_node.address
            )
            return

    def complete_net_keys(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["list"] = {}
        completions["update"] = {}
        completions["remove"] = {}
        return completions

    @category(SETUP_CAT)
    def do_net_keys(self, args):
        """Manages the net keys of the node (update, add, remove)

        <ansicyan><b>net_keys</b> [<i>ACTION</i>] [<i>NET_KEY_IDX</i>] [<i>NET_KEY_VALUE</i>]</ansicyan>

        For the <i>ACTION</i> field :

        - <b>list</b> : Lists the netkeys and theis values
        - <b>update</b> : If net_key_idx not already there, add the net_key with net_key_value. If already present, update the value of the key
        - <b>remove</b> : If net_key_idx present, removes the key (cannot have less than 1 net_key though)

        > To list  :  net_keys list


        > To update/add key :  net_keys update 0 efb2255e6422d330088e09bb015ed707

        > To remove : net_keys remove 1

        By default, list
        """

        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Cannot manage keys on an unprovisionned device or in element edit mode"
            )

        action = args[0].lower() if len(args) >= 1 else "list"
        if action == "list":
            subnets = self.profile.get_all_subnets()
            for subnet in subnets:
                net_key = self.profile.get_net_key(subnet.net_key_index)
                if net_key is None:
                    continue
                print_formatted_text(
                    HTML(
                        "|─ <ansimagenta><b>Index : %d Key : %s</b></ansimagenta>"
                        % (subnet.net_key_index, net_key.net_key.hex())
                    )
                )
            return
        elif action == "update":
            if len(args) < 3:
                self.error("Specify net_key_index and value of the key")
                return

            try:
                net_key_index = int(args[1], 0) & 0xFFFF
                key = bytes.fromhex(args[2])
            except ValueError:
                self.error(
                    "The net_key_index is an integer and the key is a hex string."
                )
                return

            success = self.profile.update_net_key(net_key_index, key)
            if not success:
                self.error("Update of net_key failed")
                return
            else:
                self.success("Update of net_key successfull")

        elif action == "remove":
            if len(args) < 2:
                self.error("Need to specify net_key_index to remove")
                return
            try:
                net_key_index = int(args[1], 0) & 0xFFFF
            except ValueError:
                self.error("The net_key_index is an integer")
                return

            if self._net_key_index == net_key_index:
                self.error("Cannot delete this key for now, used in message context ! ")
                return

            success = self.profile.remove_net_key(net_key_index)

            if not success:
                self.error(
                    "Removal of NetKey failed, does it exist ? Or maybe only a single net_key is present."
                )
                return
            self.success("Successfully removed NetKey with index %d" % net_key_index)
            return

    def complete_app_keys(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["list"] = {}
        completions["update"] = {}
        completions["remove"] = {}
        return completions

    @category(SETUP_CAT)
    def do_app_keys(self, args):
        """Manages the app keys of the node (update, add, remove)

        <ansicyan><b>app_keys</b> [<i>ACTION</i>] [<i>APP_KEY_IDX</i>] [<i>NET_KEY_IDX</i>] [<i>APP_KEY_VALUE</i>]</ansicyan>

        For the <i>ACTION</i> field :

        - <b>list</b> : Lists the appkeys and theis values, and the netkey they are bound to
        - <b>update</b> : If app_key_idx not already there, add the app_key with app_key_value, bound to the net_key specified. If already present, update the value of the key
        - <b>remove</b> : If app_key_idx present, removes the key (cannot have less than 1 app_key though, specification)

        > To list  :  app_keys list


        > To update/add key (index 1, bound to net_key_idx 0) :  app_keys update 1 0 aab2255e6422d330088e09bb015ed707

        > To remove : app_keys remove 1

        By default, list
        """

        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Cannot manage keys on an unprovisionned device or in element edit mode"
            )

        action = args[0].lower() if len(args) >= 1 else "list"
        if action == "list":
            app_keys = self.profile.get_all_app_keys()
            for app_key in app_keys:
                print_formatted_text(
                    HTML(
                        "|─ <ansimagenta><b>Index : %d Bounded to NetKey : %d Key : %s</b></ansimagenta>"
                        % (
                            app_key.key_index,
                            app_key.net_key_index,
                            app_key.app_key.hex(),
                        )
                    )
                )
            return
        elif action == "update":
            if len(args) < 4:
                self.error("Specify app_key_index, net_key_index and value of the key")
                return

            try:
                app_key_index = int(args[1], 0) & 0xFFFF
                net_key_index = int(args[2], 0) & 0xFFFF
                key = bytes.fromhex(args[3])
            except ValueError:
                self.error(
                    "The net_key_index/app_key_index is an integer and the key is a hex string."
                )
                return

            success = self.profile.update_app_key(app_key_index, net_key_index, key)
            if not success:
                self.error("Update of app_key failed")
                return
            else:
                self.success("Update of app_key successfull")

        elif action == "remove":
            if len(args) < 3:
                self.error("Need to specify app_key_index to remove")
                return
            try:
                app_key_index = int(args[1], 0) & 0xFFFF
                net_key_index = int(args[2], 0) & 0xFFFF
            except ValueError:
                self.error("The app_key_index is an integer")
                return

            if self._app_key_index == app_key_index:
                self.error("Cannot delete this key for now, used in message context ! ")
                return

            success = self.profile.remove_app_key(app_key_index, net_key_index)

            if not success:
                self.error(
                    "Removal of NetKey failed, does it exist ? Or maybe only a single net_key is present."
                )
                return
            self.success("Successfully removed NetKey with index %d" % net_key_index)
            return

    @category(MISC)
    def do_secure_network_beacon(self, args):
        """Sends a secure network beacon with the given parameters.

        <ansicyan><b>secure_network_beacon</b> <i>0|1</i> <i>0|1</i></ansicyan>

        First arugment is key refresh flag, second is IV update flag
        """
        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Can only send a message from a provisioned node and not in element edit mode."
            )
            return

        if len(args) < 2:
            self.error("Specify key refresh and IV update flags")
            return

        try:
            key_refresh = int(args[0], 0)
            iv_update = int(args[0], 0)
        except ValueError:
            self.error("Values for the arguments is 0 or 1")
            return

        if key_refresh not in [0, 1] or iv_update not in [0, 1]:
            self.error("Values for the arguments is 0 or 1")
            return

        self._connector.do_secure_network_beacon(key_refresh, iv_update)
        self.success("Successfully sent the Secure network beacon.")

    def complete_wireshark(self):
        """Autocomplete wireshark command"""
        completions = {}
        if self._wireshark is not None:
            completions["off"] = {}
        else:
            completions["on"] = {}
        return completions

    @category("Monitoring")
    def do_wireshark(self, arg):
        """launch wireshark to monitor packets

        <ansicyan><b>wireshark</b> <i>["on" | "off"]</i></ansicyan>

        This command launches a wireshark that will display all the packets sent
        and received in the active connection.
        """
        if len(arg) >= 1:
            enabled = arg[0].lower() == "on"
            if enabled:
                if self._wireshark is None:
                    try:
                        self._wireshark = WiresharkMonitor()
                        if self._connector is not None:
                            self._wireshark.attach(self._connector)
                            self._wireshark.start()
                    except ExternalToolNotFound as notfound:
                        self.error(
                            "Cannot launch Wireshark, please make sure it is installed."
                        )
                else:
                    self.error(
                        "Wireshark is already launched, see <ansicyan>wireshark off</ansicyan>"
                    )
            else:
                # Detach monitor if any
                if self._wireshark is not None:
                    self._wireshark.detach()
                    self._wireshark.close()
                    self._wireshark = None
        else:
            self.error("Missing arguments, see <ansicyan>help wireshark</ansicyan>.")

    def complete_msg_context(self):
        """Autocomplete wireshark command"""
        completions = {}
        completions["dst"] = {}
        completions["src"] = {}
        completions["net_key_idx"] = {}
        completions["app_key_idx"] = {}
        completions["dev_key_addr"] = {}
        completions["seq_num"] = {}
        completions["credentials"] = {}
        completions["ttl"] = {}
        return completions

    @category(SETUP_CAT)
    def do_msg_context(self, args):
        """Set the parameters/context to send messages via the access-send or control-send commands.

        <ansicyan><b>msg_context</b> [<i>PARAM_TYPE</i>] [<i>VALUE</i>]</ansicyan>

        The parameters types/context for a message sent are :

        - <b>dst</b> : The destination address (default 0xffff)
        - <b>src</b> : The source address (default the primary unicast address of the node)
        - <b>net_key_idx</b> : The net_key_index used (default 0)
        - <b>app_key_idx</b> : The app_key_index used (default 0). Value is -1 if devkey used.
        - <b>dev_key_addr</b> : The address of the node we used the devkey of for the message. (default the primary unicast address of the node)
        - <b>seq_num</b> : The sequence number to use (default is intended sequence number for the node)
        - <b>credentials</b> : The credentials for the message(default 0, Managed Flooding). 0 for MF, 1 for Friend (not supported yet), 2 for Directed Forwarding (doesnt check/init paths)
        - <b>ttl</b> : The TTL to use (default : 0x7f)

        By default, prints the parameters.

        Examples :

        > msg_context dst 0x0002
        > msg_context src 0x0008
        > msg_context net_key_idx a
        > msg_context app_key_index 8
        > msg_context dev_key_addr 0x0006
        > msg_context seq_num 0x50
        > msg_context credentials 1
        > msg_context ttl 0x45
        """

        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Need a provisioned node to access message context and not in element edit mode"
            )
            return

        if len(args) >= 2:
            action = args[0].lower()

            if action == "dst":
                try:
                    self._dst_addr = int(args[1], 0) & 0xFFFF
                except ValueError:
                    self.error("Destination address must be an int")
                    return
                self.success(
                    "Set message context 'Destination' to value 0x%x" % self._dst_addr
                )
                return

            if action == "src":
                try:
                    self._src_addr = int(args[1], 0) & 0xFFFF
                except ValueError:
                    self.error("Source address must be an int.")
                    return
                self.success(
                    "Set message context 'Source' to value 0x%x" % self._src_addr
                )
                return

            if action == "net_key_idx":
                try:
                    net_key_index = int(args[1], 0) & 0xFFFF
                except ValueError:
                    self.error("Net Key Index must be an int")
                    return

                if self.profile.get_subnet(net_key_index) is None:
                    self.error("Net Key Index %d does not exist, fail." % net_key_index)
                    return

                self._net_key_index = net_key_index
                self.success(
                    "Set message context 'Net Key Index' to value %d"
                    % self._net_key_index
                )
                return

            if action == "app_key_idx":
                try:
                    app_key_index = int(args[1], 0)
                except ValueError:
                    self.error("App Key Index must be an int (-1 if devkey used)")
                    return

                if (
                    app_key_index != -1
                    and self.profile.get_app_key(app_key_index) is None
                ):
                    self.error("App Key Index %d does not exist, fail." % app_key_index)
                    return

                self._app_key_index = app_key_index
                self.success(
                    "Set message context 'App Key Index' to value %d"
                    % self._app_key_index
                )
                return

            if action == "seq_num":
                try:
                    self._seq_num = int(args[1], 0) & 0xFFFFFF
                except ValueError:
                    self.error("Sequence Number must be an int")
                    return

                self.success(
                    "Set message context 'Sequence Number' to value 0x%x"
                    % self._seq_num
                )
                return

            if action == "dev_key_addr":
                try:
                    dev_key_addr = int(args[1], 0) & 0xFFFF
                except ValueError:
                    self.error("dev_key_addr is a 2 bytes int")
                    return

                if self.profile.get_dev_key(dev_key_addr) is None:
                    self.error(
                        "Dev Key for address 0x%x does not exist in this node"
                        % dev_key_addr
                    )
                    return

                self._dev_key_address = dev_key_addr
                self.success(
                    "Set message context 'Dev Key Address' to value 0x%x (do not forget to set App Key Idx to -1 to use it)"
                    % self._dev_key_address
                )
                return

            if action == "seq_num":
                try:
                    self._seq_num = int(args[1], 0) & 0xFFFFFF
                except ValueError:
                    self.error("Sequence Number must be an int")
                    return

                self.success(
                    "Set message context 'Sequence Number' to value 0x%x"
                    % self._seq_num
                )
                return

            if action == "credentials":
                try:
                    credentials = int(args[1], 0)
                except ValueError:
                    self.error("Credentials must be 0 (MF) or 1 (Friend) or 2 (DF).")
                    return

                if credentials == 0:
                    self._credentials = MANAGED_FLOODING_CREDS
                    self.success(
                        "Set message context 'Credentials' to Managed Flooding"
                    )
                elif credentials == 1:
                    self._credentials = FRIEND_CREDS
                    self.success("Set message context 'Credentials' to Friend")

                elif credentials == 2:
                    self._credentials = DIRECTED_FORWARDING_CREDS
                    self.success(
                        "Set message context 'Credentials' to Directed Forwarding"
                    )
                else:
                    self.error("Relay method must be 0,1 or 2.")

                return

            if action == "ttl":
                try:
                    self._ttl = int(args[1], 0) & 0x7F
                except ValueError:
                    self.error("TTL must be an int number.")
                    return

                self.success("Set message context 'TTL' to 0x%x" % self._ttl)
                return

            else:
                self.error("No action for %s" % action)
                return

        else:
            print_formatted_text(HTML("<ansicyan><b>Message context :</b></ansicyan>"))
            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>src</ansiyellow>) <ansimagenta><b>Source : 0x%x</b></ansimagenta>"
                    % self._src_addr
                )
            )

            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>dst</ansiyellow>) <ansimagenta><b>Destination : 0x%x</b></ansimagenta>"
                    % self._dst_addr
                )
            )
            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>net_key_idx</ansiyellow>) <ansimagenta><b>Net Key Index : %d</b></ansimagenta>"
                    % self._net_key_index
                )
            )
            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>app_key_idx</ansiyellow>) <ansimagenta><b>App Key Index : %d</b></ansimagenta>"
                    % self._app_key_index
                )
            )
            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>dev_key_addr</ansiyellow>) <ansimagenta><b>Dev Key Address : 0x%x</b></ansimagenta>"
                    % self._dev_key_address
                )
            )
            if self._seq_num is None:
                print_formatted_text(
                    HTML(
                        "|─ (<ansiyellow>seq_num</ansiyellow>) <ansimagenta><b>Sequence Number is intended one for node</b></ansimagenta>"
                    )
                )
            else:
                print_formatted_text(
                    HTML(
                        "|─ (<ansiyellow>seq_num</ansiyellow>) <ansimagenta><b>Sequence Number : 0x%x</b></ansimagenta>"
                        % self._seq_num
                    )
                )

            if self._credentials == MANAGED_FLOODING_CREDS:
                print_formatted_text(
                    HTML(
                        "|─ (<ansiyellow>credentials</ansiyellow>) <ansimagenta><b>Credentials : Managed Flooding (0)</b></ansimagenta>"
                    )
                )
            elif self._credentials == FRIEND_CREDS:
                print_formatted_text(
                    HTML(
                        "|─ (<ansiyellow>credentials</ansiyellow>) <ansimagenta><b>Credentials : Friend (1)</b></ansimagenta>"
                    )
                )
            elif self._credentials == FRIEND_CREDS:
                print_formatted_text(
                    HTML(
                        "|─ (<ansiyellow>credentials</ansiyellow>) <ansimagenta><b>Credentials : Directed Forwarding (2)</b></ansimagenta>"
                    )
                )

            print_formatted_text(
                HTML(
                    "|─ (<ansiyellow>ttl</ansiyellow>) <ansimagenta><b>TTL : 0x%x</b></ansimagenta>"
                    % self._ttl
                )
            )

    def _show_state(self, state, sub_state_name=None):
        """
        Nice display of a state with its value(s). For composite state, can specify a sub_state or None if show all sub_states

        :param state: State to display
        :type state: ModelState | CompositeModelState
        :param: sub_state_name: Name of the substate to show if composite state, defaults to None
        :type sub_state_name: str
        :returns: True if all good, False if a sub_state_name does not exist
        :rtype: bool
        """
        if isinstance(state, CompositeModelState):
            print_formatted_text(
                HTML("   |─ <ansimagenta><b>%s</b></ansimagenta>: " % (state.name))
            )
            if sub_state_name is None:
                for sub_state in state.get_all_sub_states():
                    print_formatted_text(
                        HTML(
                            "      |─ <ansiyellow><b>%s</b></ansiyellow>:"
                            % (sub_state.name)
                        )
                    )
                    for field_name, value in sub_state.values.items():
                        if value is not None:
                            print_formatted_text(
                                HTML(
                                    "          |─ <ansigreen><b>%s</b></ansigreen>:"
                                    % (field_name)
                                ),
                                value,
                            )

                return True

            else:
                sub_state = state.get_sub_state(sub_state_name)
                if sub_state is None:
                    return False
                print_formatted_text(
                    HTML(
                        "   |─ <ansiyellow><b>%s</b></ansiyellow>:"
                        % (state.name + "." + sub_state.name),
                    ),
                    sub_state.value,
                )
                for field_name, value in sub_state.values.items():
                    if value is not None:
                        print_formatted_text(
                            HTML(
                                "       |─ <ansigreen><b>%s</b></ansigreen>:"
                                % (field_name)
                            ),
                            value,
                        )

                return True

        else:
            print_formatted_text(
                HTML("   |─ <ansimagenta><b>%s</b></ansimagenta>:" % (state.name))
            )
            for field_name, value in state.values.items():
                if value is not None:
                    print_formatted_text(
                        HTML(
                            "       |─ <ansigreen><b>%s</b></ansigreen>:" % (field_name)
                        ),
                        value,
                    )

            return True

    def _parse_args(self, args):
        """
        Function to parse the arguments for the values of a state, used in do_model

        :param args: The args to parse
        :type args: List
        """
        parsed_values = []

        hex_bytes_pattern = compile(
            r"^[0-9a-fA-F]{2,}$"
        )  # Even-length hex string, for bytes

        for arg in args:
            arg = arg.strip()

            # Try to parse as int
            try:
                parsed_values.append(int(arg, 0))
            except ValueError:
                continue

            # Check for bytes in hex (e.g., '0a78FF')
            if hex_bytes_pattern.match(arg) and len(arg) % 2 == 0:
                try:
                    parsed_values.append(bytes.fromhex(arg))
                except ValueError:
                    raise ValueError(f"Invalid hex string for bytes: {arg}")

            # Try to interpret as float
            else:
                try:
                    parsed_values.append(float(arg))
                except ValueError:
                    raise ValueError(f"Unrecognized value: {arg}")

        return parsed_values
