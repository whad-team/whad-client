from whad.cli.shell import InteractiveShell, category
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connectors.provisionee import Provisionee
from whad.btmesh.models import ModelServer, CompositeModelState
from prompt_toolkit import HTML, print_formatted_text

from whad.exceptions import ExternalToolNotFound

from whad.common.monitors import WiresharkMonitor
from re import match

INTRO = """
wbtmesh-provisionee, the WHAD Bluetooth Mesh Provisionee utility
"""

SETUP_CAT = "Setup node"
ELEMENT_CAT = "Element edit"
ATTACK_CAT = "Attacks"
MISC = "Miscellaneous"


class BTMeshProvisioneeShell(InteractiveShell):
    MODE_NORMAL = 0
    MODE_STARTED = 1
    MODE_ELEMENT_EDIT = 2

    def __init__(self, interface=None, profile=BaseMeshProfile):
        super().__init__(HTML("<b>wbtmesh-provisionee></b> "))

        self._current_mode = self.MODE_NORMAL

        # Device parameters
        self._complete_name = "WhadDev"
        self._shortened_name = None

        # If interface is None, pick the first matching our needs
        self._interface = interface

        # Profile
        self._profile = profile()

        # Index of element in MODE_ELEMENT_EDIT and MODE_MODEL_EDIT modes
        self._selected_element = None

        # Model id of the selected model in MODE_MODEL_EDIT
        self._selected_model = None

        self._connector = None
        self._wireshark = None
        self.intro = INTRO

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

    @category(SETUP_CAT)
    def do_start(self, arg):
        """Start the provisionee.
        Recalling it will reset the node.

        <ansicyan><b>start</b> <i>["auto"]</i></ansicyan>

        Starts the provisionee.

        This command can auto the node if specified with :

        > start auto

        If not specified, will send Unprovisioned Device Beacons to be provisioned.
        """

        # Switch to emulation mode
        self._current_mode = self.MODE_STARTED
        self.update_prompt()

        auto_provision = False

        if len(arg) >= 1:
            auto_provision = arg[0].lower() == "auto"

        # Instanciate our Peripheral
        self._connector = Provisionee(
            self._interface, profile=self._profile, auto_provision=auto_provision
        )
        self._connector.start()

    @category(SETUP_CAT)
    def do_address(self, arg):
        """Manages the device's primary unicast address

        <ansicyan><b>address</b> <i>[value]</i></ansicyan>

        This command will set the primary unicast address of the device to 0x05 :

        > address 0x0005

        By default, will print de device's address
        """

        if self._current_mode != self.MODE_STARTED:
            self.error("Need to have the devices started")
            return

        addr = None
        if len(arg) >= 1:
            try:
                addr = int(arg[0], 16)
            except ValueError:
                self.error("Address must be in hexadecimal form")
                return

            if addr > 32767:
                self.error("Address must be lower than 0x7FFF")
                return

        addr = self._connector.do_address(address=addr)

        self.success("Address of the device is now : 0x%x" % addr)

    @category(SETUP_CAT)
    def do_relay(self, arg):
        """Activate or deactivate the relaying of messages by the device (should be provisioned)

        <ansicyan><b>relay</b>  [<i>on/off</i>]</ansicyan>

        Activate : <b>relay</b> <i>on</i>

        By default, this command shows the relay status of the node
        """

        if self._current_mode != self.MODE_STARTED:
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

        self._connector.start_listening()
        self._current_mode = self.MODE_STARTED

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

        After provisioning, only editing states will function.
        """

        if len(args) > 0:
            action = args[0].lower()
            if action == "add":
                if self._current_mode != self.MODE_NORMAL:
                    self.error("Cannot add elements after provisioning")
                    return

                index = self._profile.register_element(is_primary=False)

                self.success("Element %d successfully added." % index)

            elif action == "remove":
                if self._current_mode != self.MODE_NORMAL:
                    self.error("Cannot remove elements after provisioning")
                    return

                if len(args) >= 2:
                    try:
                        index = int(args[1])
                    except ValueError:
                        self.error("Index needs to be an int")
                        return

                    if index == 0:
                        self.error("Cannot delete primary element")

                    elif self._profile.remove_elements(index):
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
                        index = int(args[1])
                    except ValueError:
                        self.error("Index needs to be an int")
                        return

                    element = self._profile.get_element(index)
                    if element is None:
                        self.error(
                            "Invalid element index, element %d does not exist." % index
                        )
                        return

                    if self._connector is not None:
                        self._connector.stop_listening()

                    self._selected_element = index
                    self._current_mode = self.MODE_ELEMENT_EDIT

                else:
                    self.error("Need to specify an element index to edit")

        else:
            elements = self._profile.get_all_elements()

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

    @category(SETUP_CAT)
    def do_model(self, args):
        """Manage device's models (in an element), specifically its bounded states (and those of its base models). Only functions on Server models !
        Names of composite states are <i>BASE_STATE.SUB_STATE</i> or <i>STATE.FIELD_NAME</i>

        Ex : <i>health_fault.current_fault</i>

        <i>FIELD_NAME</i> not specified will targte the "default" key.

        NEED TO BE IN ELEMENT EDIT MODE

        <ansicyan><b>model</b> [<i>MODEL_ID</i>] [<i>ACTION</i> <i>[PARAMS]</i>]</ansicyan>

        - <b>read</b>: reads the value of the state of an element
        - <b>write</b>: write in the state's value
        - <b>list</b>: list the states of the specified model

        To read a state of the model : <b>model</b> <i>MODEL_ID</i> <i>read</i> <i>STATE_NAME</i>

        To write to the state of the model : <b>model</b> <i>MODEL_ID</i> <i>write</i> <i>STATE_NAME</i> <i>VALUE</i>

        To list the states of a model (no values) : <b>model</b> <i>MODEL_ID</i> <i>list</i>

        By default, this command lists the models of the element.

        Writing/reseting to NetKeyList, AppKeyList, ModelToAppKeyList uses other commands.
        """

        if self._current_mode != self.MODE_ELEMENT_EDIT:
            self.error("Can only edit models whilst in Element edit mode.")
            return

        element = self._profile.get_element(self._selected_element)
        if len(args) >= 2:
            try:
                model_id = int(args[0], 16)
            except ValueError:
                self.error("Model id is in hex format.")
                return
            model = element.get_model_by_id(model_id)

            if model is None:
                self.error(
                    "Model with id %d does not exist in this element." % model_id
                )
                return

            action = args[1].lower()

            if action == "list":
                if len(args) < 2:
                    self.error("You need to specify a model id to list its states.")
                    return

                if not isinstance(model, ModelServer):
                    self.error("Can only list states of a server model.")
                    return

                print_formatted_text(
                    HTML("<ansicyan><b>Model 0x%x</b></ansicyan>:" % model.model_id)
                )
                if len(model.states) == 0:
                    print_formatted_text(HTML(" <i>No states defined</i>"))
                    return

                for state in model.states.values():
                    if isinstance(state, CompositeModelState):
                        print_formatted_text(
                            HTML(
                                "|─ <ansimagenta><b>%s</b></ansimagenta> :" % state.name
                            )
                        )
                        for sub_state in state.sub_states.values():
                            print_formatted_text(
                                HTML(
                                    "  |─ <ansiyellow><b>%s</b></ansiyellow>"
                                    % sub_state.name,
                                )
                            )
                    else:
                        print_formatted_text(
                            HTML("|─ <ansimagenta><b>%s</b></ansimagenta>" % state.name)
                        )

            if action == "read":
                if len(args) < 3:
                    self.error("Need to specify the state name")

                state_name = args[2].lower().split(".")

                state = model.get_state(state_name[0])
                if state is None:
                    self.error(
                        "State %s does not exists in model %d."
                        % (state_name[0], model_id)
                    )
                    return

                # Only one state name = no composite
                if len(state_name) == 1:
                    if isinstance(state, CompositeModelState):
                        self.error(
                            "State %s is a composite state, specify sub state."
                            % state.name
                        )
                        return

                    print_formatted_text(
                        HTML(
                            "<ansimagenta><b>%s</b></ansimagenta> : %s"
                            % (state.name, state.values)
                        )
                    )

                # either compositestate of specific field in normal state
                elif len(state_name) == 2:
                    if isinstance(state, CompositeModelState):
                        sub_state = state.get_sub_state(state_name[1])
                        if sub_state is None:
                            self.error(
                                "State %s does not exists in model %d."
                                % (state_name[0] + state_name[1], model_id)
                            )
                            return

                        print_formatted_text(
                            HTML(
                                "<ansimagenta><b>%s</b></ansimagenta>: %s"
                                % (state.name + sub_state.name, sub_state.values)
                            )
                        )
                    else:
                        value = state.get_value(state_name[1])
                        if value is None:
                            self.error(
                                "State %s does not exists in model %d."
                                % (state_name[0] + state_name[1], model_id)
                            )
                            return

                        print_formatted_text(
                            HTML(
                                "<ansimagenta><b>%s</b></ansimagenta>: %s"
                                % (
                                    state.name + state_name[1],
                                    value,
                                )
                            )
                        )

            elif action == "write":
                if len(args) < 4:
                    self.error("Need to specify the state name and value")

                state_name = args[2].lower().split(".")

                state = model.get_state(state_name[0])
                if state is None:
                    self.error(
                        "State %s does not exists in model %d."
                        % (state_name[0], model_id)
                    )
                    return

                state_name = args[2].lower().split(".")

                state = model.get_state(state_name[0])

                if state is None:
                    self.error(
                        "State %s does not exists in model %d."
                        % (state_name[0], model_id)
                    )
                    return
                try:
                    value = int(args[3], 16)
                except ValueError:
                    self.error("Value should be a hex int.")

                # Only one state name = no composite
                if len(state_name) == 1:
                    if isinstance(state, CompositeModelState):
                        self.error(
                            "State %s is a composite state, specify sub state."
                            % state.name
                        )
                        return

                    state.set_value(value)
                    self.success("Successfully set the value for the state.")

                # either compositestate of specific field in normal state
                elif len(state_name) == 2:
                    if isinstance(state, CompositeModelState):
                        sub_state = state.get_sub_state(state_name[1])
                        if sub_state is None:
                            self.error(
                                "State %s does not exists in model %d."
                                % (state_name[0] + state_name[1], model_id)
                            )
                            return
                        sub_state.set_value(value)
                        self.success("Successfully set the value for the state")

                    else:
                        field_name = state_name[1].lower()
                        state.set_value(field_name=field_name, value=value)
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

        if self._current_mode != self.MODE_STARTED:
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
        """Manages the sequence number of the node


        <ansicyan><b>seqnum</b> [<i>seqnum</i>]</ansicyan>

        By default, prints the current sequence number.

        To set the sequence number :

        > seqnum 0xA10010
        """

        if self._current_mode != self.MODE_STARTED:
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
                seqnum = int(arg[0], 16)
            except ValueError:
                self.error("Sequence number should be in hex format.")
                return

            if seqnum > 0xFFFFFF:
                self.error("Sequence Number cannot be larger than 0xFFFFFF.")
                return

            self._connector.profile.set_seq_number(seqnum)
            self.success("Successfully set the sequence number to 0x%x." % seqnum)

    @category(MISC)
    def do_onoff(self, args):
        """Sends an onoff message via DF
        <ansicyan><b>onoff</b> <i>"1"|"0"</i> <i>addr</i> [<i>"acked"|"unacked"</i>]</ansicyan>

        > onoff 1 0x0004 acked

        By default, sends the message unacked
        """

        if len(args) < 2:
            self.error("You need to specify value and a destination address and ")
            return

        try:
            value = abs(int(args[0]))
            addr = int(args[1], 16)
        except ValueError:
            self.error(
                "Value is either '0' or '1', and address is a 2 bytes hexadecimal int."
            )
            return

        if value > 1:
            self.error("Value is either '0' or '1'.")
            return

        acked = False
        if len(args) >= 3:
            acked = args[2] == "acked"

        self._connector.do_onoff(value, addr, acked)
        self.success("Successfully sent onoff message.")

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
