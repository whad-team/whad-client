from whad.cli.shell import InteractiveShell, category
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connectors.df_attack import DFAttacks
from whad.btmesh.models import ModelServer, CompositeModelState
from prompt_toolkit import HTML, print_formatted_text

from whad.exceptions import ExternalToolNotFound

from whad.common.monitors import WiresharkMonitor

INTRO = """
wbtmesh-provisionee, the WHAD Bluetooth Mesh Provisionee utility
"""

SETUP_CAT = "Setup node"
ELEMENT_CAT = "Element edit"
ATTACK_CAT = "Attacks"


class BTMeshProvisioneeShell(InteractiveShell):
    MODE_NORMAL = 0
    MODE_STARTED = 1
    MODE_ELEMENT_EDIT = 2

    def __init__(self, interface=None, profile=BaseMeshProfile):
        super().__init__(HTML("<b>wbtmesh-provisionee></b> "))

        self.__current_mode = self.MODE_NORMAL

        # Device parameters
        self.__complete_name = "WhadDev"
        self.__shortened_name = None

        # If interface is None, pick the first matching our needs
        self.__interface = interface

        # Profile
        self.__profile = profile()

        # Index of element in MODE_ELEMENT_EDIT and MODE_MODEL_EDIT modes
        self.__selected_element = None

        # Model id of the selected model in MODE_MODEL_EDIT
        self.__selected_model = None

        self.__connector = None
        self.__wireshark = None
        self.intro = INTRO

        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state"""
        # Are we in element edit mode ?
        if self.__current_mode == self.MODE_ELEMENT_EDIT:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-provisionee | <ansicyan>element(%d)</ansicyan>></b> "
                    % (self.__selected_element)
                ),
                force,
            )
        elif self.__current_mode == self.MODE_NORMAL:
            self.set_prompt(HTML("<b>wbtmesh-provisionee></b> "), force)
        elif self.__current_mode == self.MODE_STARTED:
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
        self.__current_mode = self.MODE_STARTED
        self.update_prompt()

        auto_provision = False

        if len(arg) >= 1:
            auto_provision = arg[0].lower() == "auto"

        # Instanciate our Peripheral
        self.__connector = DFAttacks(
            self.__interface, profile=self.__profile, auto_provision=auto_provision
        )
        self.__connector.start()

    @category(SETUP_CAT)
    def do_resume(self, arg):
        """Resumes the normal behaviour of a provisioned node (after editing an element)

        <ansicyan><b>resume</b></ansicyan>
        """

        self.__connector.start_listening()
        self.__current_mode = self.MODE_STARTED

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
                if self.__current_mode != self.MODE_NORMAL:
                    self.error("Cannot add elements after provisioning")
                    return

                index = self.__profile.register_element(is_primary=False)

                self.success("Element %d successfully added." % index)

            elif action == "remove":
                if self.__current_mode != self.MODE_NORMAL:
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

                    elif self.__profile.remove_elements(index):
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

                    element = self.__profile.get_element(index)
                    if element is None:
                        self.error(
                            "Invalid element index, element %d does not exist." % index
                        )
                        return

                    if self.__connector is not None:
                        self.__connector.stop_listening()

                    self.__selected_element = index
                    self.__current_mode = self.MODE_ELEMENT_EDIT

                else:
                    self.error("Need to specify an element index to edit")

        else:
            elements = self.__profile.get_all_elements()

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

        if self.__current_mode != self.MODE_ELEMENT_EDIT:
            self.error("Can only edit models whilst in Element edit mode.")
            return

        element = self.__profile.get_element(self.__selected_element)
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

    @category(ATTACK_CAT)
    def do_network_discovery(self, args):
        """Performs discovery of the network (on a network with directed forwarding)

        <ansicyan><b>network_discovery</b> <i>addr_low</i> <i>addr_low</i></ansicyan>

        > network_discovery 0001 00AA
        """
        if self.__current_mode != self.MODE_STARTED:
            self.error(
                "Need to have a provisioned node started to launch the discovery."
            )
            return

        if len(args) < 2:
            self.error("Please provide the range of addresses to discover")
            return

        try:
            addr_low = int(args[0], 16)
            addr_high = int(args[1], 16)
        except ValueError:
            self.error("Please provide the addresses in hex format")
            return

        self.__connector.do_network_discovery(addr_low, addr_high)
        self.success("Successfully started the network_discovery attack.")
        self.success("Wait a little to ask for the topolgy")

    @category(ATTACK_CAT)
    def do_get_network(self, arg):
        """Prints the result of the last network discovery (might not be complete if you have not waited enough)

        <ansicyan><b>get_network</b</ansicyan>
        """
        topology = self.__connector.get_network_topology()

        for range_start, (range_length, distance) in topology.items():
            print_formatted_text(
                HTML(
                    "|─ <ansimagenta><b>Node 0x%x to 0x%x , %d hops away</b></ansimagenta>"
                    % (range_start, range_start + range_length, distance)
                )
            )

    @category(SETUP_CAT)
    def do_activate_df(self, arg):
        """Activates DF to all nodes using via a DIRECTED_CONTROL_SET message (to the broadcast address)

        Activates it for net 0.

        <ansicyan><b>activate_df</b> [<i>APP_KEY_IDX</i>]</ansicyan>

        To send the message using the AppKey with index 1 :

        > activate_df 1

        By default, uses AppKey with index 0.
        """
        if self.__current_mode != self.MODE_STARTED:
            self.error("Need to have a provisioned node started to send this message.")
            return

        if len(arg) > 0:
            try:
                app_key_index = int(arg[0])
            except ValueError:
                self.error("AppKey index should be an int in decimal base.")
                return
        else:
            app_key_index = 0

        success = self.__connector.df_set(app_key_index)
        if not success:
            self.error(
                "Could not send the message. App key index specified might be invalid."
            )
        else:
            self.success(
                "Successfully sent the DIRECTED_CONTROL_SET message to broadcast address."
            )

    def complete_wireshark(self):
        """Autocomplete wireshark command"""
        completions = {}
        if self.__wireshark is not None:
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
                if self.__wireshark is None:
                    try:
                        self.__wireshark = WiresharkMonitor()
                        if self.__connector is not None:
                            self.__wireshark.attach(self.__connector)
                            self.__wireshark.start()
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
                if self.__wireshark is not None:
                    self.__wireshark.detach()
                    self.__wireshark.close()
                    self.__wireshark = None
        else:
            self.error("Missing arguments, see <ansicyan>help wireshark</ansicyan>.")
