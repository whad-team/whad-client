from whad.device import WhadDevice, WhadDeviceConnector
from whad.zigbee.connector.enddevice import EndDevice

from prompt_toolkit import print_formatted_text, HTML

from whad.cli.shell import InteractiveShell, category
from whad.dot15d4.exceptions import InvalidDot15d4AddressException
from whad.dot15d4.address import Dot15d4Address
from whad.zigbee.profile.nodes import CoordinatorNode, RouterNode, EndDeviceNode, \
    EndpointsDiscoveryException
from whad.zigbee.stack.apl.constants import ZIGBEE_PROFILE_IDENTIFIERS, \
    ZIGBEE_DEVICE_IDENTIFIERS, ZIGBEE_CLUSTER_IDENTIFIERS

from whad.zigbee.stack.apl.zcl import ZCLClientCluster
from whad.zigbee.profile.network import JoiningForbidden, NotAssociated, NotAuthorized
from .cache import ZigbeeNetworksCache
from .helpers import create_enddevice

INTRO='''
zigbee-enddevice, the WHAD Zigbee end device utility
'''

class ZigbeeEndDeviceShell(InteractiveShell):
    """Zigbee End Device interactive shell
    """

    def __init__(self, interface: WhadDevice = None, connector=None, network_panid=None):
        super().__init__(HTML('<b>zigbee-enddevice></b> '))

        # If interface is None, pick the first matching our needs
        self.__interface = interface
        self.__cache = ZigbeeNetworksCache()
        self.__wireshark = None

        # If connector is not provided
        if connector is None:
            # Reset target info and connector.
            self.__target_network = None
            self.__target_network_panid = None
            self.__connector: WhadDeviceConnector = EndDevice(self.__interface)
        else:
            # If connector provided, consider the network already connected
            self.__connector = connector
            self.__target_network = None
            self.__target_network_panid = network_panid

        self.intro = INTRO

        self.update_prompt()


    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        """
        if not self.__target_network:
            self.set_prompt(HTML('<b>zigbee-enddevice></b> '), force)
        else:
            self.set_prompt(HTML('<b>zigbee-enddevice|<ansicyan>%s|%s</ansicyan>></b> ' % (
                    hex(self.__target_network['info'].pan_id),
                    str(Dot15d4Address(self.__target_network['info'].extended_pan_id))
                )
            ), force)


    @category('Networks discovery')
    def do_scan(self, args):
        """scan surrounding networks and show a small summary

        <ansicyan><b>scan</b></ansicyan>

        Scan surrounding networks and report them in this console in real-time.

        The following information is provided:
         - <b>Channel:</b> represents the channel where the network is deployed
         - <b>Pan ID:</b> short identifier of the ZigBee network
         - <b>Ext. Pan ID:</b> long (extended) identifier of the ZigBee network
         - <b>Joining:</b> indicates if joining the network is allowed or not

        You can stop a scan by hitting <b>CTL-c</b> at any time, the discovered networks are kept in
        memory and would be available in autocompletion.
        """

        # Start scanning
        print_formatted_text(HTML('<ansigreen>Channel   PAN ID   Ext. PAN ID             Joining</ansigreen>'))
        self.__connector.start()
        try:
            for network in self.__connector.discover_networks():
                # Show network
                print(
                        network.channel," "*6,
                        hex(network.pan_id)," ",
                        Dot15d4Address(network.extended_pan_id),
                        "permitted" if network.is_joining_permitted() else "forbidden"
                )

                # Add network to cache
                self.__cache.add(network)
        except KeyboardInterrupt as keybd_int:
            print('\rScan terminated by user')

        if self.__wireshark is not None:
            self.__wireshark.detach()

        self.__connector.stop()


    @category('Networks discovery')
    def do_networks(self, arg):
        """list discovered networks

        <ansicyan><b>networks</b></ansicyan>

        List every discovered networks so far, through the <ansicyan>scan</ansicyan> command.
        This command displays the content of the console networks cache.
        """
        print_formatted_text(HTML('<ansigreen>Channel   PAN ID   Ext. PAN ID             Joining</ansigreen>'))
        for network in self.__cache.iterate():
            # Show network
            print(
                    network['info'].channel," "*6,
                    hex(network['info'].pan_id)," ",
                    Dot15d4Address(network['info'].extended_pan_id),
                    "permitted" if network['info'].is_joining_permitted() else "forbidden"
            )



    def get_cache_targets(self):
        # Keep track of Extended PAN ID
        targets = [str(Dot15d4Address(network['info'].extended_pan_id)) for network in self.__cache.iterate()]
        targets.extend(['%s' % hex(network['info'].pan_id) for network in self.__cache.iterate()])
        return targets

    def complete_join(self):
        """Autocomplete the 'join' command, providing extended PAN ID of surrounding networks.
        """
        # Keep track of Extended PAN ID
        targets = self.get_cache_targets()
        completions = self.autocomplete_env()
        for address in targets:
            completions[address] = None
        return completions

    @category('Network interaction')
    def do_join(self, args):
        """join a network

        <ansicyan><b>join</b> <i>[ Extended PAN ID or PAN ID ]</i> </ansicyan>

        Initiate a ZigBee join to a specific network by its extended PAN ID or
        PAN ID. If multiple networks have the same PAN ID, the first one will be
        picked for join.
        """

        if len(args) < 1:
            self.error('<u>join</u> requires at least one parameter (extended PAN ID or PAN ID).\ntype \'help join\' for more details.')
            return

        #try:
        target = None

        try:
            target = self.__cache[args[0]]
            target_pan_id = Dot15d4Address(target['info'].extended_pan_id)

        except IndexError as notfound:
            # If target not in cache, we are expecting an extended PAN ID or a PAN ID
            try:
                target_pan_id = Dot15d4Address(args[0])
            except InvalidDot15d4AddressException:
                self.error('You must provide a valid extended PAN ID or PAN ID.')
                return

        # Look in cache by PAN ID
        if target is None:
            for network in self.__cache.iterate():
                if target_pan_id == network['info'].pan_id:
                    target = network
                    break

        if target is None:
            # Discover surrounding networks if needed
            for network in self.__connector.discover_networks():
                # Add network to cache
                if target_pan_id == network.extended_pan_id or target_pan_id == network.pan_id:
                    self.__cache.add(network)
                    target = self.__cache[target_pan_id]
                    break

            if target is None:
                self.error('No matching network found.')
                return

        try:
            # Attach our wireshark monitor, if any
            if self.__wireshark is not None:
                self.__wireshark.attach(self.__connector)

            print("Joining target network (PAN ID = %s / Ext. PAN ID = %s) on channel %d ..." % (
                hex(target['info'].pan_id),
                str(Dot15d4Address(target['info'].extended_pan_id)),
                target['info'].channel
                )
            )
            target['info'].join()
            print("Successfully joined to target network (PAN ID = %s / Ext. PAN ID = %s)." % (
                    hex(target['info'].pan_id),
                    str(Dot15d4Address(target['info'].extended_pan_id))
                )
            )
            if target['info'].network_key is not None:
                print_formatted_text(HTML('<ansicyan><b>Network key:</b></ansicyan> %s' % target['info'].network_key.hex()))

                self.__target_network = target
                # Update prompt
                self.update_prompt()

        except JoiningForbidden:
            self.error('Joining forbidden.')


    @category('Network interaction')
    def do_nodes(self, args):
        """discover nodes present within the associated network.

        <ansicyan><b>nodes</b></ansicyan>

        This command performs a nodes discovery, collecting all this information and
        keeping it in a dedicated <b>cache</b>.

        <aaa fg="orange">Sometimes this discovery process may cause an error and produces
        incomplete information, in this case try again and cross fingers.</aaa>
        """
        if self.__target_network is not None:
            if not self.__target_network['discovered']:
                print("Discovering surrounding nodes.")
                nodes = self.__target_network['info'].discover()
                self.__target_network['discovered'] = True

                for node in nodes:
                    if isinstance(node, CoordinatorNode):
                        print("New Coordinator discovered (addr. = %s, ext. addr. = %s)" % (
                                str(Dot15d4Address(node.address)),
                                str(Dot15d4Address(node.extended_address))
                            )
                        )
                    elif isinstance(node, RouterNode):
                        print("New Router discovered (addr. = %s, ext. addr. = %s)" % (
                                str(Dot15d4Address(node.address)),
                                str(Dot15d4Address(node.extended_address))
                            )
                        )
                    else:
                        print("New End Device discovered (addr. = %s, ext. addr. = %s)" % (
                                str(Dot15d4Address(node.address)),
                                str(Dot15d4Address(node.extended_address))
                            )
                        )

            print_formatted_text(HTML('<ansigreen>Addr.     Ext. addr.                  Type</ansigreen>'))

            for node in self.__target_network['info'].nodes:
                if isinstance(node, CoordinatorNode):
                    print("%s    %s     coordinator" % (
                            str(Dot15d4Address(node.address)),
                            str(Dot15d4Address(node.extended_address))
                        )
                    )
                elif isinstance(node, RouterNode):
                    print("%s    %s     router" % (
                            str(Dot15d4Address(node.address)),
                            str(Dot15d4Address(node.extended_address))
                        )
                    )
                else:
                    print("%s    %s     end device" % (
                            str(Dot15d4Address(node.address)),
                            str(Dot15d4Address(node.extended_address))
                        )
                    )
        else:
            self.error("You must join a network to perform a discovery.")
            return



    def get_cache_nodes(self):
        # Keep track of Nodes
        if self.__target_network is None:
            return []
        nodes = []
        if self.__target_network['discovered']:
            nodes = ["0x{:04x}".format(node.address) for node in self.__target_network['info'].nodes]
            nodes.extend(['%s' % str(Dot15d4Address(node.extended_address)) for node in self.__target_network['info'].nodes])
        return nodes

    def complete_endpoints(self):
        """Autocomplete the 'endpoints' command, providing address or extended address of neighbors nodes.
        """
        # Keep track of Extended PAN ID
        nodes = self.get_cache_nodes()
        completions = self.autocomplete_env()
        for address in nodes:
            completions[address] = None
        return completions

    @category('Node interaction')
    def do_endpoints(self, args):
        """discover endpoints related to a given node.

        <ansicyan><b>endpoints</b> <i>[addr. | ext. addr]</i></ansicyan>

        This command performs a endpoints discovery, collecting all this information and
        keeping it in a dedicated <b>cache</b>.

        <aaa fg="orange">Sometimes this discovery process may cause an error and produces
        incomplete information, in this case try again and cross fingers.</aaa>
        """
        if self.__target_network is not None:
            if len(args) < 1:
                self.error('No target node provided. ')
                return

            try:
                target_node = Dot15d4Address(args[0])
            except InvalidDot15d4AddressException:
                self.error("Invalid 802.15.4 address.")
                return

            if not self.__target_network['discovered']:
                print("Discovering surrounding nodes.")
                nodes = self.__target_network['info'].discover()
                self.__target_network['discovered'] = True

            selected_node = None
            for node in self.__target_network['info'].nodes:
                if (
                    target_node == Dot15d4Address(node.address) or
                    target_node == Dot15d4Address(node.extended_address)
                ):
                    selected_node = node
                    break

            if selected_node is None:
                self.error("No matching node found.")
                return
            try:
                for endpoint in selected_node.endpoints:
                    try:
                        profile_name = ZIGBEE_PROFILE_IDENTIFIERS[endpoint.profile_id]
                    except IndexError:
                        profile_name = "Unknown"

                    try:
                        device_name = ZIGBEE_DEVICE_IDENTIFIERS[endpoint.device_id]
                    except IndexError:
                        device_name = "Unknown device"

                    print_formatted_text(HTML('<ansigreen><b>Endpoint #%d: %s profile (%s) -> %s device (%s) </b></ansigreen>' %
                            (
                                endpoint.number,
                                profile_name,
                                hex(endpoint.profile_id),
                                device_name,
                                hex(endpoint.device_id)
                            )
                        )
                    )
                    print_formatted_text(HTML('  | <ansicyan><b>Input clusters:</b></ansicyan>'))
                    for cluster_id in endpoint.input_clusters:
                        try:
                            category, cluster_name = ZIGBEE_CLUSTER_IDENTIFIERS[cluster_id]
                        except IndexError:
                            category, cluster_name = ("Unknown category", "Unknown cluster")
                        print_formatted_text(HTML('    | <b>%s - %s (%s)</b>' % (category, cluster_name, hex(cluster_id))))

                    print_formatted_text(HTML('  | <ansicyan><b>Output clusters:</b></ansicyan>'))
                    for cluster_id in endpoint.output_clusters:
                        try:
                            category, cluster_name = ZIGBEE_CLUSTER_IDENTIFIERS[cluster_id]
                        except IndexError:
                            category, cluster_name = ("Unknown category", "Unknown cluster")
                        print_formatted_text(HTML('    | <b>%s - %s (%s)</b>' % (category, cluster_name, hex(cluster_id))))
                print()

            except EndpointsDiscoveryException:
                self.error("An error occured during endpoints discovery.")
                return
        else:
            self.error("You must join a network to perform a discovery.")
            return

    def get_cache_endpoints(self, address):
        input_clusters = {}
        for node in self.__target_network['info'].nodes:
            if address == "0x{:04x}".format(node.address) or address == str(Dot15d4Address(node.extended_address)).lower():
                endpoints = {}
                for endpoint in node.endpoints:
                    input_clusters = {}
                    for input_cluster in endpoint.input_clusters:
                        commands = {}
                        for candidate_cluster_class in ZCLClientCluster.child_clusters():
                            candidate = candidate_cluster_class()
                            if candidate.cluster_id == input_cluster:
                                for command_id, command in candidate.CLUSTER_SPECIFIC_COMMANDS.items():
                                    commands[str(command['name'].replace(' ', '_').lower())] = None
                                for command_id, command in candidate.PROFILE_WIDE_COMMANDS.items():
                                    commands[str(command['name'].replace(' ', '_').lower())] = None
                                break
                        input_clusters[str(input_cluster)] = commands
                    endpoints[str(endpoint.number)] = input_clusters
        return endpoints

    def complete_cluster_cmd(self):
        """Autocomplete the 'cluster_cmd' command, providing address or extended address of neighbors nodes.
        """
        # Keep track of Extended PAN ID
        nodes = self.get_cache_nodes()
        completions = self.autocomplete_env()
        for address in nodes:
            input_clusters = self.get_cache_endpoints(address)
            '''
            for node in self.__target_network['info'].nodes:
                if address == "0x{:04x}".format(node.address) or address == str(Dot15d4Address(node.extended_address)).lower():
                    for endpoint in node.endpoints:
                        for input_cluster in endpoint.input_clusters:
                            input_clusters[str(input_cluster)] = None
                            try:
                                category, cluster_name = ZIGBEE_CLUSTER_IDENTIFIERS[input_cluster]
                                cluster_name = cluster_name.replace(" ", "_").replace("/","").lower()
                                input_clusters[cluster_name] = None

                            except IndexError:
                                pass
            '''
            completions[address] = input_clusters
        return completions

    @category('Node interaction')
    def do_cluster_cmd(self, args):
        """Run a cluster command on a given node.

        <ansicyan><b>cluster_cmd</b> <i>[addr. | ext. addr] [cluster id | cluster name] [cmd id | cmd name] [cmd parameters]</i></ansicyan>

        This command performs a cluster command targeted on a given name.
        """
        if self.__target_network is not None:
            if len(args) < 1:
                self.error('No target node provided. ')
                return

            if len(args) < 2:
                self.error('No target endpoint provided. ')
                return

            if len(args) < 3:
                self.error('No target cluster provided. ')
                return

            if len(args) < 4:
                self.error('No target cluster command provided. ')
                return

            try:
                target_node = Dot15d4Address(args[0])
            except InvalidDot15d4AddressException:
                self.error("Invalid 802.15.4 address.")
                return

            try:
                target_endpoint = int(args[1])
            except:
                self.error("Invalid endpoint.")
                return

            try:
                target_cluster = int(args[2])
            except:
                self.error("Invalid cluster.")
                return


            try:
                target_cmd = args[3]
                if len(args) >= 4:
                    target_cmd_parameters = args[4:]
                else:
                    target_cmd_parameters = None
            except:
                self.error("Invalid command.")
                return


            if not self.__target_network['discovered']:
                print("Discovering surrounding nodes.")
                nodes = self.__target_network['info'].discover()
                self.__target_network['discovered'] = True

            selected_node = None
            for node in self.__target_network['info'].nodes:
                if (
                    target_node == Dot15d4Address(node.address) or
                    target_node == Dot15d4Address(node.extended_address)
                ):
                    selected_node = node
                    break

            if selected_node is None:
                self.error("No matching node found.")
                return
            try:
                selected_endpoint = None
                for endpoint in selected_node.endpoints:
                    if endpoint.number == target_endpoint:
                        selected_endpoint = endpoint
                        break

                if selected_endpoint is None:
                    self.error("No matching endpoint found.")
                    return

                cluster = None
                if target_cluster in selected_endpoint.input_clusters:
                    cluster = selected_endpoint.attach_to_input_cluster(target_cluster)

                if cluster is None:
                    self.error("No matching cluster or cluster not implemented.")
                    return

                selected_command_name = None
                for command_id, command in cluster.PROFILE_WIDE_COMMANDS.items():
                    if target_cmd == command['name'].replace(" ","_").lower():
                        selected_command_name = command['generate_callback'].__name__

                for command_id, command in cluster.CLUSTER_SPECIFIC_COMMANDS.items():
                    if target_cmd == command['name'].replace(" ","_").lower():
                        selected_command_name = command['generate_callback'].__name__

                if selected_command_name is None:
                    self.error("No matching command found.")
                    return

                getattr(cluster, selected_command_name)()

            except EndpointsDiscoveryException:
                self.error("An error occured during cluster command.")
                return
        else:
            self.error("You must join a network to perform a cluster command.")
            return
