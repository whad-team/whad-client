from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode

from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.zcl.commands import ZCLCommands
from whad.zigbee.stack.apl.zcl.attributes import ZCLAttributes
from whad.zigbee.stack.apl.zcl.exceptions import ZCLCommandNotFound
from whad.zigbee.stack.apl.zcl.configuration import ZCLClusterConfiguration
from whad.zigbee.stack.apl.zcl.constants import ZCLClusterType

from scapy.layers.zigbee import ZigbeeClusterLibrary, ZCLGeneralReadAttributes
from whad.scapy.layers.zll import ZCLGeneralDiscoverAttributes, \
    ZCLGeneralDiscoverAttributesResponse, ZigbeeZLLCommissioningCluster

from inspect import stack,signature
from time import time
import logging

logger = logging.getLogger(__name__)


class ZCLClusterMetaclass(type):
    """
    Metaclass allowing to facilitate definition of Zigbee Cluster Library Clusters.
    """
    def __new__(cls, name, bases, attrs):
        # Define lists for cluster specific & profile wide commands
        cluster_specific_commands = {}
        profile_wide_commands = {}

        # Iterate over every commands callbacks
        for key, val in attrs.items():
            # if method is marked as a receive callback or generation callback
            receive_property = getattr(val, "_command_receive", None)
            generate_property = getattr(val, "_command_generate", None)

            # If it is a reception callback
            if receive_property is not None:
                # Get the command ID & name + if it is a profile wide command
                command_id, command_name, profile_wide = receive_property

                # Populate or update the right dictionnary
                commands = profile_wide_commands if profile_wide else cluster_specific_commands

                if command_id in commands:
                    # Update entry
                    commands[command_id]["name"] = command_name
                    commands[command_id]["receive_callback"] = val
                else:
                    # Create entry
                    commands[command_id] = {
                        "name":command_name,
                        "receive_callback": val,
                        "generate_callback":None
                    }

            # If it is a generation callback
            if generate_property is not None:

                # Get the command ID & name + if it is a profile wide command
                command_id, command_name, profile_wide = generate_property
                commands = profile_wide_commands if profile_wide else cluster_specific_commands

                # Populate or update the right dictionnary
                if command_id in commands:
                    # Update entry
                    commands[command_id]["name"] = command_name
                    commands[command_id]["generate_callback"] = val
                else:
                    # Create entry
                    commands[command_id] = {
                        "name":command_name,
                        "receive_callback": None,
                        "generate_callback": val
                    }

        # Generate new attributes according to the created dictionnaries
        if cluster_specific_commands != {}:
            attrs["CLUSTER_SPECIFIC_COMMANDS"] = cluster_specific_commands
        if profile_wide_commands != {}:
            attrs["PROFILE_WIDE_COMMANDS"] = profile_wide_commands

        # Iterate over attributes and populate the ZCL attributes accordingly
        attrs["ATTRIBUTES"] = {}
        # Split the annotations
        if "__annotations__" in attrs:
            for attribute, properties in attrs["__annotations__"].items():
                 attrs["ATTRIBUTES"][attribute] = {
                    "id":properties[0],
                    "permissions":properties[1],
                    "value":attrs[attribute]
                }
        # Build the class
        return super().__new__(cls, name, bases, attrs)


class ZCLCluster(Cluster, metaclass=ZCLClusterMetaclass):
    """
    Base class representing a Zigbee Cluster Library Cluster.
    """
    # Current transaction counter
    _transaction_counter = 0

    def __init__(
                    self,
                    cluster_id,
                    type,
                    default_configuration=ZCLClusterConfiguration()
    ):
        super().__init__(cluster_id)
        # Type of the cluster (Client or Server)
        self.type = type

        # Databases of attributes and commands
        self.attributes = ZCLAttributes()
        self.cluster_specific_commands = ZCLCommands()
        self.profile_wide_commands = ZCLCommands()

        # Populate the cluster specific commands database according to CLUSTER_SPECIFIC_COMMANDS dictionnary
        for command_id, command in self.CLUSTER_SPECIFIC_COMMANDS.items():
            generate_callback = None
            receive_callback = None

            if command["generate_callback"] is not None:
                generate_callback = getattr(self, command["generate_callback"].__name__)
            if command["receive_callback"] is not None:
                receive_callback = getattr(self, command["receive_callback"].__name__)

            # Add the command in the cluster specific commands database
            self.cluster_specific_commands.add_command(
                command_id,
                command["name"],
                generate_callback=generate_callback,
                receive_callback=receive_callback
            )

        # Populate the profile wide commands database according to PROFILE_WIDE_COMMANDS dictionnary
        for command_id, command in self.PROFILE_WIDE_COMMANDS.items():
            generate_callback = None
            receive_callback = None

            if command["generate_callback"] is not None:
                generate_callback = getattr(self, command["generate_callback"].__name__)
            if command["receive_callback"] is not None:
                receive_callback = getattr(self, command["receive_callback"].__name__)

            # Add the command in the profile wide commands database
            self.profile_wide_commands.add_command(
                command_id,
                command["name"],
                generate_callback=generate_callback,
                receive_callback=receive_callback
            )
        # Populate the attribute database
        for attribute, properties in self.ATTRIBUTES.items():
            self.attributes.add_attribute(
                properties["id"],
                attribute,
                properties["value"],
                properties["permissions"]
            )

        # Keep the default configuration and the active configuration
        self.default_configuration = default_configuration
        self.active_configuration = None

        # Pending responses
        self.pending_responses = {}
        # Cache keeping the last transaction
        self.last_transaction = None

        # List of destination nodes & the associated endpoints
        self.destinations = []


    @property
    def configuration(self):
        """
        Access the configuration.
        """
        if self.active_configuration is None:
            # if an active configuration is registered, use it.
            return self.default_configuration
        else:
            # Otherwise, use the default one.
            configuration = self.active_configuration
            self.active_configuration = None
            return configuration


    def connect(self, destination, endpoint):
        """
        Connect this cluster to a specific destination node endpoint.
        """
        for existing_destination in self.destinations:
            if existing_destination["address"] == destination and existing_destination["endpoint"] == endpoint:
                return

        self.destinations.append(
            {
                "address": destination,
                "endpoint": endpoint
            }
        )


    def disconnect(self, *destinations):
        """
        Disconnect this cluster from destination node endpoint(s).
        """
        removed_indexes = []
        for i in range(len(self.destinations)):
            if self.destinations[i] in destinations:
                removed_indexes.append(i)

        for i in removed_indexes:
            del self.destinations[i]


    def wait_response(self, transaction=None, timeout=1):
        """
        Wait for the response associated to a specific transaction (default: last transaction).
        """
        # if transaction not provided, use the last transaction by default
        if transaction is None:
            transaction = self.last_transaction

        # Clear the entry associated to the provided transaction in pending responses dictionnary
        self.pending_responses[transaction] = None

        start = time()
        while self.pending_responses[transaction] is None and time() - start < timeout:
            pass
        # If we got a response return it, otherwise a timeout occured and we return None
        if self.pending_responses[transaction] is not None:
            return_value = self.pending_responses[transaction]
        else:
            return_value = None
        del self.pending_responses[transaction]
        return return_value


    def configure(
                    self,
                    destination_address_mode = None,
                    destination_address = None,
                    destination_endpoint = None,
                    transaction = None,
                    alias_address=None,
                    alias_sequence_number=0,
                    radius=30,
                    security_enabled_transmission=False,
                    use_network_key=True,
                    acknowledged_transmission=False,
                    fragmentation_permitted=False,
                    include_extended_nonce=False,
                    disable_default_response=False,
                    interpan=False,
                    asdu_handle=0,
                    source_address_mode=MACAddressMode.EXTENDED,
                    destination_pan_id=0xFFFF
    ):
        """
        Update the active configuration.
        """
        self.active_configuration = ZCLClusterConfiguration(
            destination_address_mode = destination_address_mode,
            destination_address = destination_address,
            destination_endpoint = destination_endpoint,
            transaction = transaction,
            alias_address = alias_address,
            alias_sequence_number = alias_sequence_number,
            radius = radius,
            security_enabled_transmission = security_enabled_transmission,
            use_network_key = use_network_key,
            acknowledged_transmission = acknowledged_transmission,
            fragmentation_permitted = fragmentation_permitted,
            include_extended_nonce = include_extended_nonce,
            disable_default_response = disable_default_response,
            interpan=interpan,
            asdu_handle=asdu_handle,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id
        )



    def send_command(self, command):
        """
        Send a command.
        """
        csc = self.cluster_specific_commands
        pwc = self.profile_wide_commands
        # Find the command infos linked to the caller method
        found_calling_callback = False

        caller_function = getattr(self, stack()[1][3])
        cluster_specific = False

        try:
            command_id, command_structure = csc.get_command_by_callback(caller_function)
            cluster_specific = True
            found_calling_callback = True
        except ZCLCommandNotFound:
            pass

        if not cluster_specific:
            try:
                command_id, command_structure = pwc.get_command_by_callback(caller_function)
                cluster_specific = False
                found_calling_callback = True
            except ZCLCommandNotFound:
                pass

        # if we did not found the related info, returns
        if not found_calling_callback:
            return False

        logger.info("[zcl] Cluster {} (cluster_id={}) Transmitting {} command '{}' (command_id={})".format(
            self.__class__.__name__,
            hex(self.cluster_id),
            "cluster specific" if cluster_specific else "profile wide",
            command_structure.name,
            hex(command_id))
        )
        # Get the current configuration
        current_configuration = self.configuration

        # If no transaction counter is provided, use the global one
        if current_configuration.transaction is None:
            transaction = ZCLCluster._transaction_counter
            ZCLCluster._transaction_counter += 1
        else:
            transaction = current_configuration.transaction

        # Register the last transaction
        self.last_transaction = transaction

        # Build a ZigbeeClusterLibrary PDU according to current configuration
        asdu = ZigbeeClusterLibrary(
                zcl_frametype=1 if cluster_specific else 0,
                command_direction=(
                    0 if self.type == ZCLClusterType.CLIENT else 1
                ),
                command_identifier=command_id,
                transaction_sequence=transaction,
                disable_default_response=current_configuration.disable_default_response
        ) / command

        # If we need to use interpan, add ZLL Commissioning Cluster header
        if current_configuration.interpan:
            asdu = ZigbeeZLLCommissioningCluster(
                zcl_frametype=1 if cluster_specific else 0,
                direction=0 if self.type == ZCLClusterType.CLIENT else 1,
                command_identifier=command_id,
                transaction_sequence=transaction,
                disable_default_response=int(current_configuration.disable_default_response)
            ) / command

            # Send InterPAN data
            return self.send_interpan_data(
                asdu,
                asdu_handle=current_configuration.asdu_handle,
                source_address_mode=current_configuration.source_address_mode,
                destination_pan_id=current_configuration.destination_pan_id,
                destination_address=current_configuration.destination_address,
                destination_address_mode=current_configuration.destination_address_mode,
                acknowledged_transmission=current_configuration.acknowledged_transmission

            )
        else:
            # Send PAN data, to the destination address if provided, otherwise to registered destinations
            if current_configuration.destination_address is not None:
                return self.send_data(
                    asdu,
                    current_configuration.destination_address_mode,
                    current_configuration.destination_address,
                    current_configuration.destination_endpoint,
                    alias_address=current_configuration.alias_address,
                    alias_sequence_number=current_configuration.alias_sequence_number,
                    radius=current_configuration.radius,
                    security_enabled_transmission=current_configuration.security_enabled_transmission,
                    use_network_key=current_configuration.use_network_key,
                    acknowledged_transmission=current_configuration.acknowledged_transmission,
                    fragmentation_permitted=current_configuration.fragmentation_permitted,
                    include_extended_nonce=current_configuration.include_extended_nonce
                )
            else:
                for destination in self.destinations:
                    self.send_data(
                        asdu,
                        APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
                        destination["address"],
                        destination["endpoint"],
                        alias_address=current_configuration.alias_address,
                        alias_sequence_number=current_configuration.alias_sequence_number,
                        radius=current_configuration.radius,
                        security_enabled_transmission=current_configuration.security_enabled_transmission,
                        use_network_key=current_configuration.use_network_key,
                        acknowledged_transmission=current_configuration.acknowledged_transmission,
                        fragmentation_permitted=current_configuration.fragmentation_permitted,
                        include_extended_nonce=current_configuration.include_extended_nonce
                    )


    def on_interpan_data(self, asdu,destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        """
        Triggered when an InterPAN data is received by the cluster.

        Forwards the data to the right reception callback.
        """
        # Get command identifier
        command_identifier = asdu.command_identifier

        # Select the right command database depending on the type of command
        commands = (
            self.cluster_specific_commands if
            asdu.zcl_frametype == 1 else
            self.profile_wide_commands
        )
        # Try to find the corresponding reception callback in the database
        try:
            command = commands.get_command_by_id(command_identifier)

            # Raise an error if no command is found
            if command.receive_callback is None:
                raise ZCLCommandNotFound

            # Adapt informations to callbacks parameters, based on signature
            parameters = []
            callback_parameters = signature(command.receive_callback).parameters
            if ZigbeeClusterLibrary in asdu:
                base_class = ZigbeeClusterLibrary
            elif ZigbeeZLLCommissioningCluster in asdu:
                base_class = ZigbeeZLLCommissioningCluster
            for name, parameter in callback_parameters.items():
                if int(parameter.kind) == 1:
                    if name in ("payload","command"):
                        parameters += [asdu[base_class].payload]
                    elif name in ("source","src", "source_address"):
                        parameters += [source_address]
                    elif name in ("source_pan_id", "src_panid","source_panid"):
                        parameters += [source_pan_id]
                    elif name in ("destination","dest", "dest_address","destination_address"):
                        parameters += [destination_address]
                    elif name in ("destination_pan_id","dest_panid", "destination_panid"):
                        parameters += [destination_pan_id]
                    elif name in ("link_quality", "lqi"):
                        parameters += [link_quality]
                    elif name in ("transaction", "transaction_sequence"):
                        parameters += [asdu[base_class].transaction_sequence]
                    elif name in ("no_response", "disable_default_response"):
                        parameters += [asdu[base_class].disable_default_response]

            logger.info("[zcl] Cluster {} (cluster_id={}) Receiving {} interpan command '{}' (command_id={})".format(
                self.__class__.__name__,
                hex(self.cluster_id),
                "cluster specific" if asdu.zcl_frametype == 1 else "profile wide",
                command.name,
                hex(command_identifier))
            )
            # Call reception callback and update the pending response dict with the return value
            return_value = command.receive_callback(*parameters)
            if asdu.transaction_sequence in self.pending_responses:
                self.pending_responses[asdu.transaction_sequence] = return_value

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))


    def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
        """
        Triggered when a data is received by the cluster.

        Forwards the data to the right reception callback.
        """
        command_identifier = asdu.command_identifier
        commands = (
            self.cluster_specific_commands if
            asdu.zcl_frametype == 1 else
            self.profile_wide_commands
        )
        # Try to find the corresponding reception callback in the database
        try:
            command = commands.get_command_by_id(command_identifier)

            # If no reception callback is found, raise an error
            if command.receive_callback is None:
                raise ZCLCommandNotFound
            # Adapt informations to callbacks parameters, based on signature
            parameters = []
            callback_parameters = signature(command.receive_callback).parameters
            for name, parameter in callback_parameters.items():
                if int(parameter.kind) == 1:
                    if name in ("payload","command"):
                        parameters += [asdu[ZigbeeClusterLibrary].payload]
                    elif name in ("source","src", "source_address"):
                        parameters += [source_address]
                    elif name in ("source_mode","source_address_mode","mode"):
                        parameters += [source_address_mode]
                    elif name in ("security", "security_status"):
                        parameters += [security_status]
                    elif name in ("link_quality", "lqi"):
                        parameters += [link_quality]
                    elif name in ("transaction", "transaction_sequence"):
                        parameters += [asdu[ZigbeeClusterLibrary].transaction_sequence]
                    elif name in ("no_response", "disable_default_response"):
                        parameters += [asdu[ZigbeeClusterLibrary].disable_default_response]

            logger.info("[zcl] Cluster {} (cluster_id={}) Receiving {} command '{}' (command_id={})".format(
                self.__class__.__name__,
                hex(self.cluster_id),
                "cluster specific" if asdu.zcl_frametype == 1 else "profile wide",
                command.name,
                hex(command_identifier))
            )
            # Call reception callback and update the pending response dict with the return value
            return_value = command.receive_callback(*parameters)
            if asdu.transaction_sequence in self.pending_responses:
                self.pending_responses[asdu.transaction_sequence] = return_value

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))


    # Decorators
    def command_receive(command_id, command_name, profile_wide=False):
        """
        Mark a method as command reception callback.
        """
        def receive_decorator(f):
            f._command_receive = (command_id, command_name, profile_wide)
            return f
        return receive_decorator

    def command_generate(command_id, command_name, profile_wide=False):
        """
        Mark a method as command generator callback.
        """
        def generate_decorator(f):
            f._command_generate = (command_id, command_name, profile_wide)
            return f
        return generate_decorator

    # Profile wide commands
    @command_generate(0x00, "Read Attributes", profile_wide=True)
    def read_attributes(self, *attributes):
        """
        Read a list of attributes.
        """
        command = ZCLGeneralReadAttributes(attribute_identifiers=list(attributes))
        self.send_command(command)
        attributes = self.wait_response()
        return attributes

    @command_receive(0x0b, "Default Response", profile_wide=True)
    def on_default_response(self, command):
        """
        Processes a received default response.
        """
        return command.status

    @command_receive(0x01, "Read Attributes Response", profile_wide=True)
    def on_read_attributes_response(self, command):
        """
        Processes a Read Attributes response.
        """
        attributes = []
        for attribute in command.read_attribute_status_record:
            attributes.append(
                (
                    attribute.attribute_identifier,
                    attribute.status,
                    attribute.attribute_value if attribute.status == 0 else None
                )
            )
        return attributes

    @command_generate(0x0c, "Discover Attributes", profile_wide=True)
    def discover_attributes(self, start_identifier=0, max_reports=0xFFFF):
        """
        Discover a set of Attributes.
        """
        attributes = []
        command = ZCLGeneralDiscoverAttributes(
            start_attribute_identifier=start_identifier,
            max_attribute_identifiers=max_reports
        )
        self.send_command(command)
        return self.wait_response()

    @command_receive(0x0d, "Discover Attributes Response", profile_wide=True)
    def on_discover_attributes(self, command):
        """
        Processes a Discover Attributes response.
        """
        attributes = []
        for attribute in command.attribute_records:
            attributes.append(
                (
                    attribute.attribute_identifier,
                    attribute.attribute_data_type
                )
            )
        return (0 == command.discovery_complete, attributes)


    # Black magic to keep attributes database consistent with local variable
    def __setattr__(self, att, value):
        if "attributes" in self.__dict__:
            for attribute in self.__dict__["attributes"].attributes.values():
                if attribute.name == att:
                    attribute.value = value
        return super().__setattr__(att, value)

    def __getattribute__(self, att):
        if att != "__dict__" and "attributes" in self.__dict__:
            for attribute in self.__dict__["attributes"].attributes.values():
                if attribute.name == att:
                    super().__setattr__(att, attribute.value)
        return super().__getattribute__(att)


class ZCLClientCluster(ZCLCluster):
    """
    Base class for Zigbee Cluster Library Client Clusters.
    """
    @classmethod
    def child_clusters(cls):
        """
        Returns a list of child clusters classes.
        """
        subclasses = set()
        work = [cls]
        while work:
            parent = work.pop()
            for child in parent.__subclasses__():
                if child not in subclasses:
                    subclasses.add(child)
                    work.append(child)
        return subclasses

    def __init__(
                    self,
                    cluster_id,
                    default_configuration=ZCLClusterConfiguration()
    ):
        super().__init__(
            cluster_id,
            ZCLClusterType.CLIENT,
            default_configuration=default_configuration
        )

class ZCLServerCluster(ZCLCluster):
    """
    Base class for Zigbee Cluster Library Server Clusters.
    """
    @classmethod
    def child_clusters(cls):
        """
        Returns a list of child clusters classes.
        """
        subclasses = set()
        work = [cls]
        while work:
            parent = work.pop()
            for child in parent.__subclasses__():
                if child not in subclasses:
                    subclasses.add(child)
                    work.append(child)
        return subclasses


    def __init__(
                    self,
                    cluster_id,
                    default_configuration=ZCLClusterConfiguration()
    ):
        super().__init__(
            cluster_id,
            ZCLClusterType.SERVER,
            default_configuration=default_configuration
        )
