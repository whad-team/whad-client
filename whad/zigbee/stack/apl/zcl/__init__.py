from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.zcl.attributes import ZCLAttributes
from whad.zigbee.stack.apl.zcl.commands import ZCLCommands
from whad.zigbee.stack.apl.zcl.exceptions import ZCLCommandNotFound
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from scapy.layers.zigbee import ZigbeeClusterLibrary, ZCLGeneralReadAttributes
from whad.scapy.layers.zll import ZCLGeneralDiscoverAttributes, ZCLGeneralDiscoverAttributesResponse
from inspect import stack,signature
from enum import IntEnum
import logging
from time import time

logger = logging.getLogger(__name__)

class ZCLClusterMetaclass(type):

    def __new__(cls, name, bases, attrs):
        cluster_specific_commands = {}
        profile_wide_commands = {}

        for key, val in attrs.items():
            receive_property = getattr(val, "_command_receive", None)
            generate_property = getattr(val, "_command_generate", None)
            if receive_property is not None:
                command_id, command_name, profile_wide = receive_property
                commands = profile_wide_commands if profile_wide else cluster_specific_commands
                if command_id in commands:
                    commands[command_id]["name"] = command_name
                    commands[command_id]["receive_callback"] = val
                else:
                    commands[command_id] = {"name":command_name, "receive_callback": val, "generate_callback":None}

            if generate_property is not None:
                command_id, command_name, profile_wide = generate_property
                commands = profile_wide_commands if profile_wide else cluster_specific_commands
                if command_id in commands:
                    commands[command_id]["name"] = command_name
                    commands[command_id]["generate_callback"] = val
                else:
                    commands[command_id] = {"name":command_name, "receive_callback": None, "generate_callback": val}

        if cluster_specific_commands != {}:
            attrs["CLUSTER_SPECIFIC_COMMANDS"] = cluster_specific_commands
        if profile_wide_commands != {}:
            attrs["PROFILE_WIDE_COMMANDS"] = profile_wide_commands
        attrs["ATTRIBUTES"] = {}
        if "__annotations__" in attrs:
            for attribute, properties in attrs["__annotations__"].items():
                 attrs["ATTRIBUTES"][attribute] = {"id":properties[0], "permissions":properties[1], "value":attrs[attribute]}
        return super().__new__(cls, name, bases, attrs)

class ZCLClusterType(IntEnum):
    CLIENT = 0
    SERVER = 1

class ZCLClusterConfiguration:
    def __init__(   self,
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
                    disable_default_response=False
    ):
        self.destination_address_mode = destination_address_mode
        self.destination_address = destination_address
        self.destination_endpoint = destination_endpoint
        self.transaction = transaction
        self.alias_address = alias_address
        self.alias_sequence_number = alias_sequence_number
        self.radius = radius
        self.security_enabled_transmission = security_enabled_transmission
        self.use_network_key = use_network_key
        self.acknowledged_transmission = acknowledged_transmission
        self.fragmentation_permitted = fragmentation_permitted
        self.include_extended_nonce = include_extended_nonce
        self.disable_default_response = disable_default_response

class ZCLCluster(Cluster, metaclass=ZCLClusterMetaclass):
    _transaction_counter = 0

    def __init__(self, cluster_id, type, default_configuration=ZCLClusterConfiguration()):
        super().__init__(cluster_id)
        self.type = type
        self.attributes = ZCLAttributes()
        self.cluster_specific_commands = ZCLCommands()
        self.profile_wide_commands = ZCLCommands()

        for command_id, command in self.CLUSTER_SPECIFIC_COMMANDS.items():
            generate_callback = None
            receive_callback = None

            if command["generate_callback"] is not None:
                generate_callback = getattr(self, command["generate_callback"].__name__)
            if command["receive_callback"] is not None:
                receive_callback = getattr(self, command["receive_callback"].__name__)

            self.cluster_specific_commands.add_command(
                command_id,
                command["name"],
                generate_callback=generate_callback,
                receive_callback=receive_callback
            )

        for command_id, command in self.PROFILE_WIDE_COMMANDS.items():
            generate_callback = None
            receive_callback = None

            if command["generate_callback"] is not None:
                generate_callback = getattr(self, command["generate_callback"].__name__)
            if command["receive_callback"] is not None:
                receive_callback = getattr(self, command["receive_callback"].__name__)

            self.profile_wide_commands.add_command(
                command_id,
                command["name"],
                generate_callback=generate_callback,
                receive_callback=receive_callback
            )
        for attribute, properties in self.ATTRIBUTES.items():
            self.attributes.add_attribute(properties["id"], attribute, properties["value"], properties["permissions"])

        self.default_configuration = default_configuration
        self.active_configuration = None

        self.pending_responses = {}
        self.last_transaction = None
        self.destinations = []

    @property
    def configuration(self):
        if self.active_configuration is None:
            return self.default_configuration
        else:
            configuration = self.active_configuration
            self.active_configuration = None
            return configuration

    def connect(self, destination, endpoint):
        self.destinations.append({"address": destination, "endpoint": endpoint})

    def disconnect(self, *destinations):
        removed_indexes = []
        for i in range(len(self.destinations)):
            if self.destinations[i] in destinations:
                removed_indexes.append(i)
        for i in removed_indexes:
            del self.destinations[i]

    def wait_response(self, transaction=None, timeout=2):
        if transaction is None:
            transaction = self.last_transaction
        self.pending_responses[transaction] = None
        start = time()
        while self.pending_responses[transaction] is None and time() - start < timeout:
            pass
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
                    disable_default_response=False
    ):
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
            disable_default_response = disable_default_response
        )

    def send_command(self, command):
        found_calling_callback = False

        caller_function = getattr(self, stack()[1][3])
        cluster_specific = False

        try:
            command_id, command_structure = self.cluster_specific_commands.get_command_by_callback(caller_function)
            cluster_specific = True
            found_calling_callback = True
        except ZCLCommandNotFound:
            pass

        if not cluster_specific:
            try:
                command_id, command_structure = self.profile_wide_commands.get_command_by_callback(caller_function)
                cluster_specific = False
                found_calling_callback = True
            except ZCLCommandNotFound:
                pass

        if not found_calling_callback:
            return False

        logger.info("[zcl] Cluster {} (cluster_id={}) Transmitting {} command '{}' (command_id={})".format(
            self.__class__.__name__,
            hex(self.cluster_id),
            "cluster specific" if cluster_specific else "profile wide",
            command_structure.name,
            hex(command_id))
        )
        current_configuration = self.configuration

        if current_configuration.transaction is None:
            transaction = ZCLCluster._transaction_counter
            ZCLCluster._transaction_counter += 1
        else:
            transaction = current_configuration.transaction

        self.last_transaction = transaction

        asdu = ZigbeeClusterLibrary(
                zcl_frametype=1 if cluster_specific else 0,
                command_direction=0 if self.type == ZCLClusterType.CLIENT else 1,
                command_identifier=command_id,
                transaction_sequence=transaction,
                disable_default_response=current_configuration.disable_default_response
        ) / command

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


    def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
        command_identifier = asdu.command_identifier
        commands = self.cluster_specific_commands if asdu.zcl_frametype == 1 else self.profile_wide_commands
        try:
            command = commands.get_command_by_id(command_identifier)
            if command.receive_callback is None:
                raise ZCLCommandNotFound
            # Adapt informations to callbacks parameters
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
            return_value = command.receive_callback(*parameters)
            if asdu.transaction_sequence in self.pending_responses:
                self.pending_responses[asdu.transaction_sequence] = return_value

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))

    # Decorators
    def command_receive(command_id, command_name, profile_wide=False):
        def receive_decorator(f):
            f._command_receive = (command_id, command_name, profile_wide)
            return f
        return receive_decorator

    def command_generate(command_id, command_name, profile_wide=False):
        def generate_decorator(f):
            f._command_generate = (command_id, command_name, profile_wide)
            return f
        return generate_decorator

    # profile wide commands
    @command_generate(0x00, "Read Attributes", profile_wide=True)
    def read_attributes(self, *attributes):
        command = ZCLGeneralReadAttributes(attribute_identifiers=list(attributes))
        self.send_command(command)
        attributes = self.wait_response()
        return attributes

    @command_receive(0x01, "Read Attributes Response", profile_wide=True)
    def on_read_attributes_response(self, command):
        attributes = []
        for attribute in command.read_attribute_status_record:
            attributes.append((attribute.attribute_identifier, attribute.status, attribute.attribute_value if attribute.status == 0 else None))
        return attributes

    @command_generate(0x0c, "Discover Attributes", profile_wide=True)
    def discover_attributes(self, start_identifier=0, max_reports=0xFFFF):
        attributes = []
        command = ZCLGeneralDiscoverAttributes(start_attribute_identifier=start_identifier, max_attribute_identifiers=max_reports)
        self.send_command(command)
        return self.wait_response()

    @command_receive(0x0d, "Discover Attributes Response", profile_wide=True)
    def on_discover_attributes(self, command):
        attributes = []
        for attribute in command.attribute_records:
            attributes.append((attribute.attribute_identifier, attribute.attribute_data_type))
        return (0 == command.discovery_complete, attributes)

class ZCLClientCluster(ZCLCluster):
    def __init__(self, cluster_id, default_configuration=ZCLClusterConfiguration()):
        super().__init__(cluster_id, ZCLClusterType.CLIENT)

class ZCLServerCluster(ZCLCluster):
    def __init__(self, cluster_id, default_configuration=ZCLClusterConfiguration()):
        super().__init__(cluster_id, ZCLClusterType.SERVER)

'''
class ZCLCluster(Cluster):
    zcl_transaction_counter = 1

    def __init__(self, cluster_id):
        super().__init__(cluster_id)
        self.attributes = ZCLAttributes()
        self.commands = ZCLCommands()
        self.register_attributes()
        self.register_commands()

    def register_attributes(self):
        pass

    def register_commands(self):
        pass

    def send_command(self, command_identifier, command, destination_address_mode, destination_address, destination_endpoint, transaction=None, alias_address=None, alias_sequence_number=0, radius=30, security_enabled_transmission=False, use_network_key=True, acknowledged_transmission=False, fragmentation_permitted=False, include_extended_nonce=False, disable_default_response=False):
        if transaction is None:
            transaction = ZCLCluster.zcl_transaction_counter
            ZCLCluster.zcl_transaction_counter += 1

        asdu = ZigbeeClusterLibrary(
                zcl_frametype=1,
                command_direction=0,
                command_identifier=command_identifier,
                transaction_sequence=transaction,
                disable_default_response=disable_default_response
        ) / command

        return self.send_data(asdu, destination_address_mode, destination_address, destination_endpoint, alias_address=alias_address, alias_sequence_number=alias_sequence_number, radius=radius, security_enabled_transmission=security_enabled_transmission, use_network_key=use_network_key, acknowledged_transmission=acknowledged_transmission, fragmentation_permitted=fragmentation_permitted, include_extended_nonce=include_extended_nonce)

    def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
        command_identifier = asdu.command_identifier

        try:
            command = self.commands.get_command(command_identifier)
            command.receive_callback(asdu[ZigbeeClusterLibrary].payload, transaction=asdu.transaction_sequence, no_response=asdu.disable_default_response)

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))
'''
