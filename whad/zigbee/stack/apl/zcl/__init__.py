from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.zcl.attributes import ZCLAttributes
from whad.zigbee.stack.apl.zcl.commands import ZCLCommands
from scapy.layers.zigbee import ZigbeeClusterLibrary
import logging

logger = logging.getLogger(__name__)

class ZCLClusterMetaclass(type):

    def __init__(cls, name, bases, attrs):
        commands = {}
        if name != "ZCLCluster":
            print(cls.__annotations__)
            for key, val in attrs.items():
                receive_property = getattr(val, "_command_receive", None)
                generate_property = getattr(val, "_command_generate", None)
                if receive_property is not None:
                    command_id, command_name = receive_property
                    if command_id in commands:
                        commands[command_id]["name"] = command_name
                        commands[command_id]["receive_callback"] = key
                    else:
                        commands[command_id] = {"name":command_name, "receive_callback": key, "generate_callback":None}

                if generate_property is not None:
                    command_id, command_name = generate_property
                    if command_id in commands:
                        commands[command_id]["name"] = command_name
                        commands[command_id]["generate_callback"] = key
                    else:
                        commands[command_id] = {"name":command_name, "receive_callback": None, "generate_callback": key}
            print(bases, attrs)
        '''
        zcl_commands = ZCLCommands()
        for command_id, command in commands.items():
            zcl_commands.add_command(command_id, command["name"], generate_callback=getattr(instance, command["generate_callback"]), receive_callback=getattr(instance, command["receive_callback"]))
        print(attrs)
        '''

class ZCLCluster(Cluster, metaclass=ZCLClusterMetaclass):
    def __init__(self, cluster_id):
        super().__init__(cluster_id)
        self.attributes = ZCLAttributes()
        self.commands = ZCLCommands()


    def command_receive(command_id, command_name):
        def receive_decorator(f):
            f._command_receive = (command_id, command_name)
            return f
        return receive_decorator

    def command_generate(command_id, command_name):
        def generate_decorator(f):
            f._command_generate = (command_id, command_name)
            return f
        return generate_decorator

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
