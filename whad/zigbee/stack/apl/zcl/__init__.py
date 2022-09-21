from whad.zigbee.stack.apl.cluster import Cluster
from scapy.layers.zigbee import ZigbeeClusterLibrary
import logging

logger = logging.getLogger(__name__)

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
