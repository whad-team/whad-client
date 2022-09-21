from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.cluster import Cluster
from whad.scapy.layers.zll import ZigbeeZLLCommissioningCluster, ZLLScanRequest
from whad.zigbee.stack.apl.exceptions import ZCLAttributePermissionDenied, \
    ZCLAttributeNotFound, ZCLCommandNotFound
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.mac.constants import MACAddressMode
from scapy.layers.zigbee import ZigbeeClusterLibrary
from dataclasses import dataclass
import logging
from random import randint

logger = logging.getLogger(__name__)

@dataclass
class ZCLAttribute:
    name : str = None
    value = None
    permissions = ["read", "write"]

class ZCLAttributes:
    def __init__(self):
        self.attributes = {}

    def add_attribute(self, id, name, value, permissions=['read', 'write']):
        self.attributes[id] = ZCLAttribute(name=name, value=value, permissions=permissions)

    def read_by_id(self, id):
        if id in self.attributes:
            attribute = self.attributes[id]
            if "read" in attribute.permissions:
                return attribute.value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def read_by_name(self, name):
        for attribute in self.attributes:
            if attribute.name == name:
                if "read" in attribute.permissions:
                    return attribute.value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_id(self, id, value):
        if id in self.attributes:
            attribute = self.attributes[id]
            if "write" in attribute.permissions:
                attribute.value = value
            raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()

    def write_by_name(self, name, value):
        for attribute in self.attributes:
            if attribute.name == name:
                if "write" in attribute.permissions:
                    attribute.value = value
                else:
                    raise ZCLAttributePermissionDenied()
        raise ZCLAttributeNotFound()


class ZCLCommand:
    def __init__(self, name, generate_callback=None, receive_callback=None):
        self.name = name
        self.generate_callback = generate_callback
        self.receive_callback = receive_callback

class ZCLCommands:
    def __init__(self):
        self.commands = {}

    def add_command(self, id, name, generate_callback=None, receive_callback=None):
        self.commands[id] = ZCLCommand(name, generate_callback, receive_callback)

    def get_command(self, id):
        if id in self.commands:
            return self.commands[id]
        raise ZCLCommandNotFound()

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

class ZCLOnOff(ZCLCluster):
    def __init__(self):
        super().__init__(cluster_id=0x0006)

    def register_commands(self):
        self.commands.add_command(0x00, "Off", generate_callback=self.off, receive_callback=None)
        self.commands.add_command(0x01, "On", generate_callback=self.on, receive_callback=None)
        self.commands.add_command(0x02, "Toggle", generate_callback=self.toggle, receive_callback=None)

    def on(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x01, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    def off(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x00, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)

    def toggle(self, destination_address, destination_endpoint, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, transaction=None):
        return self.send_command(0x02, b"", destination_address_mode, destination_address, destination_endpoint, transaction=transaction)


class ZCLTouchLink(ZCLCluster):
    def __init__(self):
        super().__init__(cluster_id=0x1000)

    def register_commands(self):
        self.commands.add_command(0x00, "ScanRequest", generate_callback=self.scan_request, receive_callback=None)
        self.commands.add_command(0x01, "ScanResponse", generate_callback=None, receive_callback=self.on_scan_response)

    def scan_request(self, transaction_id=randint(0, 0xFFFFFFFF), link_initiator=True, address_assignment=True, factory_new=True):
        node_descriptor = self.application.manager.get_application_by_name("zdo").configuration.get("configNodeDescriptor")

        command = ZLLScanRequest(
            inter_pan_transaction_id=transaction_id,
            rx_on_when_idle=int(node_descriptor.receiver_on_when_idle),
            logical_type=int(node_descriptor.logical_type),
            link_initiator=link_initiator,
            address_assignment=address_assignment,
            factory_new=factory_new
        )

        return self.send_command(0x00, command)

    def on_scan_response(self, payload, transaction=None, no_response=True):
        payload.show()

    def send_command(self, command_identifier, command, transaction=None,  disable_default_response=True):
        if transaction is None:
            transaction = ZCLCluster.zcl_transaction_counter
            ZCLCluster.zcl_transaction_counter += 1

        asdu = ZigbeeZLLCommissioningCluster(
                zcl_frametype=1,
                direction=0,
                command_identifier=command_identifier,
                transaction_sequence=transaction,
                disable_default_response=disable_default_response
        ) / command

        return self.send_interpan_data(asdu, asdu_handle=0, source_address_mode=MACAddressMode.EXTENDED, destination_pan_id=0xFFFF, destination_address=0xFFFF)

    def on_interpan_data(self, asdu,destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        command_identifier = asdu.command_identifier

        try:
            command = self.commands.get_command(command_identifier)
            command.receive_callback(asdu[ZigbeeZLLCommissioningCluster].payload, transaction=asdu.transaction_sequence, no_response=asdu.disable_default_response)

        except ZCLCommandNotFound:
            logger.info("[zcl] command not found (command_identifier = 0x{:02x})".format(command_identifier))
