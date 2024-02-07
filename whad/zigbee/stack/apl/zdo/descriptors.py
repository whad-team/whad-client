from whad.dot15d4.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.apl.constants import LogicalDeviceType

class NodeDescriptor:
    """
    This class is a descriptor for a ZigBee Node.
    """
    def __init__(
                    self,
                    logical_type=LogicalDeviceType.END_DEVICE,
                    complex_descriptor_available=False,
                    user_descriptor_available=False,
                    aps_flags=0,
                    support_868_mhz=False,
                    support_902_mhz=False,
                    support_2400_mhz=True,
                    alternate_pan_coordinator=False,
                    device_type=MACDeviceType.FFD,
                    power_source=MACPowerSource.ALTERNATING_CURRENT_SOURCE,
                    receiver_on_when_idle=True,
                    security_capability=True,
                    allocate_address=False,
                    manufacturer_code=0x1234,
                    max_buffer_size=128,
                    max_incoming_transfer_size=128,
                    server_primary_trust_center = False,
                    server_backup_trust_center = False,
                    server_primary_binding_table_cache = False,
                    server_backup_binding_table_cache = False,
                    server_primary_discovery_cache = False,
                    server_backup_discovery_cache = False,
                    network_manager = False,
                    stack_compliance_revision = 21,
                    max_outgoing_transfer_size = 128,
                    extended_active_endpoint_list_available = False,
                    extended_simple_descriptors_list_available = False
        ):
        self.logical_type = logical_type
        self.complex_descriptor_available = complex_descriptor_available
        self.user_descriptor_available = user_descriptor_available
        self.aps_flags = aps_flags
        self.support_868_mhz = support_868_mhz
        self.support_902_mhz = support_902_mhz
        self.support_2400_mhz = support_2400_mhz
        self.alternate_pan_coordinator = alternate_pan_coordinator
        self.device_type = device_type
        self.power_source = power_source
        self.receiver_on_when_idle = receiver_on_when_idle
        self.security_capability = security_capability
        self.allocate_address = allocate_address
        self.manufacturer_code = manufacturer_code
        self.max_buffer_size = max_buffer_size
        self.max_incoming_transfer_size = max_incoming_transfer_size
        self.server_primary_trust_center = server_primary_trust_center
        self.server_backup_trust_center = server_backup_trust_center
        self.server_primary_binding_table_cache = server_primary_binding_table_cache
        self.server_backup_binding_table_cache = server_backup_binding_table_cache
        self.server_primary_discovery_cache = server_primary_discovery_cache
        self.server_backup_discovery_cache = server_backup_discovery_cache
        self.network_manager = network_manager
        self.stack_compliance_revision = stack_compliance_revision
        self.max_outgoing_transfer_size = max_outgoing_transfer_size
        self.extended_active_endpoint_list_available = extended_active_endpoint_list_available
        self.extended_simple_descriptors_list_available = extended_simple_descriptors_list_available

    def __repr__(self):
        return ("NodeDescriptor(" +
            "logical_type="+str(self.logical_type)+","+
            "complex_descriptor_available="+str(self.complex_descriptor_available)+","+
            "user_descriptor_available="+str(self.user_descriptor_available)+","+
            "aps_flags="+str(self.aps_flags)+","+
            "support_868_mhz="+str(self.support_868_mhz)+","+
            "support_902_mhz="+str(self.support_902_mhz)+","+
            "support_2400_mhz="+str(self.support_2400_mhz)+","+
            "alternate_pan_coordinator="+str(self.alternate_pan_coordinator)+","+
            "device_type="+str(self.device_type)+","+
            "power_source="+str(self.power_source)+","+
            "receiver_on_when_idle="+str(self.receiver_on_when_idle)+","+
            "security_capability="+str(self.security_capability)+","+
            "allocate_address="+str(self.allocate_address)+","+
            "manufacturer_code="+str(self.manufacturer_code)+","+
            "max_buffer_size="+str(self.max_buffer_size)+","+
            "max_incoming_transfer_size="+str(self.max_incoming_transfer_size)+","+
            "server_primary_trust_center="+str(self.server_primary_trust_center)+","+
            "server_backup_trust_center="+str(self.server_backup_trust_center)+","+
            "server_primary_binding_table_cache="+str(self.server_primary_binding_table_cache)+","+
            "server_backup_binding_table_cache="+str(self.server_backup_binding_table_cache)+","+
            "server_primary_discovery_cache="+str(self.server_primary_discovery_cache)+","+
            "server_backup_discovery_cache="+str(self.server_backup_discovery_cache)+","+
            "network_manager="+str(self.network_manager)+","+
            "stack_compliance_revision="+str(self.stack_compliance_revision)+","+
            "max_outgoing_transfer_size="+str(self.max_outgoing_transfer_size)+","+
            "extended_active_endpoint_list_available="+str(self.extended_active_endpoint_list_available)+","+
            "extended_simple_descriptors_list_available="+str(self.extended_simple_descriptors_list_available)+","+
        ")")

class SimpleDescriptor:
    """
    This class is a descriptor for an application.
    """
    def __init__(
                    self,
                    endpoint,
                    profile_identifier,
                    device_identifier,
                    device_version,
                    input_clusters,
                    output_clusters
    ):
        self.endpoint = endpoint
        self.profile_identifier = profile_identifier
        self.device_identifier = device_identifier
        self.device_version = device_version
        self.input_clusters = input_clusters
        self.output_clusters = output_clusters

    def __repr__(self):
        return (
            "SimpleDescriptor(" +
            "endpoint="+str(self.endpoint)+"," +
            "profile_identifier="+hex(self.profile_identifier)+"," +
            "device_identifier="+hex(self.device_identifier)+"," +
            "device_version="+hex(self.device_version)+"," +
            "input_clusters="+str(self.input_clusters)+"," +
            "output_clusters="+str(self.output_clusters) +
            ")"
        )
