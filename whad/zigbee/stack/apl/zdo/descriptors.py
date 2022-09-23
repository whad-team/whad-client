from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.mac.constants import MACDeviceType, MACPowerSource

class NodeDescriptor:
    def __init__(self):
        self.logical_type = LogicalDeviceType.END_DEVICE
        self.complex_descriptor_available = False
        self.user_descriptor_available = False
        self.aps_flags = 0
        self.support_868_mhz = False
        self.support_902_mhz = False
        self.support_2400_mhz = True
        self.alternate_pan_coordinator = False
        self.device_type = MACDeviceType.FFD
        self.power_source = MACPowerSource.ALTERNATING_CURRENT_SOURCE
        self.receiver_on_when_idle = True
        self.security_capability = True
        self.allocate_address = False
        self.manufacturer_code = 0x1234
        self.max_buffer_size = 128
        self.max_incoming_transfer_size = 128
        self.server_primary_trust_center = False
        self.server_backup_trust_center = False
        self.server_primary_binding_table_cache = False
        self.server_backup_binding_table_cache = False
        self.server_primary_discovery_cache = False
        self.server_backup_discovery_cache = False
        self.network_manager = False
        self.stack_compliance_revision = 21
        self.max_outgoing_transfer_size = 128
        self.extended_active_endpoint_list_available = False
        self.extended_simple_descriptors_list_available = False
