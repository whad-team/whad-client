from scapy.layers.zigbee import ZigbeeDeviceProfile, ZigbeeAppDataPayloadStub, ZigbeeClusterLibrary, \
    _aps_profile_identifiers, _zcl_attribute_data_types, _zcl_enumerated_status_values, _DiscreteString, \
    _zcl_cluster_identifier, ZigbeeNWKStub
from scapy.fields import BitEnumField, BitField, ByteEnumField, ByteField, ConditionalField, \
    FlagsField, XBitField, XLEIntField, XLEShortField, EnumField, XShortField, PacketListField, \
    StrFixedLenField
from scapy.layers.dot15d4 import dot15d4AddressField
from scapy.packet import Packet, bind_layers

class ZigbeeZLLCommissioningCluster(Packet):
    name = "Zigbee LightLink Commissioning Cluster Frame"
    fields_desc = [
        # Frame control (8 bits)
        BitField("reserved", 0, 3),
        BitField("disable_default_response", 1, 1), # 1 not default response command will be returned
        BitEnumField("direction", 0, 1, ['client2server', 'server2client']),
        BitField("manufacturer_specific", 0, 1), # 0 manufacturer code shall not be included in the ZCL frame
        # Frame Type
        # 0b00 command acts across the entire profile
        # 0b01 command is specific to a cluster
        # 0b10 - 0b11 reserved
        BitField("zcl_frametype", 1, 2),
        # Manufacturer code (0/16 bits) only present then manufacturer_specific field is set to 1
        ConditionalField(XLEShortField("manufacturer_code", 0x0),
            lambda pkt:pkt.getfieldval("manufacturer_specific") == 1
        ),
        # Transaction sequence number (8 bits)
        ByteField("transaction_sequence", 0),
        # Command identifier (8 bits): the cluster command
        ByteEnumField("command_identifier", 0x00, {}),
    ]

class ZLLScanRequest(Packet):
    name = "ZLL: Scan Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666), # Unsigned 32-bit Integer (4 octets)
	# ZigBee information (1 octet)
        BitField("reserved", 0, 5),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        #FlagsField("ZLL information", 0, 8, [ 'factory_new', 'address_assignment', 'reserved1', 'reserved2', 'link_initiator', 'undefined', 'reserved3', 'reserved4' ]),
        BitField("reserved1", 0, 2),
        BitField("undefined", 0, 1),
        BitEnumField("link_initiator", 0, 1, [False, True]),
        BitField("reserved2", 0, 2),
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
    ]
    def answers(self, other):
        if isinstance(other, ZLLScanResponse):
            return self.inter_pan_transaction_id == other.inter_pan_transaction_id
        return 0

class ZLLScanResponse(Packet):
    name = "ZLL: Scan Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        ByteField("rssi_correction", 0x00), # range 0x00 - 0x20 (1 octet)
	# ZigBee information (1 octet)
        # HiddenField(BitField("reserved", 0, 5)),
        BitField("reserved", 0, 5),
        BitEnumField("rx_on_when_idle", 1, 1, [False, True]),
        BitEnumField("logical_type", 1, 2, {
            0:"coordinator", 1:"router", 2:"end device", 3:"reserved"}
        ),
	# ZLL information (1 octet)
        # HiddenField(BitField("reserved1", 0, 2)),
        BitField("reserved1", 0, 2),
        BitEnumField("touchlink_priority_request", 0, 1, [False, True]),
        BitEnumField("touchlink_initiator", 0, 1, [False, True]),
        # HiddenField(BitField("reserved2", 0, 2)),
        BitField("reserved2", 0, 2),
        BitEnumField("address_assignment", 0, 1, [False, True]),
        BitEnumField("factory_new", 0, 1, [False, True]),
        # Key bitmask (2 octets)
        FlagsField("key_bitmask", 0, 16, ["reserved_key_8", "reserved_key_9",
            "reserved_key_10", "reserved_key_11", "reserved_key_12",
            "reserved_key_13", "reserved_key_14", "certification_key",
            "development_key", "reserved_key_1", "reserved_key_2", "reserved_key_3",
            "master_key", "reserved_key_5", "reserved_key_6",
            "reserved_key_7"]),
        # BitField("reserved3", 0, 3),
        # BitEnumField("master_key", 0, 1, [False, True]),
        # BitField("reserved4", 0, 3),
        # BitEnumField("development_key", 0, 1, [False, True]),
        # BitEnumField("certification_key", 0, 1, [False, True]),
        # BitField("reserved5", 0, 3),
        # BitField("reserved6", 0, 4),

        # Response identifier (4 octets)
        XLEIntField("response_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
        # Number of sub-devices (1 octet)
        ByteField("number_of_sub_devices", 1),
        # Total group identifiers (1 octet)
        ByteField("number_of_group_ids", 0),
        # Endpoint identifier (0/1 octets)
        ConditionalField(ByteField("endpoint_id", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Profile identifier (0/2 octets)
        #ConditionalField(XShortField("profile_id", 0x0000)
        ConditionalField(EnumField("profile_id", 0, _aps_profile_identifiers, fmt = "<H"), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Device identifier (0/2 octets)
        ConditionalField(XShortField("device_id", 0x0000), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Version (0/1 octets)
        # HiddenField(ConditionalField(BitField("0x0", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1))),
        ConditionalField(BitField("unknown", 0, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        ConditionalField(BitField("application_device_version", 2, 4), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
        # Group identifier count (0/1 octets)
        ConditionalField(ByteField("group_id_count", 0x00), lambda pkt:(pkt.getfieldval("number_of_sub_devices") == 1)),
    ]

class ZLLDeviceInformationRequest(Packet):
    name = "ZLL: Device Information Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
       # Start index of device table (1 octet)
        ByteField("start_index", 0),
    ]

class ZLLDeviceInformationRecord(Packet):
    name = "ZLL: Device Information Record"
    fields_desc = [
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("ieee_address", 0, adjust=lambda pkt,x: 8),
        # Endpoint identifier (1 octet)
        ByteField("endpoint_id", 0x00),
        # Profile identifier (2 octets)
        XLEShortField("profile_id", 0x0000),
        # Device identifier (2 octets)
        XLEShortField("device_id", 0x0000),
        # Version (1 octet)
        ByteField("version", 0),
        # Group identifier count (1 octet)
        ByteField("group_identifier_count", 0),
        # Sort (1 octet)
        ByteField("sort", 0),

    ]

class ZLLDeviceInformationResponse(Packet):
    name = "ZLL: Device Information Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Number of sub devices (1 octet)
        ByteField("number_of_sub_devices", 0),
        # Start index of device table (1 octet)
        ByteField("start_index", 0),
        # Device information record count (1 octet)
        ByteField("device_information_record_count", 0),
        # Device Information record (variable)
        PacketListField("device_information_record", [], ZLLDeviceInformationRecord)
    ]


class ZLLIdentifyRequest(Packet):
    name = "ZLL: Identify Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Identify duration (1 octet):
        #   0x0000: Exit identify mode
        #   0x0001 - 0xfffe: Number of seconds to remain in identify mode
        #   0xffff: Remain in identify mode for a default time known by the receiver
        XLEShortField("identify_duration", 0xffff),
    ]

class ZLLResetToFactoryNewRequest(Packet):
    name = "ZLL: Reset to Factory New Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
    ]

class ZLLNetworkStartRequest(Packet):
    name = "ZLL: Network Start Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        StrFixedLenField("encrypted_network_key", None, length=16),#XBitField("encrypted_network_key", 0, 128),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
        # Initiator IEEE address (8 octet)
        XBitField("initiator_ieee_address", 0, 64),
        # Initiator network address (2 octets)
        XLEShortField("initiator_network_address", 0),
    ]

class ZLLNetworkStartResponse(Packet):
    name = "ZLL: Network Start Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
    ]

class ZLLNetworkJoinRouterRequest(Packet):
    name = "ZLL: Network Join Router Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Key index (1 octets)
        ByteField("key_index", 4),  # default: Master key
        # Encrypted network key (16 octets)
        StrFixedLenField("encrypted_network_key", None, length=16),#XBitField("encrypted_network_key", 0, 128),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical channel (1 octet)
        ByteField("channel", 0),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0x0001),
        # Group identifiers begin (2 octets)
        XLEShortField("group_id_begin", 0),
        # Group identifiers end (2 octets)
        XLEShortField("group_id_end", 0),
        # Free network address range begin (2 octets)
        XLEShortField("free_network_address_range_begin", 0),
        # Free network address range end (2 octets)
        XLEShortField("free_network_address_range_end", 0),
        # Free group address range begin (2 octets)
        XLEShortField("free_group_address_range_begin", 0),
        # Free group address range end (2 octets)
        XLEShortField("free_group_address_range_end", 0),
    ]

class ZLLNetworkJoinRouterResponse(Packet):
    name = "ZLL: Network Join Router Response"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Status (1 octet)
        ByteEnumField("status", 0, {0: "success", 1: "failure",
            2: "reserved_status_2", 3: "reserved_status_3",
            4: "reserved_status_4", 5: "reserved_status_5",
            6: "reserved_status_6", 7: "reserved_status_7",
            8: "reserved_status_8", 9: "reserved_status_9",
            10: "reserved_status_10", 11: "reserved_status_11",
            12: "reserved_status_12", 13: "reserved_status_13",
            14: "reserved_status_14", 15: "reserved_status_15"}),
    ]

class ZLLNetworkUpdateRequest(Packet):
    name = "ZLL: Network Update Request"
    fields_desc = [
        # Inter-PAN transaction identifier (4 octets)
        XLEIntField("inter_pan_transaction_id", 0x66666666),
        # Extended PAN identifier (8 octets)
        dot15d4AddressField("pan_id_ext", 0, adjust=lambda pkt,x: 8),
        # Network update identifier (1 octet)
        ByteField("network_update_id", 0x00),
        # Logical Channel (1 octet)
        ByteField("channel", 11),
        # PAN identifier (2 octets)
        XLEShortField("pan_id", 0x0000),
        # Network address (2 octets)
        XLEShortField("network_address", 0xffff),
    ]

def nwk_stub_guess_payload_class(self, payload):
    if self.frametype == 0b11:
        return NewZigbeeAppDataPayloadStub
    else:
        return Packet.guess_payload_class(self, payload)

ZigbeeNWKStub.guess_payload_class = nwk_stub_guess_payload_class

class NewZigbeeAppDataPayloadStub(Packet):
    name = "Zigbee Application Layer Data Payload for Inter-PAN Transmission"
    fields_desc = [
        FlagsField("frame_control", 0, 4, [ 'reserved1', 'security', 'ack_req', 'extended_hdr' ]),
        BitEnumField("delivery_mode", 0, 2, {0:'unicast', 2:'broadcast', 3:'group'}),
        BitField("frametype", 3, 2), # value 0b11 (3) is a reserved frame type
        # Group Address present only when delivery mode field has a value of 0b11 (group delivery mode)
        ConditionalField(
            XLEShortField("group_addr", 0x0), # 16-bit identifier of the group
            lambda pkt:pkt.getfieldval("delivery_mode") == 0b11
        ),
        # Cluster identifier
        EnumField("cluster", 0, _zcl_cluster_identifier, fmt = "<H"), # unsigned short (little-endian)
        # Profile identifier
        EnumField("profile", 0, _aps_profile_identifiers, fmt = "<H"),
        # ZigBee Payload
#        ConditionalField(
#            ZigbeePayloadField("data", "", length_from=lambda pkt, s:len(s)),
#            lambda pkt:pkt.frametype == 3
#        ),
    ]
    def guess_payload_class(self, payload):
        if self.frametype == 3 and self.profile == 0xc05e and self.cluster == 0x1000:
            return ZigbeeZLLCommissioningCluster
        else:
            return Packet.guess_payload_class(self, payload)


class ZCLWriteAttributeRecord(Packet):
    name = "ZCL Write Attribute Record"
    fields_desc = [
        # Attribute Identifier (2 octets)
        XLEShortField("attribute_identifier", 0),
        # Attribute Data Type (1 octet)
        ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
        # Attribute Data (variable)
        _DiscreteString("attribute_data", ""),
    ]

    def extract_padding(self, s):
        return "", s

class ZCLGeneralWriteAttributesUndivided(Packet):
    name = "General Domain: Command Frame Payload: write_attributes_undivided"
    fields_desc = [
        PacketListField("write_records", [], ZCLWriteAttributeRecord),
    ]

class ZCLGeneralWriteAttributesNoResponse(Packet):
    name = "General Domain: Command Frame Payload: write_attributes_no_response"
    fields_desc = [
        PacketListField("write_records", [], ZCLWriteAttributeRecord),
    ]



class ZCLConfigureReportingConfigurationRecord(Packet):
    name = "ZCL Configure Reporting Configuration Record"
    fields_desc = [
        # Direction (0/1 octet)
        ByteField("attribute_direction", 0),
        XLEShortField("attribute_identifier", 0)
    ]

    def extract_padding(self, s):
        return "", s


class ZCLGeneralReadReportingConfiguration(Packet):
    name = "General Domain: Command Frame Payload: read_reporting_configuration"
    fields_desc = [
        PacketListField("write_records", [], ZCLConfigureReportingConfigurationRecord),
    ]


class ZCLConfigureReportingConfigurationResponseRecord(Packet):
    name = "ZCL Reporting Configuration Response Record"
    fields_desc = [
        # Status (1 octet)
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
        # Direction (0/1 octet)
        ConditionalField(
            ByteField("attribute_direction", 0),
            lambda pkt:pkt.status != 0x00
        ),
        # Attribute Identifier (0/2 octets)
        ConditionalField(
            XLEShortField("attribute_identifier", 0),
            lambda pkt:pkt.status != 0x00
        ),
        # Attribute Data Type (0/1 octets)
        ConditionalField(
            ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types),
            lambda pkt:pkt.status != 0x00
        ),
        # Minimum Reporting Interval (0/2 octets)
        ConditionalField(
            XLEShortField("min_reporting_interval", 0),
            lambda pkt:pkt.status != 0x00
        ),
        # Maximum Reporting Interval (0/2 octets)
        ConditionalField(
            XLEShortField("max_reporting_interval", 0),
            lambda pkt:pkt.status != 0x00
        ),
        # Reportable Change (variable)
        ConditionalField(
            _DiscreteString("reportable_change", ""),
            lambda pkt:pkt.status != 0x00
        ),
        # Timeout Period (0/2 octets)
        ConditionalField(
            XLEShortField("timeout_period", 0),
            lambda pkt:pkt.status != 0x00
        ),
    ]

    def extract_padding(self, s):
        return "", s

class ZCLGeneralReadReportingConfigurationResponse(Packet):
    name = "General Domain: Command Frame Payload: read_reporting_configuration_response"
    fields_desc = [
        PacketListField("write_records", [], ZCLConfigureReportingConfigurationResponseRecord),
    ]


class ZCLGeneralDiscoverAttributes(Packet):
    name = "General Domain: Command Frame Payload: discover_attributes"
    fields_desc = [
        XLEShortField("start_attribute_identifier", 0),
        XLEShortField("max_attribute_identifiers", 0)
    ]


class ZCLDiscoverAttributesRecord(Packet):
    name = "ZCL Discover Attributes Record"
    fields_desc = [
        # Attribute Identifier
        XLEShortField("attribute_identifier", 0),
        ByteEnumField("attribute_data_type", 0, _zcl_attribute_data_types)
    ]

    def extract_padding(self, s):
        return "", s

class ZCLGeneralDiscoverAttributesResponse(Packet):
    name = "General Domain: Command Frame Payload: discover_attributes_response"
    fields_desc = [
        ByteEnumField("discovery_complete", 0, {0: "complete", 1:"incomplete", 0xFF:"invalid"}),
        PacketListField("attribute_records", [], ZCLDiscoverAttributesRecord),
    ]

class ZCLGeneralDefaultResponse(Packet):
    name = "General Domain: Command Frame Payload: default_response"
    fields_desc = [
        ByteField("response_to_command", None),
        ByteEnumField("status", 0, _zcl_enumerated_status_values),
    ]

bind_layers(ZigbeeClusterLibrary, ZCLGeneralWriteAttributesUndivided, zcl_frametype=0x00, command_identifier=0x03)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralWriteAttributesNoResponse, zcl_frametype=0x00, command_identifier=0x05)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadReportingConfiguration, zcl_frametype=0x00, command_identifier=0x08)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralReadReportingConfigurationResponse, zcl_frametype=0x00, command_identifier=0x09)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralDiscoverAttributes, zcl_frametype=0x00, command_identifier=0x0c)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralDiscoverAttributesResponse, zcl_frametype=0x00, command_identifier=0x0d)
bind_layers(ZigbeeClusterLibrary, ZCLGeneralDefaultResponse, zcl_frametype=0x00, command_identifier=0x0b)


bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanRequest,
        command_identifier=0x00, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLScanResponse,
        command_identifier=0x01, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLDeviceInformationRequest,
        command_identifier=0x03, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLDeviceInformationResponse,
        command_identifier=0x03, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLIdentifyRequest,
        command_identifier=0x06, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLResetToFactoryNewRequest,
        command_identifier=0x07, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartRequest,
        command_identifier=0x10, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkStartResponse,
        command_identifier=0x11, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterRequest,
        command_identifier=0x12, direction=0)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkJoinRouterResponse,
        command_identifier=0x13, direction=1)
bind_layers( ZigbeeZLLCommissioningCluster, ZLLNetworkUpdateRequest,
        command_identifier=0x16, direction=0)
