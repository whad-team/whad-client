from scapy.layers.zigbee import ZigbeeDeviceProfile
from scapy.fields import BitField, XLEShortField, ByteEnumField, \
    XLEShortField, ByteField, ConditionalField, FieldListField, \
    FieldLenField
from scapy.layers.dot15d4 import dot15d4AddressField
from scapy.packet import Packet

class ZDPActiveEPReq(Packet):
    name = "ZDP Transaction Data: Active_EP_req"
    fields_desc = [
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
    ]

class ZDPActiveEPRsp(Packet):
    name = "ZDP Transaction Data: Active_EP_rsp"
    fields_desc = [
        ByteEnumField("status", 0, {0:"success", 1:"device_not_found", 2:"inv_requesttype", 3:"no_descriptor"}),
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
        ConditionalField(FieldLenField("num_active_endpoints", None, length_of="endpoints", fmt="B"),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            FieldListField("active_endpoints",[],ByteField("", 0), length_from=lambda p:p.num_active_endpoints),
            lambda pkt:pkt.getfieldval("status") == 0
        ),

    ]

class ZDPDeviceAnnce(Packet):
    name = "ZDP Transaction Data: Device_annce"
    fields_desc = [
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
        # IEEE Address (8 octets)
        dot15d4AddressField("ieee_addr", 0, adjust=lambda pkt, x: 8),
        # Capability Information (1 octet)
        BitField("allocate_address", 0, 1),
        BitField("security_capability", 0, 1),
        BitField("reserved2", 0, 1),
        BitField("reserved1", 0, 1),
        BitField("receiver_on_when_idle", 0, 1),
        BitField("power_source", 0, 1),
        BitField("device_type", 0, 1),
        BitField("alternate_pan_coordinator", 0, 1),
    ]

class ZDPNodeDescReq(Packet):
    name = "ZDP Transaction Data: Node_desc_req"
    fields_desc = [
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
    ]


class ZDPNodeDescRsp(Packet):
    name = "ZDP Transaction Data: Node_desc_rsp"
    fields_desc = [
        ByteEnumField("status", 0, {0:"success", 1:"device_not_found", 2:"inv_requesttype", 3:"no_descriptor"}),
        # NWK Address (2 octets)
        XLEShortField("nwk_addr", 0),
        ConditionalField(
            BitField("reserved0", 0, 3),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("user_descriptor_available", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("complex_descriptor_available", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("logical_type", 0, 3),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved1bis", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("support_2400_mhz", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("support_902_mhz", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved1", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("support_868_mhz", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("aps_flags", 0, 3),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("allocate_address", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("security_capability", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved2", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved3", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("receiver_on_when_idle", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("power_source", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("device_type", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("alternate_pan_coordinator", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            XLEShortField("manufacturer_code", None),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            ByteField("max_buffer_size", None),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            XLEShortField("max_incoming_transfer_size", None),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_primary_trust_center", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_backup_trust_center", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_primary_binding_table_cache", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_backup_binding_table_cache", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_primary_discovery_cache", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("server_backup_discovery_cache", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("network_manager", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved4", 0, 2),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("stack_compliance_revision", 0, 7),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            XLEShortField("max_outgoing_transfer_size", None),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("extended_active_endpoint_list_available", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("extended_simple_descriptors_list_available", 0, 1),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            BitField("reserved5", 0, 6),
            lambda pkt:pkt.getfieldval("status") == 0
        )
    ]

class ZDPNWKAddrReq(Packet):
    name = "ZDP Transaction Data: NWK_addr_req"
    fields_desc = [
        # IEEE Address (8 octets)
        dot15d4AddressField("ieee_addr", 0, adjust=lambda pkt, x: 8),
        ByteEnumField("request_type", 0, {0:"single_device_response", 1:"extended_response"}),
        ByteField("start_index", 0)
    ]

class ZDPNWKAddrRsp(Packet):
    name = "ZDP Transaction Data: NWK_addr_rsp"
    fields_desc = [
        ByteEnumField("status", 0, {0:"success", 1:"device_not_found", 2:"inv_requesttype", 3:"no_descriptor"}),
        dot15d4AddressField("ieee_addr", 0, adjust=lambda pkt, x: 8),
        XLEShortField("nwk_addr", 0),
        ConditionalField(
            FieldLenField("num_assoc_dev", None, length_of="associated_devices"),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(ByteField("start_index", 0x0),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            FieldListField("associated_devices",[],XLEShortField("", 0), length_from=lambda p:p.num_assoc_dev),
            lambda pkt:pkt.getfieldval("status") == 0
        ),

    ]

class ZDPIEEEAddrReq(Packet):
    name = "ZDP Transaction Data: IEEE_addr_req"
    fields_desc = [
        # IEEE Address (8 octets)
        XLEShortField("nwk_addr", 0),
        ByteEnumField("request_type", 0, {0:"single_device_response", 1:"extended_response"}),
        ByteField("start_index", 0)
    ]

class ZDPIEEEAddrRsp(Packet):
    name = "ZDP Transaction Data: IEEE_addr_rsp"
    fields_desc = [
        ByteEnumField("status", 0, {0:"success", 1:"device_not_found", 2:"inv_requesttype", 3:"no_descriptor"}),
        dot15d4AddressField("ieee_addr", 0, adjust=lambda pkt, x: 8),
        XLEShortField("nwk_addr", 0),
        ConditionalField(ByteField("num_assoc_dev", None),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(ByteField("start_index", 0x0),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            FieldListField("associated_devices",[],XLEShortField("", 0), length_from=lambda p:p.num_assoc_dev * 2),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
    ]

class ZDPSimpleDescReq(Packet):
    name = "ZDP Transaction Data: Simple_Desc_Req"
    fields_desc = [
        # IEEE Address (8 octets)
        XLEShortField("nwk_addr", 0),
        ByteField("endpoint", 0)
    ]

class ZDPSimpleDescRsp(Packet):
    name = "ZDP Transaction Data: Simple_Desc_Rsp"
    fields_desc = [
        ByteEnumField("status", 0, {0:"success", 1:"device_not_found", 2:"inv_requesttype", 3:"no_descriptor"}),
        # IEEE Address (8 octets)
        XLEShortField("nwk_addr", 0),
        ByteField("descriptor_length", 0),
        ConditionalField(ByteField("endpoint", 0x0),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(XLEShortField("profile_identifier", 0x0),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(XLEShortField("device_identifier", 0x0),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(BitField("device_version", 0 , 4),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(BitField("reserved", 0 , 4),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(FieldLenField("input_clusters_count", None, length_of="input_clusters", fmt="B"),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            FieldListField("input_clusters",[],XLEShortField("", 0), length_from=lambda p:p.input_clusters_count * 2),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(FieldLenField("output_clusters_count", None, length_of="output_clusters", fmt="B"),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
        ConditionalField(
            FieldListField("output_clusters",[],XLEShortField("", 0), length_from=lambda p:p.output_clusters_count * 2),
            lambda pkt:pkt.getfieldval("status") == 0
        ),
    ]

def guess_payload_class(self, payload):
    if self.underlayer.cluster == 0x0000:
        return ZDPNWKAddrReq
    elif self.underlayer.cluster == 0x0001:
        return ZDPIEEEAddrReq
    elif self.underlayer.cluster == 0x0002:
        return ZDPNodeDescReq
    elif self.underlayer.cluster == 0x0004:
        return ZDPSimpleDescReq
    elif self.underlayer.cluster == 0x0005:
        return ZDPActiveEPReq
    elif self.underlayer.cluster == 0x8000:
        return ZDPNWKAddrRsp
    elif self.underlayer.cluster == 0x8001:
        return ZDPIEEEAddrRsp
    elif self.underlayer.cluster == 0x8002:
        return ZDPNodeDescRsp
    elif self.underlayer.cluster == 0x8004:
        return ZDPSimpleDescRsp
    elif self.underlayer.cluster == 0x8005:
        return ZDPActiveEPRsp
    elif self.underlayer.cluster == 0x0013:
        return ZDPDeviceAnnce
    return Packet.guess_payload_class(self, payload)

ZigbeeDeviceProfile.guess_payload_class = guess_payload_class
