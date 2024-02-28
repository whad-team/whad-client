from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import ByteEnumField, ShortEnumField, LEIntField, XShortField, LEShortField, \
    UUIDField, StrFixedLenField, ConditionalField, PacketField, XLongField, XIntField,  XLEShortField, \
    BitEnumField, BitField, ByteField, FieldListField
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS




class RF4CE_Hdr(Packet):
    name = "RF4CE Packet"
    fields_desc = [
        BitField("channel_identifier", 0, 2),

        BitField("reserved", 0, 1),
        BitField("protocol_version", 0, 2),

        BitEnumField("security_enabled", 0, 1, {0: "disabled", 1:"enabled"}),

        BitEnumField("frame_type", 0, 2, {0: "reserved", 1:"data", 2:"command", 3:"vendor"}),
        LEIntField("frame_counter", None),
        ConditionalField(
            ByteField("profile_id", None),
            lambda pkt: pkt.frame_type in (1, 3)
        ),
        ConditionalField(
            LEShortField("vendor_id", None),
            lambda pkt: pkt.frame_type in (1, 3)
        ),
    ]

class RF4CE_Command_Hdr(Packet):
    name = "RF4CE Command Packet"
    fields_desc = [
        ByteEnumField("command_identifier", None, {
            0x01 : "discovery_req",
            0x02 : "discovery_rsp",
            0x03 : "pair_req",
            0x04 : "pair_rsp",
            0x05 : "unpair_req",
            0x06 : "key_seed",
            0x07 : "ping_req",
            0x08 : "ping_rsp"
        })
    ]

class RF4CE_Cmd_Discovery_Request(Packet):
    name = "RF4CE Discovery Request Command"
    fields_desc = [
        BitField("reserved2", 0, 4),
        BitEnumField("channel_normalization_capable", 0, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("security_capable", 0,  1,{0 : "no", 1 : "yes"}),
        BitEnumField("power_source", 0,  1,{ 0 : "battery_source", 1 : "alternating_current_source"}),
        BitEnumField("node_type", 0,  1,{0 : "controller", 1 : "target"}),

        LEShortField("vendor_identifier",None),
        StrFixedLenField("vendor_string", b"", length=7),

        BitField("reserved4", 0, 1),
        BitField("number_of_supported_profiles", 0, 3),
        BitField("reserved3", 0, 1),
        BitField("number_of_supported_device_types", 0, 2),
        BitEnumField("user_string_specificied", 0,  1, {0 : "no", 1 : "yes"}),
        ConditionalField(
            StrFixedLenField("user_string", None, length=15),
            lambda pkt: pkt.user_string_specificied  == 1
        ),
        FieldListField("device_type_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_device_types),
        FieldListField("profile_identifier_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_profiles),
        ByteField("requested_device_type", None)
    ]

class RF4CE_Cmd_Discovery_Response(Packet):
    name = "RF4CE Discovery Response Command"
    fields_desc = [
        ByteField("status", None),

        BitField("reserved2", 0, 4),
        BitEnumField("channel_normalization_capable", 0, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("security_capable", 0,  1,{0 : "no", 1 : "yes"}),
        BitEnumField("power_source", 0,  1,{ 0 : "battery_source", 1 : "alternating_current_source"}),
        BitEnumField("node_type", 0,  1,{0 : "controller", 1 : "target"}),


        LEShortField("vendor_identifier",None),
        StrFixedLenField("vendor_string", b"", length=7),

        BitField("reserved4", 0, 1),
        BitField("number_of_supported_profiles", 0, 3),
        BitField("reserved3", 0, 1),
        BitField("number_of_supported_device_types", 0, 2),
        BitEnumField("user_string_specificied", 0,  1, {0 : "no", 1 : "yes"}),
        ConditionalField(
            StrFixedLenField("user_string", None, length=15),
            lambda pkt: pkt.user_string_specificied  == 1
        ),
        FieldListField("device_type_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_device_types),
        FieldListField("profile_identifier_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_profiles),

        ByteField("discovery_req_lqi", None)
    ]


class RF4CE_Cmd_Pair_Request(Packet):
    name = "RF4CE Pair Request Command"
    fields_desc = [
        XLEShortField("nwk_addr", None),

        BitField("reserved2", 0, 4),
        BitEnumField("channel_normalization_capable", 0, 1, {0 : "no", 1 : "yes"}),
        BitEnumField("security_capable", 0,  1,{0 : "no", 1 : "yes"}),
        BitEnumField("power_source", 0,  1,{ 0 : "battery_source", 1 : "alternating_current_source"}),
        BitEnumField("node_type", 0,  1,{0 : "controller", 1 : "target"}),


        LEShortField("vendor_identifier",None),
        StrFixedLenField("vendor_string", b"", length=7),

        BitField("reserved4", 0, 1),
        BitField("number_of_supported_profiles", 0, 3),
        BitField("reserved3", 0, 1),
        BitField("number_of_supported_device_types", 0, 2),
        BitEnumField("user_string_specificied", 0,  1, {0 : "no", 1 : "yes"}),
        ConditionalField(
            StrFixedLenField("user_string", None, length=15),
            lambda pkt: pkt.user_string_specificied  == 1
        ),
        FieldListField("device_type_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_device_types),
        FieldListField("profile_identifier_list", None,
            ByteField("type_list", None)
        , count_from=lambda pkt:pkt.number_of_supported_profiles),

        ByteField("key_exchange_transfer_count", None)
    ]


bind_layers(RF4CE_Hdr, RF4CE_Command_Hdr, frame_type = 2)

bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Request, command_identifier = 1)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Response, command_identifier = 2)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Pair_Request, command_identifier = 3)

pkt1 = bytes.fromhex("2a5ee10000010c4111544c00000000001353522d3030312d550000000000000001c009")
pkt2 = bytes.fromhex("2ae90400000200074111544c00000000001354656c696e6b00000000000000000009c0c0")
pkt3 = bytes.fromhex("2a61e10000010c4111544c00000000001353522d3030312d550000000000000001c009")
pkt4 = bytes.fromhex("2aea0400000200074111544c00000000001354656c696e6b00000000000000000009c0c0")
pkt5 = bytes.fromhex("2a6ae10000010c4111544c00000000001353522d3030312d550000000000000001c009")
pkt6 = bytes.fromhex("2aec0400000200074111544c00000000001354656c696e6b00000000000000000009c0c0")
pkt7 = bytes.fromhex("2a6de1000003feff0c4111544c00000000001201c003")
pkt8 = bytes.fromhex("2aed0400000400bcfe153f074111544c00000000001354656c696e6b00000000000000000009c0")
pkt9 = bytes.fromhex("2aee040000060049141712a622348577899116f0b57217e2b226288f5b9d5690eba85ec99b7568ae436d8aa826d7108683aada4e73a59fd01d7889059dc77b9456c2d20c8bef408d9714d9028b78f77b35250f8b7e762c")
pkt10 = bytes.fromhex("2f80e10000c041117c5b15a216af")
pkt11 = bytes.fromhex("2f81e10000c04111454ce1038f6a")
pkts = [
    pkt1, pkt2, pkt3, pkt4, pkt5, pkt6, pkt7, pkt8, pkt9, pkt10, pkt11
]
for pkt in pkts:
    RF4CE_Hdr(pkt).show()
