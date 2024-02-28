from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import ByteEnumField, StrLenField, LEIntField, XShortField, LEShortField, \
    FieldLenField, StrFixedLenField, ConditionalField, PacketField, XLongField, XIntField,  XLEIntField, \
    XLEShortField, BitEnumField, BitField, ByteField, FieldListField, StrField, XByteField, LEShortField
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS, Dot15d4Data
from scapy.all import raw, rdpcap, conf

RC_COMMAND_CODES = {
 0x40 : "TV POWER",
 0x43 : "MUTE",
 0x6C : "ALL POWER Off:",
 0x6D : "On:",
 0x41 : "VOL+",
 0x42 : "VOL–",
 0x4C : "REPLAY",
 0x30 : "CH+",
 0x31 : "CH–",
 0x48 : "REWIND",
 0x61 : "PLAY/PAUSE",
 0x49 : "FAST FORWARD",
 0x0D : "EXIT",
 0x09 : "MENU",
 0x47 : "RECORD",
 0x53 : "GUIDE",
 0x37 : "PAGE UP",
 0x01 : "UP ARROW",
 0x03 : "LEFT ARROW",
 0x00 : "OK",
 0x04 : "RIGHT ARROW",
 0x02 : "DOWN ARROW",
 0x32 : "LAST",
 0x35 : "INFO",
 0x38 : "PAGE DOWN",
 0x74 : "OCAP A (yellow triangle) - Function Key 3",
 0x71 : "OCAP B (blue square) - Function Key 2",
 0x72 : "OCAP C (red circle) - Function Key 0",
 0x73 : "OCAP D (green diamond) - Function Key 1",
 0x20 : "Digit 0",
 0x21 : "Digit 1",
 0x22 : "Digit 2",
 0x23 : "Digit 3",
 0x24 : "Digit 4",
 0x25 : "Digit 5",
 0x26 : "Digit 6",
 0x27 : "Digit 7",
 0x28 : "Digit 8",
 0x29 : "Digit 9",
 0x4B : "30-Second Skip Ahead",
 0x34 : "Input/Select",
 0x10 : "HOME",
 0xA0 : "PROFILE",
 0xA1 : "CALL",
 0xA2 : "HOLD",
 0xA3 : "END",
 0xA4 : "VIEWS",
 0xA5 : "SELF-VIEW",
 0xA6 : "ZOOM IN",
 0xA7 : "ZOOM OUT",
 0x65 : "MUTE MIC",
 0x64 : "STOP VIDEO",
 0xB0 : "A",
 0xB1 : "B",
 0xB2 : "C",
 0xB3 : "D",
 0xB4 : "E",
 0xB5 : "F",
 0xB6 : "G",
 0xB7 : "H",
 0xB8 : "I",
 0xB9 : "J",
 0xBA : "K",
 0xBB : "L",
 0xBC : "M",
 0xBD : "N",
 0xBE : "O",
 0xBF : "P",
 0xC0 : "Q",
 0xC1 : "R",
 0xC2 : "S",
 0xC3 : "T",
 0xC4 : "U",
 0xC5 : "V",
 0xC6 : "W",
 0xC7 : "X",
 0xC8 : "Y",
 0xC9 : "Z",
 0xCA : "a",
 0xCB : "b",
 0xCC : "c",
 0xCD : "d",
 0xCE : "e",
 0xCF : "f",
 0xD0 : "g",
 0xD1 : "h",
 0xD2 : "i",
 0xD3 : "j",
 0xD4 : "k",
 0xD5 : "l",
 0xD6 : "m",
 0xD7 : "n",
 0xD8 : "o",
 0xD9 : "p",
 0xDA : "q",
 0xDB : "r",
 0xDC : "s",
 0xDD : "t",
 0xDE : "u",
 0xDF : "v",
 0xE0 : "w",
 0xE1 : "x",
 0xE2 : "y",
 0xE3 : "z",
 0xE4 : "?",
 0xE5 : "!",
 0xE6 : "#",
 0xE7 : "$",
 0xE8 : "%",
 0xE9 : "&",
 0xEA : "*",
 0xEB : "(",
 0xEC : ")",
 0xED : "+",
 0xEE : "-",
 0xEF : "=",
 0xF0 : "/",
 0xF1 : "_",
 0xF2 : "\"",
 0xF3 : ":",
 0xF4 : ";",
 0xF5 : "@",
 0x2A : ".",
 0xF6 : "'",
 0xF7 :",",
 0xA8 : "BACKSPACE",
 0x2B : "RETURN",
 0xA9 : "LOCK/UNLOCK",
 0xAA : "CAPS",
 0xAB : "ALT",
 0xAC : "SPACE",
 0xAD : "www.",
 0xAE : ".com",
 0xF8 : "On Demand",
 0xF9 : "RF Bypass",
 0xFA : "Next Favorite Channel",
}

class RF4CE_Hdr(Packet):
    name = "RF4CE Packet"
    fields_desc = [
        BitField("channel_identifier", 0, 2),
        BitField("reserved", 0, 1),
        BitField("protocol_version", 0, 2),
        BitEnumField("security_enabled", 0, 1, {0: "disabled", 1:"enabled"}),
        BitEnumField("frame_type", 0, 2, {0: "reserved", 1:"data", 2:"command", 3:"vendor"}),

        ConditionalField(
            XLEIntField("mic", None),
            lambda pkt: pkt.security_enabled  == 1
        ),

        LEIntField("frame_counter", None),
    ]

    def pre_dissect(self,s):
        if ((s[0] & 0b100) >> 2) == 1:
            return s[:1] + s[-4:] + s[1:-4]
        else:
            return s

    def post_build(self,p,pay):
        if self.security_enabled == 1:
            mic = self.mic
            return p[:1] + p[5:] + pay + p[1:5]
        else:
            return p + pay

class RF4CE_Vendor_Hdr(Packet):
    name = "RF4CE Vendor Data Packet"
    fields_desc = [
        XByteField("profile_id", None),
        LEShortField("vendor_id", None),
    ]

class RF4CE_Data_Hdr(Packet):
    name = "RF4CE Data Packet"
    fields_desc = [
        XByteField("profile_id", None),
        LEShortField("vendor_id", None),
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



class RF4CE_Cmd_Pair_Response(Packet):
    name = "RF4CE Pair Response Command"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("allocated_nwk_addr", None),
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

    ]

class RF4CE_Cmd_Unpair_Request(Packet):
    name = "RF4CE Unpair Request Command"
    fields_desc = []


class RF4CE_Cmd_Key_Seed(Packet):
    name = "RF4CE Key Seed Command"
    fields_desc = [
        ByteField("key_sequence_number", None),
        StrFixedLenField("seed_data", None, length=80),
    ]

class RF4CE_Cmd_Ping_Request(Packet):
    name = "RF4CE Ping Request Command"
    fields_desc = [
        ByteField("ping_options", None),
        StrField("ping_payload", None),
    ]


class RF4CE_Cmd_Ping_Response(Packet):
    name = "RF4CE Ping Response Command"
    fields_desc = [
        ByteField("ping_options", None),
        StrField("ping_payload", None),
    ]


class RF4CE_Vendor_ZRC_Hdr(Packet):
    name = "RF4CE Vendor Data - ZRC Profile"
    fields_desc = [
        BitField("reserved1", 0, 3),
        BitEnumField("command_code", 0, 5, {
            0x01 : "user_control_pressed",
            0x02 : "user_control_repeated",
            0x03 : "user_control_released",
            0x04 : "command discovery request",
            0x05 : "command discovery response"
        }),
    ]


class RF4CE_Vendor_ZRC_User_Control_Pressed(Packet):
    name = "RF4CE Vendor Data - User Control Pressed - ZRC Profile"
    fields_desc = [
        ByteEnumField("code", None, RC_COMMAND_CODES),
        StrField("ctrl_payload", None)
    ]

class RF4CE_Vendor_ZRC_User_Control_Released(Packet):
    name = "RF4CE Vendor Data - User Control Released - ZRC Profile"
    fields_desc = []

class RF4CE_Vendor_ZRC_User_Control_Repeated(Packet):
    name = "RF4CE Vendor Data - User Control Repeated - ZRC Profile"
    fields_desc = []

class RF4CE_Vendor_ZRC_Command_Discovery_Request(Packet):
    name = "RF4CE Vendor Data - Command Discovery Request - ZRC Profile"
    fields_desc = [
        ByteField("command_bank_number", None),
    ]

class RF4CE_Vendor_ZRC_Command_Discovery_Response(Packet):
    name = "RF4CE Vendor Data - Command Discovery Response - ZRC Profile"
    fields_desc = [
        ByteField("command_bank_number", None),
        StrFixedLenField("commands_supported", b"", length=256),
    ]

class RF4CE_Vendor_MSO_Hdr(Packet):
    name = "RF4CE Vendor Data - MSO Profile"
    fields_desc = [
        ByteEnumField("command_code", None, {
            0x01 : "user_control_pressed",
            0x02 : "user_control_repeated",
            0x03 : "user_control_released",
            0x20 : "check_validation_request",
            0x21 : "check_validation_response",
            0x22 : "set_attribute_request",
            0x23 : "set_attribute_response",
            0x24 : "get_attribute_request",
            0x25 : "get_attribute_response",
            0x32 : "audio"
        }),
    ]

class RF4CE_Vendor_MSO_Audio(Packet):
    name = "RF4CE Vendor Data - Audio - MSO Profile (Telink extension)"
    fields_desc = [
        ByteField("sequence_number", None),
        ByteEnumField("audio_cmd_id", None, {
            0x01 : "start_req",
            0x02 : "stop_req",
            0x03 : "data_notify",
            0x81 : "start_rsp",
            0x82 : "stop_rsp",
            0x83 : "data_rsp" # not implemented ?
        }),
        ByteField("length", 0),
    ]

    def post_build(self, p, pay):
        if self.length is None:
            self.length = len(pay)
        return p + pay

class RF4CE_Vendor_MSO_Audio_Start_Request(Packet):
    name = "RF4CE Vendor Data - Audio Start Request"
    fields_desc = [
        LEShortField("sample_rate", None),
        ByteField("resolution_bits", None),
        ByteField("mic_channel_number", None),
        ByteEnumField("codec_type", None, {1 : "ADPCM"}),
        ByteField("packet_size", None),
        ByteField("interval", None),
        ByteField("channel_number", None),
        ByteField("duration", None),

    ]

class RF4CE_Vendor_MSO_Audio_Stop_Request(Packet):
    name = "RF4CE Vendor Data - Audio Stop Request"
    fields_desc = []


class RF4CE_Vendor_MSO_Audio_Start_Response(Packet):
    name = "RF4CE Vendor Data - Audio Start Response"
    fields_desc = [
        ByteField("best_channel", None)
    ]


class RF4CE_Vendor_MSO_Audio_Stop_Response(Packet):
    name = "RF4CE Vendor Data - Audio Stop Response"
    fields_desc = [
        ByteField("state", None)
    ]


class RF4CE_Vendor_MSO_Audio_Data_Notify(Packet):
    name = "RF4CE Vendor Data - Audio Data Notify"
    fields_desc = [
        LEIntField("header", None),
        StrFixedLenField("samples", None, length=80)

        #FieldListField("samples_list", None,
        #    LEShortField("sample", None),
        #    count_from=lambda _:40),

    ]


class RF4CE_Vendor_MSO_User_Control_Pressed(Packet):
    name = "RF4CE Vendor Data - User Control Pressed - MSO Profile"
    fields_desc = [
        ByteEnumField("code", None, RC_COMMAND_CODES),
        StrField("ctrl_payload", None)
    ]

class RF4CE_Vendor_MSO_User_Control_Released(Packet):
    name = "RF4CE Vendor Data - User Control Released - MSO Profile"
    fields_desc = []

class RF4CE_Vendor_MSO_User_Control_Repeated(Packet):
    name = "RF4CE Vendor Data - User Control Repeated - MSO Profile"
    fields_desc = []

class RF4CE_Vendor_MSO_Check_Validation_Request(Packet):
    name = "RF4CE Vendor Data - Check Validation Request - MSO Profile"
    fields_desc = [
        BitField("reserved1", 0, 7),
        BitEnumField("request_automatic_validation", 0, 1, {0:"no", 1:"yes"})
    ]


class RF4CE_Vendor_MSO_Check_Validation_Response(Packet):
    name = "RF4CE Vendor Data - Check Validation Request - MSO Profile"
    fields_desc = [
        ByteEnumField("check_validation_status", None, {
            0x0 : "success",
            0xc0 : "pending",
            0xc1 : "timeout",
            0xc2 : "collision",
            0xc3 : "failure",
            0xc4 : "abort",
            0xc5 : "full_abort",
        })
    ]

MSO_REMOTE_INFORMATION_BASE = {
    0x00 : "Peripheral IDs",
    0x01 : "RF Statistics",
    0x02 : "Versioning",
    0x03 : "Battery Status",
    0x04 : "Short RF Retry Period",
    0xDB : "IR-RF Database",
    0xDC : "Validation Configuration",
    0xFF : "General Purpose",
}

class RF4CE_Vendor_MSO_Set_Attribute_Request(Packet):
    name = "RF4CE Vendor Data - Set Attribute Request - MSO Profile"
    fields_desc = [
        ByteEnumField("attribute_identifier", None, MSO_REMOTE_INFORMATION_BASE),
        ByteField("index", None),
        FieldLenField("value_length", None, length_of="value", fmt="B"),
        StrLenField("value", None, length_from=lambda x:x.value_length)
    ]

class RF4CE_Vendor_MSO_Set_Attribute_Response(Packet):
    name = "RF4CE Vendor Data - Set Attribute Response - MSO Profile"
    fields_desc = [
        ByteEnumField("attribute_identifier", None, MSO_REMOTE_INFORMATION_BASE),
        ByteField("index", None),
        ByteField("status", None)
    ]

class RF4CE_Vendor_MSO_Get_Attribute_Request(Packet):
    name = "RF4CE Vendor Data - Get Attribute Request - MSO Profile"
    fields_desc = [
        ByteEnumField("attribute_identifier", None, MSO_REMOTE_INFORMATION_BASE),
        ByteField("index", None),
        ByteField("value_length", None)
    ]

class RF4CE_Vendor_MSO_Get_Attribute_Response(Packet):
    name = "RF4CE Vendor Data - Get Attribute Response - MSO Profile"
    fields_desc = [
        ByteEnumField("attribute_identifier", None, MSO_REMOTE_INFORMATION_BASE),
        ByteField("index", None),
        ByteField("status", None),
        FieldLenField("value_length", None, length_of="value", fmt="B"),
        StrLenField("value", None, length_from=lambda x:x.value_length)
    ]

bind_layers(RF4CE_Hdr, RF4CE_Command_Hdr, frame_type = 2)
bind_layers(RF4CE_Hdr, RF4CE_Data_Hdr, frame_type = 1)
bind_layers(RF4CE_Hdr, RF4CE_Vendor_Hdr, frame_type = 3)

bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Request, command_identifier = 1)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Response, command_identifier = 2)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Pair_Request, command_identifier = 3)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Pair_Response, command_identifier = 4)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Unpair_Request, command_identifier = 5)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Key_Seed, command_identifier = 6)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Ping_Request, command_identifier = 7)
bind_layers(RF4CE_Command_Hdr, RF4CE_Cmd_Ping_Response, command_identifier = 8)

bind_layers(RF4CE_Vendor_Hdr, RF4CE_Vendor_MSO_Hdr, profile_id = 0x01)


bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_User_Control_Pressed, command_code = 0x01)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_User_Control_Repeated, command_code = 0x02)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_User_Control_Released, command_code = 0x03)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Check_Validation_Request, command_code = 0x20)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Check_Validation_Response, command_code = 0x21)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Set_Attribute_Request, command_code = 0x22)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Set_Attribute_Response, command_code = 0x23)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Get_Attribute_Request, command_code = 0x24)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Get_Attribute_Response, command_code = 0x25)
bind_layers(RF4CE_Vendor_MSO_Hdr, RF4CE_Vendor_MSO_Audio, command_code = 0x32)

bind_layers(RF4CE_Vendor_Hdr, RF4CE_Vendor_MSO_Hdr,  profile_id = 0xc0)

bind_layers(RF4CE_Vendor_ZRC_Hdr, RF4CE_Vendor_ZRC_User_Control_Pressed, command_code = 0x01)
bind_layers(RF4CE_Vendor_ZRC_Hdr, RF4CE_Vendor_ZRC_User_Control_Repeated, command_code = 0x02)
bind_layers(RF4CE_Vendor_ZRC_Hdr, RF4CE_Vendor_ZRC_User_Control_Released, command_code = 0x03)
bind_layers(RF4CE_Vendor_ZRC_Hdr, RF4CE_Vendor_ZRC_Command_Discovery_Request, command_code = 0x04)
bind_layers(RF4CE_Vendor_ZRC_Hdr, RF4CE_Vendor_ZRC_Command_Discovery_Response, command_code = 0x05)


bind_layers(RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Start_Request, audio_cmd_id = 0x01)
bind_layers(RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Stop_Request, audio_cmd_id = 0x02)
bind_layers(RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Data_Notify, audio_cmd_id = 0x03)

bind_layers(RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Start_Response, audio_cmd_id = 0x81)
bind_layers(RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Stop_Response, audio_cmd_id = 0x82)

# Monkey patch to add RF4CE support in Dot15d4 layer
old_guess_payload_class = Dot15d4Data.guess_payload_class
def guess_payload_class(self, payload):
    if conf.dot15d4_protocol == "rf4ce":
        return RF4CE_Hdr
    else:
        return old_guess_payload_class(self, payload)

Dot15d4Data.guess_payload_class = guess_payload_class
conf.dot15d4_protocol = "rf4ce"

seedslist = []
for i in rdpcap("./ressources/pcaps/telink_pairing_rf4ce.pcapng"):
    pkt_raw = raw(i)[44:]
    pkt = Dot15d4FCS(pkt_raw)

    if hasattr(pkt, "seed_data"):
        seedslist.append(pkt.seed_data)

def deriveKey(seeds):
    phase1 = b"\x00" * 80
    for current_seed in seeds:
        phase1 = bytes([phase1[i] ^ current_seed[i] for i in range(min(len(phase1), len(current_seed)))])
    print(phase1)
    phase2_seeds = []
    for i in range(5):
        start = i*16
        end = (i+1)*16
        s = phase1[start:end]
        phase2_seeds.append(s)

    key = b"\x00"*16
    for current_seed in phase2_seeds:
        key = bytes([key[i] ^ current_seed[i] for i in range(min(len(key), len(current_seed)))])

    return key
key = deriveKey(seedslist)

address2 = bytes.fromhex("c4:19:d1:ae:35:0d:70:02".replace(":", ""))[::-1]
address1 = bytes.fromhex("c4:19:d1:59:d2:a7:92:c5".replace(":", ""))[::-1]

from Cryptodome.Cipher import AES
from struct import pack
state = None
samples = b""
import pyaudio

p = pyaudio.PyAudio()

stream = p.open(format=pyaudio.get_format_from_width(2, unsigned=False),
                    channels=1,
                    rate=16000,
                    output=True)


for i in rdpcap("./ressources/pcaps/telink_voice3_rf4ce.pcapng"):
    pkt_raw = raw(i)[44:]
    pkt = Dot15d4FCS(pkt_raw)
    if hasattr(pkt, "security_enabled") and pkt.security_enabled == 1:
        # force a rebuild
        pkt.reserved = 1
        ciphertext = raw(pkt[RF4CE_Hdr:][2 if pkt.frame_type in (1,3) else 1:])
        header = raw(pkt[RF4CE_Hdr:])[:-4-len(ciphertext)]
        #print(header)
        auth = raw(pkt[RF4CE_Hdr:])[:5]
        #print("ciphertext", ciphertext.hex())
        nonce1 = address2 + pack("<I", pkt.frame_counter) + b"\x05"
        # Perform the decryption and integrity check
        cipher1 = AES.new(key, AES.MODE_CCM, nonce=nonce1, mac_len=4)
        cipher1.update(auth + address1)
        ok = False
        plaintext = cipher1.decrypt(ciphertext)
        try:
            cipher1.verify(pack('<I', pkt.mic))
            ok = True
        except:
            ok = False

        if not ok:
            nonce2 = address1 + pack("<I", pkt.frame_counter) + b"\x05"
            # Perform the decryption and integrity check
            cipher2 = AES.new(key, AES.MODE_CCM, nonce=nonce2, mac_len=4)
            cipher2.update(auth + address2)
            ok2 = False
            plaintext = cipher2.decrypt(ciphertext)
            try:
                cipher2.verify(pack('<I', pkt.mic))
                ok2 = True
            except:
                ok2 = False
        '''
        if ok:
            print("cipher 1 OK")
        elif ok2:
            print("cipher 2 OK")
        else:
            print("cipher 1 & 2 KO")
        '''
        if ok or ok2:
            #print("plaintext", plaintext.hex())

            pkt_dec = RF4CE_Hdr(header + plaintext + pack('<I', pkt.mic))
            #pkt_dec.show()

            from audioop import adpcm2lin

            if RF4CE_Vendor_MSO_Audio_Data_Notify in pkt_dec:
                #print(pkt_dec.samples)
                sample, new_state = adpcm2lin(pkt_dec.samples, 2, state)
                samples += sample

                state = new_state


for i in range(0, len(samples), 1024):
    sample = samples[i:i+1024]
    stream.write(sample)


#with open("/tmp/truc.wav", "wb") as f:
#    f.write(samples)

'''
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
'''
'''
print(raw(RF4CE_Hdr(
    channel_identifier=0,
    reserved=1,
    protocol_version=1,
    security_enabled=1,
    frame_type=3,
    mic=0x6a8f03e1,
    frame_counter= 57729,
    profile_id= 192,
    vendor_id = 4417,
)/b"EL").hex())
'''
