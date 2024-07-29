from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import (
    ByteEnumField,
    ShortEnumField,
    IntField,
    LongField,
    XShortField,
    UUIDField,
    StrFixedLenField,
    ConditionalField,
    PacketField,
    XLongField,
    XIntField,
    BitEnumField,
    BitField,
    XBitField,
    FlagsField,
    BoundStrLenField,
    XStrField,
    ByteField,
    XByteField,
    ShortField,
    ThreeBytesField,
    XStrLenField,
    XStrFixedLenField,
    StrField,
    MultipleTypeField,
    FieldLenField,
)
from scapy.layers.bluetooth import EIR_Element, EIR_Hdr, EIR_Raw


MESSAGE_MODEL_OPCODES = {
    0x8201: "Generic_OnOff_Get",
    0x8202: "Generic_OnOff_Set",
    0x8203: "Generic_OnOff_Set_Unacknowledged",
    0x8204: "Generic_OnOff_Status",
    0x8205: "Generic_Level_Get",
    0x8206: "Generic_Level_Set",
    0x8207: "Generic_Level_Set_Unacknowledged",
    0x8208: "Generic_Level_Status",
    0x8209: "Generic_Delta_Set",
    0x820A: "Generic_Delta_Set_Unacknowledged",
    0x820B: "Generic_Move_Set",
    0x820C: "Generic_Move_Set_Unacknowledged",
    0x820D: "Generic_Default_Transition_Time_Get",
    0x820E: "Generic_Default_Transition_Time_Set",
    0x820F: "Generic_Default_Transition_Time_Set_Unacknowledged",
    0x8210: "Generic_Default_Transition_Time_Status",
    0x8211: "Generic_Power_OnOff_Generic_OnPowerUp_Get",
    0x8212: "Generic_OnPowerUp_Status",
    0x8213: "Generic_Power_OnOff_Setup_Generic_OnPowerUp_Set",
    0x8214: "Generic_OnPowerUp_Set_Unacknowledged",
    0x8215: "Generic_Power_Level_Get",
    0x8216: "Generic_Power_Level_Set",
    0x8217: "Generic_Power_Level_Set_Unacknowledged",
    0x8218: "Generic_Power_Level_Status",
    0x8219: "Generic_Power_Last_Get",
    0x821A: "Generic_Power_Last_Status",
    0x821B: "Generic_Power_Default_Get",
    0x821C: "Generic_Power_Default_Status",
    0x821D: "Generic_Power_Range_Get",
    0x821E: "Generic_Power_Range_Status",
    0x821F: "Generic_Power_Default_Set",
    0x8220: "Generic_Power_Default_Set_Unacknowledged",
    0x8221: "Generic_Power_Range_Set",
    0x8222: "Generic_Power_Range_Set_Unacknowledged",
    0x8223: "Generic_Battery_Generic_Battery_Get",
    0x8224: "Generic_Battery_Status",
    0x8225: "Generic_Location_Global_Get",
    0x40: "Generic_Location_Global_Status",
    0x8226: "Generic_Location_Local_Get",
    0x8227: "Generic_Location_Local_Status",
    0x41: "Generic_Location_Global_Set",
    0x42: "Generic_Location_Global_Set_Unacknowledged",
    0x8228: "Generic_Location_Local_Set",
    0x8229: "Generic_Location_Local_Set_Unacknowledged",
    0x822A: "Generic_Manufacturer_Properties_Get",
    0x43: "Generic_Manufacturer_Properties_Status",
    0x822B: "Generic_Manufacturer_Property_Get",
    0x44: "Generic_Manufacturer_Property_Set",
    0x45: "Generic_Manufacturer_Property_Set_Unacknowledged",
    0x46: "Generic_Manufacturer_Property_Status",
    0x822C: "Generic_Admin_Properties_Get",
    0x47: "Generic_Admin_Properties_Status",
    0x822D: "Generic_Admin_Property_Get",
    0x48: "Generic_Admin_Property_Set",
    0x49: "Generic_Admin_Property_Set_Unacknowledged",
    0x4A: "Generic_Admin_Property_Status",
    0x822E: "Generic_User_Properties_Get",
    0x4B: "Generic_User_Properties_Status",
    0x822F: "Generic_User_Property_Get",
    0x4C: "Generic_User_Property_Set",
    0x4D: "Generic_User_Property_Set_Unacknowledged",
    0x4E: "Generic_User_Property_Status",
    0x4F: "Generic_Client_Property_Generic_Client_Properties_Get",
    0x50: "Generic_Client_Properties_Status",
    0x8230: "Sensor_Descriptor_Get",
    0x51: "Sensor_Descriptor_Status",
    0x8231: "Sensor_Get",
    0x52: "Sensor_Status",
    0x8232: "Sensor_Column_Get",
    0x53: "Sensor_Column_Status",
    0x8233: "Sensor_Series_Get",
    0x54: "Sensor_Series_Status",
    0x8234: "Sensor_Cadence_Get",
    0x55: "Sensor_Cadence_Set",
    0x56: "Sensor_Cadence_Set_Unacknowledged",
    0x57: "Sensor_Cadence_Status",
    0x8235: "Sensor_Settings_Get",
    0x58: "Sensor_Settings_Status",
    0x8236: "Sensor_Setting_Get",
    0x59: "Sensor_Setting_Set",
    0x5A: "Sensor_Setting_Set_Unacknowledged",
    0x5B: "Sensor_Setting_Status",
    0x8237: "Time_Get",
    0x5C: "Time_Set",
    0x5D: "Time_Status",
    0x8238: "Time_Role_Get",
    0x8239: "Time_Role_Set",
    0x823A: "Time_Role_Status",
    0x823B: "Time_Zone_Get",
    0x823C: "Time_Zone_Set",
    0x823D: "Time_Zone_Status",
    0x823E: "TAI-UTC_Delta_Get",
    0x823F: "TAI-UTC_Delta_Set",
    0x8240: "TAI-UTC_Delta_Status",
    0x8241: "Scene_Get",
    0x8242: "Scene_Recall",
    0x8243: "Scene_Recall_Unacknowledged",
    0x5E: "Scene_Status",
    0x8244: "Scene_Register_Get",
    0x8245: "Scene_Register_Status",
    0x8246: "Scene_Store",
    0x8247: "Scene_Store_Unacknowledged",
    0x829E: "Scene_Delete",
    0x829F: "Scene_Delete_Unacknowledged",
    0x8248: "Scheduler_Action_Get",
    0x5F: "Scheduler_Action_Status",
    0x8249: "Scheduler_Get",
    0x824A: "Scheduler_Status",
    0x60: "Scheduler_Setup_Scheduler_Action_Set",
    0x61: "Scheduler_Action_Set_Unacknowledged",
    0x824B: "Light_Lightness_Light_Lightness_Get",
    0x824C: "Light_Lightness_Set",
    0x824D: "Light_Lightness_Set_Unacknowledged",
    0x824E: "Light_Lightness_Status",
    0x824F: "Light_Lightness_Linear_Get",
    0x8250: "Light_Lightness_Linear_Set",
    0x8251: "Light_Lightness_Linear_Set_Unacknowledged",
    0x8252: "Light_Lightness_Linear_Status",
    0x8253: "Light_Lightness_Last_Get",
    0x8254: "Light_Lightness_Last_Status",
    0x8255: "Light_Lightness_Default_Get",
    0x8256: "Light_Lightness_Default_Status",
    0x8257: "Light_Lightness_Range_Get",
    0x8258: "Light_Lightness_Range_Status",
    0x8259: "Light_Lightness_Default_Set",
    0x825A: "Light_Lightness_Default_Set_Unacknowledged",
    0x825B: "Light_Lightness_Range_Set",
    0x825C: "Light_Lightness_Range_Set_Unacknowledged",
    0x825D: "Light_CTL_Get",
    0x825E: "Light_CTL_Set",
    0x825F: "Light_CTL_Set_Unacknowledged",
    0x8260: "Light_CTL_Status",
    0x8261: "Light_CTL_Temperature_Get",
    0x8262: "Light_CTL_Temperature_Range_Get",
    0x8263: "Light_CTL_Temperature_Range_Status",
    0x8264: "Light_CTL_Temperature_Set",
    0x8265: "Light_CTL_Temperature_Set_Unacknowledged",
    0x8266: "Light_CTL_Temperature_Status",
    0x8267: "Light_CTL_Default_Get",
    0x8268: "Light_CTL_Default_Status",
    0x8269: "Light_CTL_Default_Set",
    0x826A: "Light_CTL_Default_Set_Unacknowledged",
    0x826B: "Light_CTL_Temperature_Range_Set",
    0x826C: "Light_CTL_Temperature_Range_Set_Unacknowledged",
    0x826D: "Light_HSL_Get",
    0x826E: "Light_HSL_Hue_Get",
    0x826F: "Light_HSL_Hue_Set",
    0x8270: "Light_HSL_Hue_Set_Unacknowledged",
    0x8271: "Light_HSL_Hue_Status",
    0x8272: "Light_HSL_Saturation_Get",
    0x8273: "Light_HSL_Saturation_Set",
    0x8274: "Light_HSL_Saturation_Set_Unacknowledged",
    0x8275: "Light_HSL_Saturation_Status",
    0x8276: "Light_HSL_Set",
    0x8277: "Light_HSL_Set_Unacknowledged",
    0x8278: "Light_HSL_Status",
    0x8279: "Light_HSL_Target_Get",
    0x827A: "Light_HSL_Target_Status",
    0x827B: "Light_HSL_Default_Get",
    0x827C: "Light_HSL_Default_Status",
    0x827D: "Light_HSL_Range_Get",
    0x827E: "Light_HSL_Range_Status",
    0x827F: "Light_HSL_Default_Set",
    0x8280: "Light_HSL_Default_Set_Unacknowledged",
    0x8281: "Light_HSL_Range_Set",
    0x8282: "Light_HSL_Range_Set_Unacknowledged",
    0x8283: "Light_xyL_Get",
    0x8284: "Light_xyL_Set",
    0x8285: "Light_xyL_Set_Unacknowledged",
    0x8286: "Light_xyL_Status",
    0x8287: "Light_xyL_Target_Get",
    0x8288: "Light_xyL_Target_Status",
    0x8289: "Light_xyL_Default_Get",
    0x828A: "Light_xyL_Default_Status",
    0x828B: "Light_xyL_Range_Get",
    0x828C: "Light_xyL_Range_Status",
    0x828D: "Light_xyL_Default_Set",
    0x828E: "Light_xyL_Default_Set_Unacknowledged",
    0x828F: "Light_xyL_Range_Set",
    0x8290: "Light_xyL_Range_Set_Unacknowledged",
    0x8291: "Light_LC_Mode_Get",
    0x8292: "Light_LC_Mode_Set",
    0x8293: "Light_LC_Mode_Set_Unacknowledged",
    0x8294: "Light_LC_Mode_Status",
    0x8295: "Light_LC_OM_Get",
    0x8296: "Light_LC_OM_Set",
    0x8297: "Light_LC_OM_Set_Unacknowledged",
    0x8298: "Light_LC_OM_Status",
    0x8299: "Light_LC_Light_OnOff_Get",
    0x829A: "Light_LC_Light_OnOff_Set",
    0x829B: "Light_LC_Light_OnOff_Set_Unacknowledged",
    0x829C: "Light_LC_Light_OnOff_Status",
    0x829D: "Light_LC_Property_Get",
    0x62: "Light_LC_Property_Set",
    0x63: "Light_LC_Property_Set_Unacknowledged",
    0x64: "Light_LC_Property_Status",
}

"""
PROVISIONING PDU LAYER
================================
"""


class BTMesh_Provisioning_Hdr(Packet):
    name = "Bluetooth Mesh Provisioning PDU"
    fields_desc = [
        BitField("padding", 0b00, 2),
        BitEnumField(
            "type",
            None,
            6,
            {
                0x00: "provisioning_invite",
                0x01: "provisioning_capabilities",
                0x02: "provisioning_start",
                0x03: "provisioning_public_key",
                0x04: "provisioning_input_complete",
                0x05: "provisioning_confirmation",
                0x06: "provisioning_random",
                0x07: "provisioning_data",
                0x08: "provisioning_complete",
                0x09: "provisioning_failed",
                0x0A: "provisioning_record_request",
                0x0B: "provisioning_record_response",
                0x0C: "provisioning_record_get",
                0x0D: "provisioning_record_list",
            },
        ),
    ]


class BTMesh_Provisioning_Invite(Packet):
    name = "Bluetooth Mesh Provisioning Invite"
    fields_desc = [ByteField("attention_duration", 0x00)]


class BTMesh_Provisioning_Capabilities(Packet):
    name = "Bluetooth Mesh Provisioning Capabilities"
    fields_desc = [
        ByteField("number_of_elements", None),
        FlagsField(
            "algorithms",
            None,
            2,
            {
                0b01: "BTM_ECDH_P256_CMAC_AES128_AES_CCM",
                0b10: "BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
            },
        ),
        BitField("RFU", 0, 14),
        ByteEnumField(
            "public_key_type",
            None,
            {
                0x00: "No OOB Public Key is used",
                0x01: "OOB Public Key is used",
            },
        ),
        ByteEnumField(
            "static_oob_type",
            None,
            {
                0x00: "Static OOB Information not available",
                0x01: "Static OOB Information available",
            },
        ),
        ByteField("output_oob_size", None),
        FlagsField(
            "output_oob_action",
            None,
            16,
            {
                0b00001: "Blink",
                0b00010: "Beep",
                0b00100: "Vibrate",
                0b01000: "Output Numeric",
                0b10000: "Output Alphanumeric",
            },
        ),
        ByteField("input_oob_size", None),
        FlagsField(
            "input_oob_action",
            None,
            16,
            {
                0b0001: "Push",
                0b0010: "Twist",
                0b0100: "Input Numeric",
                0b1000: "Input Alphanumeric",
            },
        ),
    ]


class BTMesh_Provisioning_Start(Packet):
    name = "Bluetooth Mesh Provisioning Start"
    fields_desc = [
        ByteEnumField(
            "algorithms",
            None,
            {
                0x00: "BTM_ECDH_P256_CMAC_AES128_AES_CCM",
                0x01: "BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
            },
        ),
        ByteEnumField(
            "public_key_type",
            None,
            {
                0x00: "No OOB Public Key is used",
                0x01: "OOB Public Key is used",
            },
        ),
        ByteEnumField(
            "authentication_method",
            None,
            {
                0x00: "No OOB authentication is used",
                0x01: "Static OOB authentication is used",
                0x02: "Output OOB authentication is used",
                0x03: "Input OOB authentication is used",
            },
        ),
        # Authentication_action  and authentication_size depend on authentication_method value
        MultipleTypeField(
            [
                (
                    ByteEnumField(
                        "authentication_action",
                        None,
                        {
                            0x00: "Blink",
                            0x01: "Beep",
                            0x02: "Vibrate",
                            0x03: "Output Numeric",
                            0x04: "Output Alphanumeric",
                        },
                    ),
                    lambda pkt: pkt.authentication_method == 0x02,
                ),
                (
                    ByteEnumField(
                        "authentication_action",
                        None,
                        {
                            0x00: "Push",
                            0x01: "Twist",
                            0x02: "Input Numeric",
                            0x03: "Input Alphanumeric",
                        },
                    ),
                    lambda pkt: pkt.authentication_method == 0x03,
                ),
            ],
            ByteField("authentication_action", 0x00),
        ),
        ByteField("authentication_size", 0x00),
    ]


class BTMesh_Provisioning_Public_Key(Packet):
    name = "Bluetooth Mesh Provisioning Public Key"
    fields_desc = [
        XStrFixedLenField("public_key_x", None, length=32),
        XStrFixedLenField("public_key_y", None, length=32),
    ]


class BTMesh_Provisioning_Input_Complete(Packet):
    name = "Bluetooth Mesh Provisioning Input Complete"


class BTMesh_Provisioning_Confirmation(Packet):
    name = "Bluetooth Mesh Provisioning Confirmation"
    fields_desc = [
        # Size depends on algorithm used, 16 or 32 bits
        BoundStrLenField("confirmation", "", minlen=16, maxlen=32)
    ]


class BTMesh_Provisioning_Random(Packet):
    name = "Bluetooth Mesh Provisioning Random"
    fields_desc = [
        # Size depends on algorithm used, 16 or 32 bits
        BoundStrLenField("random", "", minlen=16, maxlen=32)
    ]


class BTMesh_Provisioning_Data(Packet):
    name = "Bluetooth Mesh Provisioning Data"
    fields_desc = [
        XStrFixedLenField("encrypted_provisioning_data", None, length=25),
        LongField("provisioning_data_mic", None),
    ]


class BTMesh_Provisioning_Complete(Packet):
    name = "Bluetooth Mesh Provisioning Complete"


class BTMesh_Provisioning_Failed(Packet):
    name = "Bluetooth Mesh Provisioning Failed"
    fields_desc = [
        ByteEnumField(
            "error_code",
            None,
            {
                0x00: "Prohibited",
                0x01: "Invalid PDU",
                0x02: "Invalid Format",
                0x03: "Unexpected PDU",
                0x04: "Confirmation Failed",
                0x05: "Out of Resources",
                0x06: "Decryption Failed",
                0x07: "Unexpected Error",
                0x08: "Cannot Assign Addresses",
                0x09: "Invalid Data",
            },
        )
    ]


class BTMesh_Provisioning_Record_Request(Packet):
    name = "Bluetooth Mesh Provisioning Record Request"
    fields_desc = [
        ShortField("record_id", None),
        ShortField("fragment_offset", None),
        ShortField("fragment_maximum_size", None),
    ]


class BTMesh_Provisioning_Record_Response(Packet):
    name = "Bluetooth Mesh Provisioning Record Response"
    fields_desc = [
        ByteEnumField(
            "status",
            None,
            {
                0x00: "Success",
                0x01: "Requested Record Is Not Present",
                0x02: "Requested Offset Is Out Of Bounds",
            },
        ),
        ShortField("record_id", None),
        ShortField("fragment_offset", None),
        ShortField("total_length", None),
        StrField("data", None),  # optional
    ]


class BTMesh_Provisioning_Records_Get(Packet):
    name = "Bluetooth Mesh Provisioning Records Get"


class BTMesh_Provisioning_Records_List(Packet):
    name = "Bluetooth Mesh Provisioning Records List"
    fields_desc = [
        FlagsField("provisioning_extensions", None, 16, ["RFU"] * 16),
        XStrField("records_list", None),  # optional
    ]


bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Invite, type=0x00)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Capabilities, type=0x01)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Start, type=0x02)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Public_Key, type=0x03)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Input_Complete, type=0x04)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Confirmation, type=0x05)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Random, type=0x06)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Data, type=0x07)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Complete, type=0x08)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Failed, type=0x09)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Record_Request, type=0x0A)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Record_Response, type=0x0B)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Records_Get, type=0x0C)
bind_layers(BTMesh_Provisioning_Hdr, BTMesh_Provisioning_Records_List, type=0x0D)


"""
GENERIC PROVISIONING PDU LAYER
================================
"""


class BTMesh_Generic_Provisioning_Hdr(Packet):
    name = "Bluetooth Mesh Generic Provisioning PDU"
    fields_desc = [
        # Since the generic_provisioning_control_format is after in the fields, need to work with post_dissection and do_build to make sure generic_provisioning_control_format gets processed first
        ConditionalField(
            BitField("segment_number", 0, 6),
            lambda pkt: pkt.generic_provisioning_control_format == 0b00,
        ),
        ConditionalField(
            BitField("padding", 0, 6),
            lambda pkt: pkt.generic_provisioning_control_format == 0b01,
        ),
        ConditionalField(
            BitField("segment_index", 0, 6),
            lambda pkt: pkt.generic_provisioning_control_format == 0b10,
        ),
        ConditionalField(
            BitEnumField(
                "bearer_opcode",
                0,
                6,
                {0x00: "Link Open", 0x01: "Link ACK", 0x02: "Link Close"},
            ),
            lambda pkt: pkt.generic_provisioning_control_format == 0b11,
        ),
        BitEnumField(
            "generic_provisioning_control_format",
            None,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
    ]

    def pre_dissect(self, s):
        """trick to make generic_provisioning_control_format available before dissecting the first 6 bits"""
        # set the generic_provisioning_control_format value in the original packet
        if len(s) < 1:
            return s
        # we force the fecthing of the value for generic_provisioning_control_format from the raw bytes of the packet, this way the do_dissect function knows what ConditionalField to choose for the first field
        self.generic_provisioning_control_format = (s[-1] >> 6) & 0b11
        return s 

    def post_build(self, p, pay):
        """ generic_provisioning_control_format should be last, but we need to know its value to build other fields """
        p = p[:-1] + bytes([(self.generic_provisioning_control_format << 6) | (p[-1] & 0x3F)])
        return p + pay



class BTMesh_Generic_Provisioning_Transaction_Start(Packet):
    name = "Bluetooth Mesh Generic Provisioning Transaction Start"
    fields_desc = [
        FieldLenField(
            "total_length", None, length_of="generic_provisioning_payload_fragment"
        ),
        ByteField("frame_check_sequence", None),
        StrFixedLenField(
            "generic_provisioning_payload_fragment", None, length_from="total_length"
        ),
    ]


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Transaction_Start,
    generic_provisioning_control_format=0b00,
)


class BTMesh_Generic_Provisioning_Transaction_Ack(Packet):
    name = "Bluetooth Mesh Generic Provisioning Transaction Ack"


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Transaction_Ack,
    generic_provisioning_control_format=0b01,
)


class BTMesh_Generic_Provisioning_Transaction_Continuation(Packet):
    name = "Bluetooth Mesh Generic Provisioning Transaction Continuation"
    fields_desc = [
        BoundStrLenField(
            "generic_provisioning_payload_fragment", None, minlen=1, maxlen=64
        )
    ]


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Transaction_Continuation,
    generic_provisioning_control_format=0b10,
)


class BTMesh_Generic_Provisioning_Link_Ack(Packet):
    name = "Bluetooth Mesh Provisioning Bearer Link Ack"


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Transaction_Ack,
    generic_provisioning_control_format=0b11,
)


class BTMesh_Generic_Provisioning_Link_Open(Packet):
    name = "Bluetooth Mesh Generic Provisioning Bearer Link Open"
    fields_desc = [
        UUIDField("device_uuid", None, uuid_fmt=UUIDField.FORMAT_BE),
    ]


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Link_Open,
    generic_provisioning_control_format=0b11,
)


class BTMesh_Generic_Provisioning_Link_Close(Packet):
    name = "Bluetooth Mesh Generic Provisioning Bearer Link Close"
    fields_desc = [
        ByteEnumField("reason", None, {0x00: "Success", 0x01: "Timeout", 0x02: "Fail"})
    ]


bind_layers(
    BTMesh_Generic_Provisioning_Hdr,
    BTMesh_Generic_Provisioning_Link_Close,
    generic_provisioning_control_format=0b11,
)


""" 
PB-ADV LAYER
================================
"""


class EIR_PB_ADV_PDU(Packet):
    name = "Bluetooth Mesh PB_ADV PDU"
    fields_desc = [
        XIntField("link_id", None),
        XByteField("transaction_number", None),
    ]


"""
MODEL LAYER
================================
"""


class BTMesh_Model_Message(Packet):
    name = "Bluetooth Mesh Model Message"
    fields_desc = [
        ShortEnumField("opcode", None, MESSAGE_MODEL_OPCODES),
    ]


class BTMesh_Model_Generic_OnOff_Set(Packet):
    name = "Bluetooth Mesh Model Generic OnOff Set"
    fields_desc = [
        ByteEnumField("onoff", None, {0: "off", 1: "on"}),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_OnOff_Set, opcode=0x8202)


class BTMesh_Model_Generic_OnOff_Set_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Generic OnOff Set Unacknowledged"
    fields_desc = [
        ByteEnumField("onoff", None, {0: "off", 1: "on"}),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Generic_OnOff_Set_Unacknowledged, opcode=0x8203
)


class BTMesh_Model_Generic_OnOff_Status(Packet):
    name = "Bluetooth Mesh Model Generic OnOff Status"
    fields_desc = [
        ByteEnumField("present_onoff", None, {0: "off", 1: "on"}),
        ConditionalField(
            ByteEnumField("target_onoff", None, {0: "off", 1: "on"}),
            lambda pkt: len(pkt) > 2,
        ),
        ConditionalField(ByteField("remaining_time", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_OnOff_Status, opcode=0x8204)


class BTMesh_Model_Generic_Level_Set(Packet):
    name = "Bluetooth Mesh Model Generic Level Set"
    fields_desc = [
        ShortField("level", None),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_Level_Set, opcode=0x8206)


class BTMesh_Model_Generic_Level_Set_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Generic Level Set Unacknowledged"
    fields_desc = [
        ShortField("level", None),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_Level_Set, opcode=0x8207)


class BTMesh_Model_Generic_Delta_Set(Packet):
    name = "Bluetooth Mesh Model Generic Delta Set"
    fields_desc = [
        IntField("delta", None),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_Delta_Set, opcode=0x8209)


class BTMesh_Model_Generic_Delta_Set_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Generic Delta Set Unacknowledged"
    fields_desc = [
        IntField("delta", None),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_Delta_Set, opcode=0x820A)


class BTMesh_Model_Generic_Move_Set(Packet):
    name = "Bluetooth Mesh Model Generic Delta Move"
    fields_desc = [
        ShortField("delta_level", None),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Generic_Delta_Set, opcode=0x820B)


class BTMesh_Unsegmented_Access_Message(Packet):
    name = "Bluetooth Mesh Unsegmented Access Message"
    fields_desc = [
        BitField("application_key_flag", None, 1),
        BitField("application_key_id", None, 6),
    ]


class BTMesh_Lower_Transport_PDU(Packet):
    name = "Bluetooth Mesh Lower Transport PDU"
    fields_desc = [
        BitField("lower_transport_seg", None, 1),
    ]

    def guess_payload_class(self, payload):
        if self.underlayer.network_ctl == 0 and self.lower_transport_seg == 0:
            return BTMesh_Unsegmented_Access_Message
        else:
            return Packet.guess_payload_class(self, payload)


class BTMesh_Unprovisioned_Device_Beacon(Packet):
    name = "Bluetooth Mesh Unprovisioned Device Beacon"
    fields_desc = [
        UUIDField("device_uuid", None, uuid_fmt=UUIDField.FORMAT_BE),
        ShortEnumField(
            "oob_information",
            None,
            {
                0: "Other",
                1: "Electronic / URI",
                2: "2D machine-readable code",
                3: "Bar code",
                4: "Near Field Communication (NFC)",
                5: "Number",
                6: "String",
                7: "Support for certificate-based provisioning",
                8: "Support for provisioning records",
                9: "Reserved for Future Use",
                10: "Reserved for Future Use",
                11: "On box",
                12: "Inside box",
                13: "On piece of paper",
                14: "Inside manual",
                15: "On device",
            },
        ),
        IntField("uri_hash", None),
    ]


class BTMesh_Secure_Network_Beacon(Packet):
    name = "Bluetooth Mesh Secure Network Beacon"
    fields_desc = [
        BitEnumField("key_refresh_flag", 0, 1, [False, True]),
        BitEnumField(
            "iv_update_flag", 0, 1, ["normal_operation", "iv_update_in_progress"]
        ),
        BitField("unused", 0, 6),
        XLongField("network_id", None),
        XIntField("iv_index", None),
        XLongField("authentication_value", None),
    ]


class BTMesh_Private_Beacon(Packet):
    name = "Bluetooth Mesh Private Beacon"
    fields_desc = [
        StrFixedLenField("random", None, length=13),
        StrFixedLenField("obfuscated_private_beacon_data", None, length=5),
        XLongField("authentication_tag", None),
    ]


class EIR_BTMesh_Beacon(EIR_Element):
    name = "Bluetooth Mesh Beacon"
    fields_desc = [
        ByteEnumField(
            "mesh_beacon_type",
            None,
            {
                0x00: "unprovisioned_device_beacon",
                0x01: "secure_network_beacon",
                0x02: "mesh_private_beacon",
            },
        ),
        ConditionalField(
            PacketField(
                "unprovisioned_device_beacon_data",
                None,
                pkt_cls=BTMesh_Unprovisioned_Device_Beacon,
            ),
            lambda pkt: pkt.mesh_beacon_type == 0,
        ),
        ConditionalField(
            PacketField(
                "secure_beacon_data", None, pkt_cls=BTMesh_Secure_Network_Beacon
            ),
            lambda pkt: pkt.mesh_beacon_type == 1,
        ),
        ConditionalField(
            PacketField("private_beacon_data", None, pkt_cls=BTMesh_Private_Beacon),
            lambda pkt: pkt.mesh_beacon_type == 2,
        ),
    ]


class BTMesh_Mesh_Message(Packet):
    name = "Bluetooth Mesh Message"
    fields_desc = [
        BitField("iv_index", 0, 1),
        BitField("network_id", 0, 7),
        BitField("network_ctl", 0, 1),
        BitField("ttl", 0, 7),
        ThreeBytesField("seq_number", None),
        XShortField("src_addr", None),
        XShortField("dst_addr", None),
        XStrLenField(
            "network_mic",
            None,
            length_from=lambda pkt: 4 if pkt.network_ctl == 0 else 8,
        ),
    ]

    def pre_dissect(self, s):
        return (
            s[:9]
            + (s[-4:] if (s[1] >> 7) == 0 else s[-8:])
            + (s[9:-4] if (s[1] >> 7) else s[9:-8])
        )


class EIR_BTMesh_Message(EIR_Element):
    name = "EIR Bluetooth Mesh Message"
    fields_desc = [PacketField("mesh_message", None, pkt_cls=BTMesh_Mesh_Message)]


split_layers(EIR_Hdr, EIR_Raw)
bind_layers(EIR_Hdr, EIR_BTMesh_Message, type=0x2A)
bind_layers(EIR_Hdr, EIR_BTMesh_Beacon, type=0x2B)
bind_layers(EIR_Hdr, EIR_PB_ADV_PDU, type=0x29)
bind_layers(BTMesh_Mesh_Message, BTMesh_Lower_Transport_PDU)
bind_layers(BTMesh_Unsegmented_Access_Message, BTMesh_Model_Message)
bind_layers(EIR_PB_ADV_PDU, BTMesh_Generic_Provisioning_Hdr)
bind_layers(BTMesh_Generic_Provisioning_Hdr, BTMesh_Provisioning_Hdr)


def unbind():
    split_layers(EIR_Hdr, EIR_BTMesh_Beacon)
    split_layers(EIR_Hdr, EIR_BTMesh_Message)
    bind_layers(EIR_Hdr, EIR_Raw)
