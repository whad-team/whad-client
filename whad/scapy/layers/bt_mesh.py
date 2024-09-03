import struct
from scapy.packet import Packet, bind_layers, split_layers
from scapy.fields import (
    ByteEnumField,
    ShortEnumField,
    IntField,
    XShortField,
    UUIDField,
    StrFixedLenField,
    ConditionalField,
    PacketField,
    XLongField,
    XIntField,
    BitEnumField,
    BitField,
    FlagsField,
    XStrField,
    ByteField,
    XByteField,
    ShortField,
    ThreeBytesField,
    XStrLenField,
    XStrFixedLenField,
    StrField,
    MultipleTypeField,
    XBitField,
    PacketLenField,
    FieldListField,
    X3BytesField,
    LEIntField,
    LELongField,
    LEX3BytesField,
    LEShortField,
    XLEShortField,
    XNBytesField,
    PacketListField,
)


from scapy.layers.bluetooth import EIR_Element, EIR_Hdr, EIR_Raw
from scapy.all import Raw, raw, RawVal, NoPayload
from scapy.config import conf

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
    0x8211: "Generic_OnPowerUp_Get",
    0x8212: "Generic_OnPowerUp_Status",
    0x8213: "Generic_OnPowerUp_Set",
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
    0x8223: "Generic_Battery_Get",
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
    0x4F: "Generic_Client_Properties_Get",
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
    0x60: "Scheduler_Action_Set",
    0x61: "Scheduler_Action_Set_Unacknowledged",
    0x824B: "Light_Lightness_Get",
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
    0x00: "Config_AppKey_Add",
    0x8000: "Config_AppKey_Delete",
    0x8001: "Config_AppKey_Get",
    0x8002: "Config_AppKey_List",
    0x8003: "Config_AppKey_Status",
    0x01: "Config_AppKey_Update",
    0x8009: "Config_Beacon_Get",
    0x800A: "Config_Beacon_Set",
    0x800B: "Config_Beacon_Status",
    0x8008: "Config_Composition_Data_Get",
    0x02: "Config_Composition_Data_Status",
    0x03: "Config_Model_Publication_Set",
    0x800C: "Config_Default_TTL_Get",
    0x800D: "Config_Default_TTL_Set",
    0x800E: "Config_Default_TTL_Status",
    0x800F: "Config_Friend_Get",
    0x8010: "Config_Friend_Set",
    0x8011: "Config_Friend_Status",
    0x8012: "Config_GATT_Proxy_Get",
    0x8013: "Config_GATT_Proxy_Set",
    0x8014: "Config_GATT_Proxy_Status",
    0x8038: "Config_Heartbeat_Publication_Get",
    0x8039: "Config_Heartbeat_Publication_Set",
    0x06: "Config_Heartbeat_Publication_Status",
    0x803A: "Config_Heartbeat_Subscription_Get",
    0x803B: "Config_Heartbeat_Subscription_Set",
    0x803C: "Config_Heartbeat_Subscription_Status",
    0x8015: "Config_Key_Refresh_Phase_Get",
    0x8016: "Config_Key_Refresh_Phase_Set",
    0x8017: "Config_Key_Refresh_Phase_Status",
    0x802D: "Config_Low_Power_Node_PollTimeout_Get",
    0x802E: "Config_Low_Power_Node_PollTimeout_Status",
    0x803D: "Config_Model_App_Bind",
    0x803E: "Config_Model_App_Status",
    0x803F: "Config_Model_App_Unbind",
    0x8018: "Config_Model_Publication_Get",
    0x8019: "Config_Model_Publication_Status",
    0x801A: "Config_Model_Publication_Virtual_Address_Set",
    0x801B: "Config_Model_Subscription_Add",
    0x801C: "Config_Model_Subscription_Delete",
    0x801D: "Config_Model_Subscription_Delete_All",
    0x801E: "Config_Model_Subscription_Overwrite",
    0x801F: "Config_Model_Subscription_Status",
    0x8020: "Config_Model_Subscription_Virtual_Address_Add",
    0x8021: "Config_Model_Subscription_Virtual_Address_Delete",
    0x8022: "Config_Model_Subscription_Virtual_Address_Overwrite",
    0x8040: "Config_NetKey_Add",
    0x8041: "Config_NetKey_Delete",
    0x8042: "Config_NetKey_Get",
    0x8043: "Config_NetKey_List",
    0x8044: "Config_NetKey_Status",
    0x8045: "Config_NetKey_Update",
    0x8023: "Config_Network_Transmit_Get",
    0x8024: "Config_Network_Transmit_Set",
    0x8025: "Config_Network_Transmit_Status",
    0x8046: "Config_Node_Identity_Get",
    0x8047: "Config_Node_Identity_Set",
    0x8048: "Config_Node_Identity_Status",
    0x8049: "Config_Node_Reset",
    0x804A: "Config_Node_Reset_Status",
    0x8026: "Config_Relay_Get",
    0x8027: "Config_Relay_Set",
    0x8028: "Config_Relay_Status",
    0x804B: "Config_SIG_Model_App_Get",
    0x804C: "Config_SIG_Model_App_List",
    0x8029: "Config_SIG_Model_Subscription_Get",
    0x802A: "Config_SIG_Model_Subscription_List",
    0x804D: "Config_Vendor_Model_App_Get",
    0x804E: "Config_Vendor_Model_App_List",
    0x802B: "Config_Vendor_Model_Subscription_Get",
    0x802C: "Config_Vendor_Model_Subscription_List",
    0x8004: "Health_Attention_Get",
    0x8005: "Health_Attention_Set",
    0x8006: "Health_Attention_Set_Unacknowledged",
    0x8007: "Health_Attention_Status",
    0x04: "Health_Current_Status",
    0x802F: "Health_Fault_Clear",
    0x8030: "Health_Fault_Clear_Unacknowledged",
    0x8031: "Health_Fault_Get",
    0x05: "Health_Fault_Status",
    0x8032: "Health_Fault_Test",
    0x8033: "Health_Fault_Test_Unacknowledged",
    0x8034: "Health_Period_Get",
    0x8035: "Health_Period_Set",
    0x8036: "Health_Period_Set_Unacknowledged",
    0x8037: "Health_Period_Status",
    0x804F: "Remote_Provisioning_Scan_Capabilities_Get",
    0x8050: "Remote_Provisioning_Scan_Capabilities_Status",
    0x8051: "Remote_Provisioning_Scan_Get",
    0x8052: "Remote_Provisioning_Scan_Start",
    0x8053: "Remote_Provisioning_Scan_Stop",
    0x8054: "Remote_Provisioning_Scan_Status",
    0x8055: "Remote_Provisioning_Scan_Report",
    0x8056: "Remote_Provisioning_Extended_Scan_Start",
    0x8057: "Remote_Provisioning_Extended_Scan_Report",
    0x8058: "Remote_Provisioning_Link_Get",
    0x8059: "Remote_Provisioning_Link_Open",
    0x805A: "Remote_Provisioning_Link_Close",
    0x805B: "Remote_Provisioning_Link_Status",
    0x805C: "Remote_Provisioning_Link_Report",
    0x805D: "Remote_Provisioning_PDU_Send",
    0x805E: "Remote_Provisioning_PDU_Outbound_Report",
    0x805F: "Remote_Provisioning_PDU_Report",
    0x807B: "DIRECTED_CONTROL_GET",
    0x807C: "DIRECTED_CONTROL_SET",
    0x807D: "DIRECTED_CONTROL_STATUS",
    0x807E: "PATH_METRIC_GET",
    0x807F: "PATH_METRIC_SET",
    0x8080: "PATH_METRIC_STATUS",
    0x8081: "DISCOVERY_TABLE_CAPABILITIES_GET",
    0x8082: "DISCOVERY_TABLE_CAPABILITIES_SET",
    0x8083: "DISCOVERY_TABLE_CAPABILITIES_STATUS",
    0x8084: "FORWARDING_TABLE_ADD",
    0x8085: "FORWARDING_TABLE_DELETE",
    0x8086: "FORWARDING_TABLE_STATUS",
    0x8087: "FORWARDING_TABLE_DEPENDENTS_ADD",
    0x8088: "FORWARDING_TABLE_DEPENDENTS_DELETE",
    0x8089: "FORWARDING_TABLE_DEPENDENTS_STATUS",
    0x808A: "FORWARDING_TABLE_DEPENDENTS_GET",
    0x808B: "FORWARDING_TABLE_DEPENDENTS_GET_STATUS",
    0x808C: "FORWARDING_TABLE_ENTRIES_COUNT_GET",
    0x808D: "FORWARDING_TABLE_ENTRIES_COUNT_STATUS",
    0x808E: "FORWARDING_TABLE_ENTRIES_GET",
    0x808F: "FORWARDING_TABLE_ENTRIES_STATUS",
    0x8090: "WANTED_LANES_GET",
    0x8091: "WANTED_LANES_SET",
    0x8092: "WANTED_LANES_STATUS",
    0x8093: "TWO_WAY_PATH_GET",
    0x8094: "TWO_WAY_PATH_SET",
    0x8095: "TWO_WAY_PATH_STATUS",
    0x8096: "PATH_ECHO_INTERVAL_GET",
    0x8097: "PATH_ECHO_INTERVAL_SET",
    0x8098: "PATH_ECHO_INTERVAL_STATUS",
    0x8099: "DIRECTED_NETWORK_TRANSMIT_GET",
    0x809A: "DIRECTED_NETWORK_TRANSMIT_SET",
    0x809B: "DIRECTED_NETWORK_TRANSMIT_STATUS",
    0x809C: "DIRECTED_RELAY_RETRANSMIT_GET",
    0x809D: "DIRECTED_RELAY_RETRANSMIT_SET",
    0x809E: "DIRECTED_RELAY_RETRANSMIT_STATUS",
    0x809F: "RSSI_THRESHOLD_GET",
    0x80A0: "RSSI_THRESHOLD_SET",
    0x80A1: "RSSI_THRESHOLD_STATUS",
    0x80A2: "DIRECTED_PATHS_GET",
    0x80A3: "DIRECTED_PATHS_STATUS",
    0x80A4: "DIRECTED_PUBLISH_POLICY_GET",
    0x80A5: "DIRECTED_PUBLISH_POLICY_SET",
    0x80A6: "DIRECTED_PUBLISH_POLICY_STATUS",
    0x80A7: "PATH_DISCOVERY_TIMING_CONTROL_GET",
    0x80A8: "PATH_DISCOVERY_TIMING_CONTROL_SET",
    0x80A9: "PATH_DISCOVERY_TIMING_CONTROL_STATUS",
    0x80AA: "this_opcode_is_not_used",
    0x80AB: "DIRECTED_CONTROL_NETWORK_TRANSMIT_GET",
    0x80AC: "DIRECTED_CONTROL_NETWORK_TRANSMIT_SET",
    0x80AD: "DIRECTED_CONTROL_NETWORK_TRANSMIT_STATUS",
    0x80AE: "DIRECTED_CONTROL_RELAY_RETRANSMIT_GET",
    0x80AF: "DIRECTED_CONTROL_RELAY_RETRANSMIT_SET",
    0x80B0: "DIRECTED_CONTROL_RELAY_RETRANSMIT_STATUS",
    0x8060: "PRIVATE_BEACON_GET",
    0x8061: "PRIVATE_BEACON_SET",
    0x8062: "PRIVATE_BEACON_STATUS",
    0x8063: "PRIVATE_GATT_PROXY_GET",
    0x8064: "PRIVATE_GATT_PROXY_SET",
    0x8065: "PRIVATE_GATT_PROXY_STATUS",
    0x8066: "PRIVATE_NODE_IDENTITY_GET",
    0x8067: "PRIVATE_NODE_IDENTITY_SET",
    0x8068: "PRIVATE_NODE_IDENTITY_STATUS",
    0x8069: "ON_DEMAND_PRIVATE_PROXY_GET",
    0x806A: "ON_DEMAND_PRIVATE_PROXY_SET",
    0x806B: "ON_DEMAND_PRIVATE_PROXY_STATUS",
    0x806C: "SAR_TRANSMITTER_GET",
    0x806D: "SAR_TRANSMITTER_SET",
    0x806E: "SAR_TRANSMITTER_STATUS",
    0x806F: "SAR_RECEIVER_GET",
    0x8070: "SAR_RECEIVER_SET",
    0x8071: "SAR_RECEIVER_STATUS",
    0x8072: "OPCODES_AGGREGATOR_SEQUENCE",
    0x8073: "OPCODES_AGGREGATOR_STATUS",
    0x8074: "LARGE_COMPOSITION_DATA_GET",
    0x8075: "LARGE_COMPOSITION_DATA_STATUS",
    0x8076: "MODELS_METADATA_GET",
    0x8077: "MODELS_METADATA_STATUS",
    0x8078: "SOLICITATION_PDU_RPL_ITEM_CLEAR",
    0x8079: "SOLICITATION_PDU_RPL_ITEM_CLEAR_UNACKNOWLEDGED",
    0x807A: "SOLICITATION_PDU_RPL_ITEM_STATUS",
    0x80B1: "SUBNET_BRIDGE_GET",
    0x80B2: "SUBNET_BRIDGE_SET",
    0x80B3: "SUBNET_BRIDGE_STATUS",
    0x80B4: "BRIDGING_TABLE_ADD",
    0x80B5: "BRIDGING_TABLE_REMOVE",
    0x80B6: "BRIDGING_TABLE_STATUS",
    0x80B7: "BRIDGED_SUBNETS_GET",
    0x80B8: "BRIDGED_SUBNETS_LIST",
    0x80B9: "BRIDGING_TABLE_GET",
    0x80BA: "BRIDGING_TABLE_LIST",
    0x80BB: "BRIDGING_TABLE_SIZE_GET",
    0x80BC: "BRIDGING_TABLE_SIZE_STATUS",
}

"""
Custome Fields
"""


class LittleEndianPacketField(PacketField):
    """
    Little Endian Packet Field
    """

    def __init__(self, name, default, cls):
        super().__init__(name, default, cls)

    def i2m(self, pkt, val):
        if val is None:
            return b""
        return self.reverse_bytes(raw(val))

    def m2i(self, pkt, data):
        reversed_data = self.reverse_bytes(data)
        return self.cls(reversed_data)

    @staticmethod
    def reverse_bytes(data):
        return data[::-1]


class LittleEndianPacketLenField(PacketLenField):
    """
    Little Endian PacketLenField
    """

    def __init__(self, name, default, cls, length_from=None):
        super().__init__(name, default, cls, length_from)

    def i2m(self, pkt, val):
        if val is None:
            return b""
        return self.reverse_bytes(raw(val))

    def m2i(self, pkt, data):
        reversed_data = self.reverse_bytes(data)
        return self.cls(reversed_data)

    @staticmethod
    def reverse_bytes(data):
        return data[::-1]


class UnicastAddr(Packet):
    """
    Describes a Unicast Addr, as specifiied in Spec p. 55 Section 3.4.2.2.1
    """

    name = "Bluetooth Mesh Unicast Addr"
    fields_desc = [
        BitField("length_present", 0, 1),
        XBitField("range_start", 0, 15),
        ConditionalField(
            ByteField("range_length", None),
            lambda pkt: pkt.length_present == 1,
        ),
    ]

    def extract_padding(self, s):
        """
        Pass the remaining data of the Packet the the next Layer (tricky).
        We use this packet in a PacketField so we need to have the remaining data passed to the parent.
        """
        return "", s


class LEUnicastAddr(Packet):
    """
    Describes a Unicast Addr, as specifiied in Spec p. 55 Section 3.4.2.2.1
    """

    name = "Bluetooth Mesh Unicast Addr"
    fields_desc = [
        XBitField("range_start", 0, 15, tot_size=-2),
        BitField("length_present", 0, 1, end_tot_size=-2),
        ConditionalField(
            ByteField("range_length", None),
            lambda pkt: pkt.length_present == 1,
        ),
    ]

    def extract_padding(self, s):
        """
        Pass the remaining data of the Packet the the next Layer (tricky).
        We use this packet in a PacketField so we need to have the remaining data passed to the parent.
        """
        return "", s


class ForwardingTableEntryHeader(Packet):
    """
    Bluetooth Mesh Forwarding Table Entry, Mesh Protocol Spec Section 4.2.29.2
    Used in LittleEndianPacketField !
    """

    name = "Bluetooth Mesh Forwarding Table Entry Header"
    fields_desc = [
        BitField("prohibited", 0, 7),
        BitField("dependent_target_list_size_indicator", 0, 2),
        BitField("dependent_origin_list_size_indicator", 0, 2),
        BitEnumField(
            "bearer_toward_path_target_indicator",
            0,
            1,
            {
                0: "Node is not Path Target of Forwarding Table Entry",
                1: "Node is Path Target of Forwarding Table Entry",
            },
        ),
        BitEnumField(
            "bearer_toward_path_origin_indicator",
            0,
            1,
            {
                0: "Node is not Path Origin of Forwarding Table Entry",
                1: "Node is Path Origin of Forwarding Table Entry",
            },
        ),
        BitEnumField(
            "backward_path_validated_flag",
            0,
            1,
            {
                0: "Backward path has not been validated",
                1: "Backward path has been validated",
            },
        ),
        BitField("unicast_destination_flag", 0, 1),
        BitEnumField(
            "fixed_path_flag", 0, 1, {0: "Path is non fixed", 1: "Path is fixed path"}
        ),
    ]


# Can only be used via the ForwardingTableEntryHeader payload ! (otherwiser underlayer fields will be missing ...)
class ForwardingTableEntry(Packet):
    name = "Bluetooth Mesh Path Forwarding Table Entry"
    fields_desc = [
        LittleEndianPacketLenField(
            "forwarding_table_entry_header",
            ForwardingTableEntryHeader(),
            cls=ForwardingTableEntryHeader,
            length_from=lambda pkt: 2,
        ),
        ConditionalField(
            ByteField("lane_counter", None),
            lambda pkt: pkt.forwarding_table_entry_header.fixed_path_flag == 0,
        ),
        ConditionalField(
            LEShortField("path_remaining_time", None),
            lambda pkt: pkt.forwarding_table_entry_header.fixed_path_flag == 0,
        ),
        ConditionalField(
            ByteField("path_origin_forwarding_number", None),
            lambda pkt: pkt.forwarding_table_entry_header.fixed_path_flag == 0,
        ),
        PacketField("path_origin_unicast_addr_range", None, pkt_cls=LEUnicastAddr),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        ByteField("dependent_origin_list_size", 0),
                        lambda pkt: pkt.forwarding_table_entry_header.dependent_origin_list_size_indicator
                        == 0b01,
                    ),
                    (
                        XLEShortField("dependent_origin_list_size", 0),
                        lambda pkt: pkt.forwarding_table_entry_header.dependent_origin_list_size_indicator
                        == 0b10,
                    ),
                ],
                ByteField("dependent_origin_list_size", 0),  # never used
            ),
            lambda pkt: pkt.forwarding_table_entry_header.dependent_origin_list_size_indicator
            != 0b00
            and pkt.forwarding_table_entry_header.dependent_origin_list_size_indicator
            != 0b11,
        ),
        ConditionalField(
            XLEShortField("bearer_toward_path_origin", None),
            lambda pkt: pkt.forwarding_table_entry_header.bearer_toward_path_origin_indicator
            == 1,
        ),
        ConditionalField(
            PacketField("path_target_unicast_addr_range", None, pkt_cls=LEUnicastAddr),
            lambda pkt: pkt.forwarding_table_entry_header.unicast_destination_flag == 1,
        ),
        ConditionalField(
            XLEShortField("multicast_destination", None),
            lambda pkt: pkt.forwarding_table_entry_header.unicast_destination_flag == 0,
        ),
        ConditionalField(
            MultipleTypeField(
                [
                    (
                        ByteField("dependent_target_list_size", 0),
                        lambda pkt: pkt.forwarding_table_entry_header.dependent_target_list_size_indicator
                        == 0b01,
                    ),
                    (
                        XLEShortField("dependent_target_list_size", 0),
                        lambda pkt: pkt.forwarding_table_entry_header.dependent_target_list_size_indicator
                        == 0b10,
                    ),
                ],
                ByteField("dependent_target_list_size", 0),  # never used
            ),
            lambda pkt: pkt.forwarding_table_entry_header.dependent_target_list_size_indicator
            != 0b00
            and pkt.forwarding_table_entry_header.dependent_target_list_size_indicator
            != 0b11,
        ),
        ConditionalField(
            XLEShortField("bearer_toward_path_target", None),
            lambda pkt: pkt.forwarding_table_entry_header.bearer_toward_path_target_indicator
            == 1,
        ),
    ]

    def extract_padding(self, s):
        """
        Pass the remaining data of the Packet the the next Layer (tricky).
        We use this packet in a PacketField so we need to have the remaining data passed to the parent.
        """
        return "", s


"""
PROVISIONING PDU LAYER
================================
"""

_provisioning_pdu_types = {
    0x00: "Provisioning_Invite",
    0x01: "Provisioning_Capabilities",
    0x02: "Provisioning_Start",
    0x03: "Provisioning_Public_Key",
    0x04: "Provisioning_Input_Complete",
    0x05: "Provisioning_Confirmation",
    0x06: "Provisioning_Random",
    0x07: "Provisioning_Data",
    0x08: "Provisioning_Complete",
    0x09: "Provisioning_Failed",
    0x0A: "Provisioning_Record_Request",
    0x0B: "Provisioning_Record_Response",
    0x0C: "Provisioning_Records_Get",
    0x0D: "Provisioning_Records_List",
}


class BTMesh_Provisioning_Invite(Packet):
    name = "Bluetooth Mesh Provisioning Invite"
    fields_desc = [ByteField("attention_duration", 0x00)]


class BTMesh_Provisioning_Capabilities(Packet):
    name = "Bluetooth Mesh Provisioning Capabilities"
    fields_desc = [
        ByteField("number_of_elements", None),
        BitField("RFU_alg", 0, 14),
        FlagsField(
            "algorithms",
            None,
            2,
            {
                0b01: "BTM_ECDH_P256_CMAC_AES128_AES_CCM",
                0b10: "BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
            },
        ),
        BitField("RFU_pub_key_type", 0, 6),
        FlagsField(
            "public_key_type",
            None,
            2,
            {
                0b01: "No OOB Public Key is used",
                0b10: "OOB Public Key is used",
            },
        ),
        BitField("RFU_oob_type", 0, 6),
        FlagsField(
            "oob_type",
            None,
            2,
            {
                0b01: "Static OOB Information not available",
                0b10: "Static OOB Information available",
            },
        ),
        ByteField("output_oob_size", None),
        BitField("RFU_output_oob_action", 0, 11),
        FlagsField(
            "output_oob_action",
            None,
            5,
            {
                0b00001: "Blink",
                0b00010: "Beep",
                0b00100: "Vibrate",
                0b01000: "Output Numeric",
                0b10000: "Output Alphanumeric",
            },
        ),
        ByteField("input_oob_size", None),
        BitField("RFU_input_oob_action", 0, 12),
        FlagsField(
            "input_oob_action",
            None,
            4,
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
        StrFixedLenField("public_key_x", None, length=32),
        StrFixedLenField("public_key_y", None, length=32),
    ]


class BTMesh_Provisioning_Input_Complete(Packet):
    name = "Bluetooth Mesh Provisioning Input Complete"


class BTMesh_Provisioning_Confirmation(Packet):
    name = "Bluetooth Mesh Provisioning Confirmation"
    fields_desc = [
        # Size depends on algorithm used, 16 or 32 bits
        StrField("confirmation", "")
    ]


class BTMesh_Provisioning_Random(Packet):
    name = "Bluetooth Mesh Provisioning Random"
    fields_desc = [
        # Size depends on algorithm used, 16 or 32 bits
        StrField("random", "")
    ]


class BTMesh_Provisioning_Data(Packet):
    name = "Bluetooth Mesh Provisioning Data"
    fields_desc = [
        XStrFixedLenField("encrypted_provisioning_data", None, length=25),
        XStrFixedLenField("provisioning_data_mic", None, length=8),
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


class BTMesh_Provisioning_Hdr(Packet):
    name = "Bluetooth Mesh Provisioning PDU"
    fields_desc = [
        BitField("padding", 0b00, 2),
        BitEnumField("type", 0, 6, _provisioning_pdu_types),
        MultipleTypeField(
            [
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Invite(),
                        BTMesh_Provisioning_Invite,
                    ),
                    lambda pkt: pkt.type == 0x00,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Capabilities(),
                        BTMesh_Provisioning_Capabilities,
                    ),
                    lambda pkt: pkt.type == 0x01,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Start(),
                        BTMesh_Provisioning_Start,
                    ),
                    lambda pkt: pkt.type == 0x02,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Public_Key(),
                        BTMesh_Provisioning_Public_Key,
                    ),
                    lambda pkt: pkt.type == 0x03,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Input_Complete(),
                        BTMesh_Provisioning_Input_Complete,
                    ),
                    lambda pkt: pkt.type == 0x04,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Confirmation(),
                        BTMesh_Provisioning_Confirmation,
                    ),
                    lambda pkt: pkt.type == 0x05,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Random(),
                        BTMesh_Provisioning_Random,
                    ),
                    lambda pkt: pkt.type == 0x06,
                ),
                (
                    PacketField(
                        "message", BTMesh_Provisioning_Data(), BTMesh_Provisioning_Data
                    ),
                    lambda pkt: pkt.type == 0x07,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Complete(),
                        BTMesh_Provisioning_Complete,
                    ),
                    lambda pkt: pkt.type == 0x08,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Failed(),
                        BTMesh_Provisioning_Failed,
                    ),
                    lambda pkt: pkt.type == 0x09,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Record_Request(),
                        BTMesh_Provisioning_Record_Request,
                    ),
                    lambda pkt: pkt.type == 0x0A,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Record_Response(),
                        BTMesh_Provisioning_Record_Response,
                    ),
                    lambda pkt: pkt.type == 0x0B,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Records_Get(),
                        BTMesh_Provisioning_Records_Get,
                    ),
                    lambda pkt: pkt.type == 0x0C,
                ),
                (
                    PacketField(
                        "message",
                        BTMesh_Provisioning_Records_List(),
                        BTMesh_Provisioning_Records_List,
                    ),
                    lambda pkt: pkt.type == 0x0D,
                ),
            ],
            PacketField(
                "message", BTMesh_Provisioning_Invite(), BTMesh_Provisioning_Invite
            ),
        ),
    ]


"""
GENERIC PROVISIONING PDU LAYER
================================
"""


# Dont use on its own, use subclasses directly
class BTMesh_Generic_Provisioning_Hdr(Packet):
    name = "Bluetooth Mesh Generic Provisioning PDU"
    fields_desc = [
        BitField(
            "placeholder_first_6_bits", 0, 6
        ),  # The first 6 bits, name will change in subclasses
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

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kargs):
        if _pkt:
            generic_provisioning_payload_format = _pkt[0] & 0b11  # Get the last 2 bits
            if generic_provisioning_payload_format == 0b00:
                return BTMesh_Generic_Provisioning_Transaction_Start
            elif generic_provisioning_payload_format == 0b01:
                return BTMesh_Generic_Provisioning_Transaction_Ack
            elif generic_provisioning_payload_format == 0b10:
                return BTMesh_Generic_Provisioning_Transaction_Continuation
            elif generic_provisioning_payload_format == 0b11:
                bearer_opcode = (_pkt[0] & 0b11111100) >> 2
                if bearer_opcode == 0x00:
                    return BTMesh_Generic_Provisioning_Link_Open
                elif bearer_opcode == 0x01:
                    return BTMesh_Generic_Provisioning_Link_Ack
                elif bearer_opcode == 0x02:
                    return BTMesh_Generic_Provisioning_Link_Close
        return cls


class BTMesh_Generic_Provisioning_Transaction_Start(BTMesh_Generic_Provisioning_Hdr):
    name = "Bluetooth Mesh Generic Provisioning Transaction Start"
    fields_desc = [
        BitField("segment_number", 0, 6),
        BitEnumField(
            "generic_provisioning_control_format",
            0b00,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
        ShortField("total_length", None),
        XByteField(
            "frame_check_sequence", None
        ),  # TO COMPUTE IN LOGIC, ON THE WHOLE PROVISIONING PDU IN PAYLOAD (not just the 1st fragment)
        # StrFixedLenField(
        #    "generic_provisioning_payload_fragment", None, length_from="total_length"
        # ),
    ]

    def guess_payload_class(self, payload):
        # if more than one segment, return Raw data
        if self.getfieldval("segment_number") > 0:
            return Raw
        else:
            return Packet.guess_payload_class(self, payload)


class BTMesh_Generic_Provisioning_Transaction_Ack(BTMesh_Generic_Provisioning_Hdr):
    name = "Bluetooth Mesh Generic Provisioning Transaction Ack"
    fields_desc = [
        BitField("padding", 0, 6),
        BitEnumField(
            "generic_provisioning_control_format",
            0b01,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
    ]


class BTMesh_Generic_Provisioning_Transaction_Continuation(
    BTMesh_Generic_Provisioning_Hdr
):
    name = "Bluetooth Mesh Generic Provisioning Transaction Continuation"
    fields_desc = [
        BitField("segment_index", 0, 6),
        BitEnumField(
            "generic_provisioning_control_format",
            0b10,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
        StrField(
            "generic_provisioning_payload_fragment",
            None,
        ),
    ]

    def guess_payload_class(self, payload):
        # Since payload are fragments only, should not have anything after
        return None


class BTMesh_Generic_Provisioning_Link_Ack(BTMesh_Generic_Provisioning_Hdr):
    name = "Bluetooth Mesh Provisioning Bearer Link Ack"
    fields_desc = [
        BitEnumField(
            "bearer_opcode",
            0x01,
            6,
            {0x00: "Link Open", 0x01: "Link ACK", 0x02: "Link Close"},
        ),
        BitEnumField(
            "generic_provisioning_control_format",
            0b11,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
    ]


class BTMesh_Generic_Provisioning_Link_Open(BTMesh_Generic_Provisioning_Hdr):
    name = "Bluetooth Mesh Generic Provisioning Bearer Link Open"
    fields_desc = [
        BitEnumField(
            "bearer_opcode",
            0x00,
            6,
            {0x00: "Link Open", 0x01: "Link ACK", 0x02: "Link Close"},
        ),
        BitEnumField(
            "generic_provisioning_control_format",
            0b11,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
        UUIDField("device_uuid", None, uuid_fmt=UUIDField.FORMAT_BE),
    ]


class BTMesh_Generic_Provisioning_Link_Close(BTMesh_Generic_Provisioning_Hdr):
    name = "Bluetooth Mesh Generic Provisioning Bearer Link Close"
    fields_desc = [
        BitEnumField(
            "bearer_opcode",
            0x02,
            6,
            {0x00: "Link Open", 0x01: "Link ACK", 0x02: "Link Close"},
        ),
        BitEnumField(
            "generic_provisioning_control_format",
            0b11,
            2,
            {
                0b00: "Transaction Start",
                0b01: "Transaction Acknowledgment",
                0b10: "Transaction Continuation",
                0b11: "Provisioning Bearer Control",
            },
        ),
        ByteEnumField("reason", None, {0x00: "Success", 0x01: "Timeout", 0x02: "Fail"}),
    ]


""" 
PB-ADV LAYER
================================
"""


class EIR_PB_ADV_PDU(EIR_Element):
    name = "Bluetooth Mesh PB_ADV PDU"
    fields_desc = [
        StrFixedLenField("link_id", None, length=4),
        XByteField("transaction_number", None),
        PacketField("data", None, pkt_cls=BTMesh_Generic_Provisioning_Hdr),
    ]


"""
MESH PROXY LAYER
================================
"""


class BTMesh_Proxy_Hdr(Packet):
    name = "Bluetooth Mesh Proxy PDU"
    fields_desc = [
        BitEnumField(
            "SAR",
            0,
            2,
            {
                0b00: "Data field contains a complete message",
                0b01: "Data field contains the first segment of a message",
                0b10: "Data field contains a continuation segment of a message",
                0b11: "Data field contains the last segment of a message",
            },
        ),
        BitEnumField(
            "message_type",
            0,
            6,
            {
                0x00: "Network PDU",
                0x01: "Mesh Beacon",
                0x02: "Proxy Configuration",
                0x03: "Provisioning PDU",
            },
        ),
    ]


bind_layers(BTMesh_Proxy_Hdr, BTMesh_Provisioning_Hdr, message_type=0x03)


"""
MODEL LAYER
================================

ALL FIELDS IN LITTLE ENDIAN ! 
IF FIELD IS RAW DATA (LIKE StrField), ENDIANESS NEED TO BE TAKEN CARE OF IN LOGIC
"""


"""
class BTMesh_Model_Message(Packet):
    name = "Bluetooth Mesh Model Message"
    fields_desc = [
        ShortEnumField("opcode", None, MESSAGE_MODEL_OPCODES),
    ]

"""


class BTMesh_Model_Message(Packet):
    name = "Bluetooth Mesh Access Message"
    fields_desc = [
        # Size Will be changed in post_build ! size depend on value of first 2 bits
        XShortField("opcode", None),
    ]

    def post_build(self, pkt, pay):
        # The first byte of the packet, we need to determine the size of the opcode based on its first two bits
        first_byte = pkt[0]

        # Determine the size based on the first two bits
        if first_byte & 0b10000000 == 0 and first_byte != 0b01111111:
            sz = 1
        elif first_byte & 0b11000000 == 0b10000000:
            sz = 2
        elif first_byte & 0b11000000 == 0b11000000:
            sz = 3
        else:
            raise ValueError("Invalid opcode format")

        # Modify the opcode field to have the correct size
        pkt = pkt[:sz] + pay  # Rebuild the packet with the correct size

        return pkt

    def do_dissect(self, s):
        first_byte = s[0]

        # Determine the size of the opcode based on the first two bits
        if first_byte & 0b10000000 == 0 and first_byte != 0b01111111:
            field_type = XByteField  # 0xxxxxxx -> sz = 1
        elif first_byte & 0b11000000 == 0b10000000:
            field_type = XShortField  # 10xxxxxx -> sz = 2
        elif first_byte & 0b11000000 == 0b11000000:
            field_type = X3BytesField  # 11xxxxxx -> sz = 3
        else:
            raise ValueError("Invalid opcode format")

        # Set the correct size for the opcode field
        self.fields_desc[0] = field_type("opcode", None)

        # Now call super to perform the actual dissection with the correct size
        return super(BTMesh_Model_Message, self).do_dissect(s)


class BTMesh_Model_Generic_OnOff_Set(Packet):
    name = "Bluetooth Mesh Model Generic OnOff Set"
    fields_desc = [
        ByteEnumField("onoff", None, {0: "off", 1: "on"}),
        ByteField("transaction_id", None),
        ConditionalField(ByteField("transaction_time", None), lambda pkt: len(pkt) > 2),
        ConditionalField(ByteField("delay", None), lambda pkt: len(pkt) > 2),
    ]


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


### CONFIG MESSAGES


class BTMesh_Model_Config_Composition_Data_Get(Packet):
    name = "Bluetooth Mesh Config Model Composition Data Get"
    fields_desc = [ByteField("page", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Composition_Data_Get, opcode=0x8008
)


class BTMesh_Model_Config_Composition_Data_Status(Packet):
    name = "Bluetooth Mesh Config Model Composition Data Status"
    fields_desc = [ByteField("page", None), StrField("data", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Composition_Data_Status, opcode=0x02
)


class BTMesh_Model_Config_Default_TTL_Get(Packet):
    name = "Bluetooth Mesh Config Model Default TTL Get"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Default_TTL_Get, opcode=0x800C)


class BTMesh_Model_Config_Default_TTL_Set(Packet):
    name = "Bluetooth Mesh Config Model Default TTL Set"
    fields_desc = [ByteField("ttl", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Default_TTL_Set, opcode=0x800D)


class BTMesh_Model_Config_Default_TTL_Status(Packet):
    name = "Bluetooth Mesh Config Model Default TTL Status"
    fields_desc = [ByteField("ttl", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Default_TTL_Status, opcode=0x800E)


class BTMesh_Model_Config_Relay_Get(Packet):
    name = "Bluetooth Mesh Config Model Default Relay Get"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Relay_Get, opcode=0x8026)


class BTMesh_Model_Config_Relay_Set(Packet):
    name = "Bluetooth Mesh Config Model Default Relay Set"
    fields_desc = [
        ByteField("relay", None),
        BitField("relay_retransmit_interval_steps", None, 5),
        BitField("relay_retransmit_count", None, 3),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Relay_Set, opcode=0x8027)


class BTMesh_Model_Config_Relay_Status(Packet):
    name = "Bluetooth Mesh Config Model Default Relay Status"
    fields_desc = [
        ByteField("relay", None),
        BitField("relay_retransmit_interval_steps", None, 5),
        BitField("relay_retransmit_count", None, 3),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Relay_Status, opcode=0x8028)


class BTMesh_Model_Config_Publication_Get(Packet):
    name = "Bluetooth Mesh Config Model Publication Get"
    fields_desc = [
        XLEShortField("element_addr", None),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Publication_Get, opcode=0x8018)


class BTMesh_Model_Config_Publication_Set(Packet):
    name = "Bluetooth Mesh Config Model Publication Set"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("publish_addr", None),
        BitField("RFU", 0, 3, tot_size=-2),
        BitField("credential_flag", None, 1),
        XBitField("app_key_index", None, 12, end_tot_size=-2),
        ByteField("publish_ttl", None),
        ByteField("publish_period", None),
        BitField("publish_retransmit_interval_steps", None, 5),
        BitField("publish_retransmit_count", None, 3),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Publication_Set, opcode=0x03)


class BTMesh_Model_Config_Publication_Virtual_Addr_Set(Packet):
    name = "Bluetooth Mesh Config Model Publication Virtual Address Set"
    fields_desc = [
        LEShortField("element_addr", None),
        XNBytesField("publish_addr", None, sz=16),
        BitField("RFU", 0, 3, tot_size=-2),
        BitField("credential_flag", None, 1),
        XBitField("app_key_index", None, 12, end_tot_size=-2),
        ByteField("publish_ttl", None),
        ByteField("publish_period", None),
        BitField("publish_retransmit_interval_steps", None, 5),
        BitField("publish_retransmit_count", None, 3),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Publication_Virtual_Addr_Set,
    opcode=0x801A,
)


class BTMesh_Model_Config_Publication_Status(Packet):
    name = "Bluetooth Mesh Config Model Publication Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        XLEShortField("publish_addr", None),
        BitField("RFU", 0, 3, tot_size=-2),
        BitField("credential_flag", None, 1),
        XBitField("app_key_index", None, 12, end_tot_size=-2),
        ByteField("publish_ttl", None),
        ByteField("publish_period", None),
        BitField("publish_retransmit_interval_steps", None, 5),
        BitField("publish_retransmit_count", None, 3),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Publication_Status, opcode=0x8019)


class BTMesh_Model_Config_Subscription_Add(Packet):
    name = "Bluetooth Mesh Config Model Subscription Add"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("address", None),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Subscription_Add, opcode=0x801B)


class BTMesh_Model_Config_Subscription_Virtual_Addr_Add(Packet):
    name = "Bluetooth Mesh Config Model Subscription Virtual Address Add"
    fields_desc = [
        XLEShortField("element_addr", None),
        XNBytesField("label", None, sz=16),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Subscription_Virtual_Addr_Add,
    opcode=0x8020,
)


class BTMesh_Model_Config_Subscription_Delete(Packet):
    name = "Bluetooth Mesh Config Model Subscription Delete"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("address", None),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Subscription_Delete, opcode=0x801C
)


class BTMesh_Model_Config_Subscription_Virtual_Addr_Delete(Packet):
    name = "Bluetooth Mesh Config Model Subscription Virtual Address Delete"
    fields_desc = [
        XLEShortField("element_addr", None),
        XNBytesField("label", None, sz=16),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Subscription_Virtual_Addr_Delete,
    opcode=0x8021,
)


class BTMesh_Model_Config_Subscription_Overwrite(Packet):
    name = "Bluetooth Mesh Config Subscription Overwrite"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("address", None),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Subscription_Overwrite, opcode=0x801E
)


class BTMesh_Model_Config_Subscription_Virtual_Addr_Overwrite(Packet):
    name = "Bluetooth Mesh Config Subscription Virtual Address Overwrite"
    fields_desc = [
        XLEShortField("element_addr", None),
        XNBytesField("label", None, sz=16),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Subscription_Virtual_Addr_Overwrite,
    opcode=0x801E,
)


class BTMesh_Model_Config_Subscription_Delete_All(Packet):
    name = "Bluetooth Mesh Config Subscription Delete All"
    fields_desc = [
        XLEShortField("element_addr", None),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Subscription_Delete_All, opcode=0x801D
)


class BTMesh_Model_Config_Subscription_Status(Packet):
    name = "Bluetooth Mesh Config Subscription Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        XLEShortField("address", None),
        StrField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Subscription_Status, opcode=0x801F
)


class BTMesh_Model_Config_SIG_Model_Subscription_Get(Packet):
    name = "Bluetooth Mesh Config SIG Model Subscription Get"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_SIG_Model_Subscription_Get, opcode=0x8029
)


class BTMesh_Model_Config_SIG_Model_Subscription_List(Packet):
    name = "Bluetooth Mesh Config SIG Model Subscription List"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        XLEShortField("model_identifier", None),
        StrField("addresses", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_SIG_Model_Subscription_List, opcode=0x802A
)


class BTMesh_Model_Config_Vendor_Model_Subscription_Get(Packet):
    name = "Bluetooth Mesh Config Vendor Model Subscription Get"
    fields_desc = [
        XLEShortField("element_addr", None),
        LEIntField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Vendor_Model_Subscription_Get,
    opcode=0x802B,
)


class BTMesh_Model_Config_Vendor_Model_Subscription_List(Packet):
    name = "Bluetooth Mesh Config Vendor Subscription List"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        LEIntField("model_identifier", None),
        StrField("address", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Vendor_Model_Subscription_List,
    opcode=0x802C,
)


class BTMesh_Model_Config_Net_Key_Add(Packet):
    name = "Bluetooth Mesh Model Config Model NetKey Add"
    fields_desc = [
        XLEShortField("net_key_index", None),
        XNBytesField("net_key", None, sz=16),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Net_Key_Add, opcode=0x8040)


class BTMesh_Model_Config_Net_Key_Update(Packet):
    name = "Bluetooth Mesh Model Config Model NetKey Update"
    fields_desc = [
        XLEShortField("net_key_index", None),
        XNBytesField("net_key", None, sz=16),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Net_Key_Update, opcode=0x8045)


class BTMesh_Model_Config_Net_Key_Delete(Packet):
    name = "Bluetooth Mesh Model Config NetKey Delete"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Net_Key_Update, opcode=0x8041)


class BTMesh_Model_Config_Net_Key_Status(Packet):
    name = "Bluetooth Mesh Model Config NetKey Status"
    fields_desc = [ByteField("status", None), XLEShortField("net_key_index", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Net_Key_Status, opcode=0x8044)


class BTMesh_Model_Config_Net_Key_List(Packet):
    name = "Bluetooth Mesh Model Config NetKey List"
    fields_desc = [StrField("net_key_indexes", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Net_Key_List, opcode=0x8043)


class BTMesh_Model_Config_App_Key_Add(Packet):
    name = "Bluetooth Mesh Model Config AppKey Add"
    fields_desc = [
        # weird formatting so raw data, handle of dissection/endianess in logic
        StrFixedLenField("net_key_index_and_app_key_index", None, length=3),
        XNBytesField("app_key", None, sz=16),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_Add, opcode=0x00)


class BTMesh_Model_Config_App_Key_Update(Packet):
    name = "Bluetooth Mesh Model Config AppKey Update"
    fields_desc = [
        # weird formatting so raw data, handle of dissection/endianess in logic
        StrFixedLenField("net_key_index_and_app_key_index", None, length=3),
        XNBytesField("app_key", None, sz=16),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_Update, opcode=0x01)


class BTMesh_Model_Config_App_Key_Delete(Packet):
    name = "Bluetooth Mesh Model Config AppKey Delete"
    fields_desc = [
        # weird formatting so raw data, handle of dissection/endianess in logic
        StrFixedLenField("net_key_index_and_app_key_index", None, length=3),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_Delete, opcode=0x8000)


class BTMesh_Model_Config_App_Key_Status(Packet):
    name = "Bluetooth Mesh Model Config AppKey Status"
    fields_desc = [
        ByteField("status", None),
        # weird formatting so raw data, handle of dissection/endianess in logic
        StrFixedLenField("net_key_index_and_app_key_index", None, length=3),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_Status, opcode=0x8003)


class BTMesh_Model_Config_App_Key_Get(Packet):
    name = "Bluetooth Mesh Model Config AppKey Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_Get, opcode=0x8001)


class BTMesh_Model_Config_App_Key_List(Packet):
    name = "Bluetooth Mesh Model Config AppKey List"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        StrField("app_key_indexes", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_App_Key_List, opcode=0x8002)


class BTMesh_Model_Config_Node_Identity_Get(Packet):
    name = "Bluetooth Mesh Model Config Node Identity Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Node_Identity_Get, opcode=0x8046)


class BTMesh_Model_Config_Node_Identity_Set(Packet):
    name = "Bluetooth Mesh Model Config Node Identity Set"
    fields_desc = [XLEShortField("net_key_index", None), ByteField("identity", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Node_Identity_Set, opcode=0x8047)


class BTMesh_Model_Config_Node_Identity_Status(Packet):
    name = "Bluetooth Mesh Model Config Node Identity Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        ByteField("identity", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Node_Identity_Status, opcode=0x8048
)


class BTMesh_Model_Config_Model_App_Bind(Packet):
    name = "Bluetooth Mesh Model Config Model App Bind"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("app_key_index", None),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Model_App_Bind, opcode=0x803D)


class BTMesh_Model_Config_Model_App_Unbind(Packet):
    name = "Bluetooth Mesh Model Config Model App Bind"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("app_key_index", None),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Model_App_Unbind, opcode=0x803F)


class BTMesh_Model_Config_Model_App_Status(Packet):
    name = "Bluetooth Mesh Model Config Model App Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        XLEShortField("app_key_index", None),
        StrField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Model_App_Status, opcode=0x803E)


class BTMesh_Model_Config_SIG_Model_App_Get(Packet):
    name = "Bluetooth Mesh Model Config SIG Model App Get"
    fields_desc = [
        XLEShortField("element_addr", None),
        XLEShortField("model_identifier", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_SIG_Model_App_Get, opcode=0x804B)


class BTMesh_Model_Config_SIG_Model_App_List(Packet):
    name = "Bluetooth Mesh Model Config SIG Model App List"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        XLEShortField("model_identifier", None),
        StrField("app_key_indexes", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_SIG_Model_App_List, opcode=0x804C)


class BTMesh_Model_Config_Vendor_Model_App_Get(Packet):
    name = "Bluetooth Mesh Model Config Vendor Model App Get"
    fields_desc = [
        XLEShortField("element_addr", None),
        LEIntField("model_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Vendor_Model_App_Get, opcode=0x804D
)


class BTMesh_Model_Config_Vendor_Model_App_List(Packet):
    name = "Bluetooth Mesh Model Config Vendor App List"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("element_addr", None),
        LEIntField("model_identifier", None),
        StrField("app_key_indexes", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Vendor_Model_App_List, opcode=0x804E
)


class BTMesh_Model_Config_Node_Reset(Packet):
    name = "Bluetooth Mesh Model Config Node Reset"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Node_Reset, opcode=0x8049)


class BTMesh_Model_Config_Node_Reset_Status(Packet):
    name = "Bluetooth Mesh Model Config Node Reset Status"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Node_Reset_Status, opcode=0x804A)


class BTMesh_Model_Config_Friend_Get(Packet):
    name = "Bluetooth Mesh Model Config Friend Get"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Friend_Get, opcode=0x800F)


class BTMesh_Model_Config_Friend_Status(Packet):
    name = "Bluetooth Mesh Model Config Friend Status"
    fields_desc = [ByteField("friend", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Config_Friend_Status, opcode=0x8011)


class BTMesh_Model_Config_Key_Refresh_Phase_Get(Packet):
    name = "Bluetooth Mesh Model Config Key Refresh Phase Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Key_Refresh_Phase_Get, opcode=0x8015
)


class BTMesh_Model_Config_Key_Refresh_Phase_Set(Packet):
    name = "Bluetooth Mesh Model Config Key Refresh Phase Set"
    fields_desc = [XLEShortField("net_key_index", None), ByteField("transition", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Key_Refresh_Phase_Set, opcode=0x8016
)


class BTMesh_Model_Config_Key_Refresh_Phase_Status(Packet):
    name = "Bluetooth Mesh Model Config Key Refresh Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        ByteField("phase", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Key_Refresh_Phase_Status, opcode=0x8017
)


class BTMesh_Config_Model_Heartbeat_Publication_Get(Packet):
    name = "Bluetooth Mesh Config Model Heartbeat Publication Get"


bind_layers(
    BTMesh_Model_Message, BTMesh_Config_Model_Heartbeat_Publication_Get, opcode=0x8038
)


class BTMesh_Config_Model_Heartbeat_Publication_Set(Packet):
    name = "Bluetooth Mesh Config Model Heartbeat Publication Set"
    fields_desc = [
        XLEShortField("destination", None),
        ByteField("count_log", None),
        ByteField("period_log", None),
        ByteField("ttl", None),
        FlagsField("features", None, 4, ["relay", "proxy", "friend", "low_power"]),
        BitField("RFU", 0, 12),
        XLEShortField("net_key_index", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Config_Model_Heartbeat_Publication_Set, opcode=0x8039
)


class BTMesh_Config_Model_Heartbeat_Publication_Status(Packet):
    name = "Bluetooth Mesh Config Model Heartbeat Publication Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("destination", None),
        ByteField("count_log", None),
        ByteField("period_log", None),
        ByteField("ttl", None),
        FlagsField("features", None, 4, ["relay", "proxy", "friend", "low_power"]),
        BitField("RFU", 0, 12),
        XLEShortField("net_key_index", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Config_Model_Heartbeat_Publication_Status, opcode=0x06
)


class BTMesh_Config_Model_Heartbeat_Subscription_Get(Packet):
    name = "Bluetooth Mesh Config Model Heartbeat Subscription Get"


bind_layers(
    BTMesh_Model_Message, BTMesh_Config_Model_Heartbeat_Subscription_Get, opcode=0x303A
)


class BTMesh_Config_Model_Heartbeat_Subscription_Set(Packet):
    name = "Blutooth Mesh Config Heartbeat Subscription Set"
    fields_desc = [
        XLEShortField("source", None),
        XLEShortField("destination", None),
        ByteField("period_log", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Config_Model_Heartbeat_Subscription_Set, opcode=0x803B
)


class BTMesh_Config_Model_Heartbeat_Subscription_Status(Packet):
    name = "Bluetooth Mesh Config Model Heartbeat Subscription Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("source", None),
        XLEShortField("destination", None),
        ByteField("period_log", None),
        ByteField("count_log", None),
        ByteField("min_hops", None),
        ByteField("max_hops", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Config_Model_Heartbeat_Subscription_Status,
    opcode=0x803C,
)


class BTMesh_Model_Config_Low_Power_Node_Poll_Timemout_Get(Packet):
    name = "Bluetooth Mesh Config Model Low Power Node Poll Timeout Get"
    fields_desc = [XLEShortField("lpn_addr", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Low_Power_Node_Poll_Timemout_Get,
    opcode=0x802D,
)


class BTMesh_Model_Config_Low_Power_Node_Poll_Timemout_Status(Packet):
    name = "Bluetooth Mesh Config Model Low Power Node Poll Timeout Status"
    fields_desc = [
        XLEShortField("lpn_addr", None),
        ThreeBytesField("poll_timeout", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Config_Low_Power_Node_Poll_Timemout_Status,
    opcode=0x802E,
)


class BTMesh_Model_Config_Network_Transmit_Get(Packet):
    name = "Bluetooth Mesh Model Config Network Transmit Get"


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Network_Transmit_Get, opcode=0x8023
)


class BTMesh_Model_Config_Network_Transmit_Set(Packet):
    name = "Bluetooth Mesh Model Config Network Transmit Set"
    fields_desc = [
        BitField("network_transmit_interval_steps", None, 5),
        BitField("network_transmit_count", None, 3),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Network_Transmit_Set, opcode=0x8024
)


class BTMesh_Model_Config_Network_Transmit_Status(Packet):
    name = "Bluetooth Mesh Model Config Network Transmit Status"

    fields_desc = [
        BitField("network_transmit_interval_steps", None, 5),
        BitField("network_transmit_count", None, 3),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Config_Network_Transmit_Status, opcode=0x8025
)

### HEALTH MESSAGES


class BTMesh_Model_Health_Current_Status(Packet):
    name = "Bluetooth Mesh Model Health Current Status"
    fields_desc = [
        ByteField("test_id", None),
        XLEShortField("company_id", None),
        StrField("fault_array", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Current_Status, opcode=0x04)


class BTMesh_Model_Health_Fault_Get(Packet):
    name = "Bluetooth mesh Model Health Fault Get"
    fields_desc = [XLEShortField("company_id", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Fault_Get, opcode=0x8031)


class BTMesh_Model_Health_Fault_Clear_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Health Fault Clear Unacknowledged"
    fields_desc = [XLEShortField("company_id", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Health_Fault_Clear_Unacknowledged, opcode=0x8030
)


class BTMesh_Model_Health_Fault_Clear(Packet):
    name = "Bluetooth Mesh Model Health Fault Clear Unacknowledged"
    fields_desc = [XLEShortField("company_id", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Fault_Clear, opcode=0x802F)


class BTMesh_Model_Health_Fault_Test_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Health Fault Test Unacknowledged"
    fields_desc = [ByteField("test_id", None), XLEShortField("company_id", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Health_Fault_Test_Unacknowledged, opcode=0x8033
)


class BTMesh_Model_Health_Fault_Status(Packet):
    name = "Bluetooth Mesh Model Health Status"
    fields_desc = [
        ByteField("test_id", None),
        XLEShortField("company_id", None),
        StrField("fault_array", None),
    ]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Fault_Status, opcode=0x05)


class BTMesh_Model_Health_Period_Get(Packet):
    name = "Bluetooth Mesh Model Health Period Get"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Period_Get, opcode=0x8034)


class BTMesh_Model_Health_Period_Set_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Health Period Set Unacknowledged"
    fields_desc = [ByteField("fast_period_divisor", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Health_Period_Set_Unacknowledged, opcode=0x8036
)


class BTMesh_Model_Health_Period_Set(Packet):
    name = "Bluetooth Mesh Model Health Period Set"
    fields_desc = [ByteField("fast_period_divisor", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Period_Set, opcode=0x8035)


class BTMesh_Model_Health_Period_Status(Packet):
    name = "Bluetooth Mesh Model Health Period Status"
    fields_desc = [ByteField("fast_period_divisor", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Period_Status, opcode=0x8037)


class BTMesh_Model_Health_Attention_Get(Packet):
    name = "Bluetooth Mesh Model Health Attention Get"


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Attention_Get, opcode=0x8004)


class BTMesh_Model_Health_Attention_Set(Packet):
    name = "Bluetooth Mesh Model Health Attention Set"
    fields_desc = [ByteField("attention", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Attention_Set, opcode=0x8005)


class BTMesh_Model_Health_Attention_Set_Unacknowledged(Packet):
    name = "Bluetooth Mesh Model Health Attention Set Unacknowledged"
    fields_desc = [ByteField("attention", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Health_Attention_Set_Unacknowledged,
    opcode=0x8006,
)


class BTMesh_Model_Health_Attention_Status(Packet):
    name = "Bluetooth Mesh Model Health Attention Status"
    fields_desc = [ByteField("attention", None)]


bind_layers(BTMesh_Model_Message, BTMesh_Model_Health_Attention_Status, opcode=0x8007)

### DIRECTED FORWARDING MODEL


class BTMesh_Model_Directed_Forwarding_Directed_Control_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Control Get"
    fields_desc = [
        XLEShortField("net_key_index", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Get,
    opcode=0x807B,
)


class BTMesh_Model_Directed_Forwarding_Control_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Control Set"
    fields_desc = [
        XLEShortField("net_key_index", None),
        ByteEnumField(
            "directed_forwarding",
            None,
            {0x00: "Directed Forwarding Disable", 0x01: "Directed Forwarding Enable"},
        ),
        ByteEnumField(
            "directed_relay",
            None,
            {0x00: "Directed Relay Disable", 0x01: "Directed Relay Enable"},
        ),
        ByteEnumField(
            "directed_proxy",
            None,
            {0x00: "Directed Proxy Disable", 0x01: "Directed Proxy Enable"},
        ),
        ByteEnumField(
            "directed_proxy_use_directed_default",
            None,
            {
                0x00: "Directed Proxy Use Directed Default Disable",
                0x01: "Directed Proxy Used Directed Default Enable",
                0xFF: "Do not process",
            },
        ),
        ByteEnumField(
            "directed_friend",
            None,
            {
                0x00: "Directed Friend Disable",
                0x01: "Directed Friend Enable",
                0xFF: "Do not process",
            },
        ),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Directed_Forwarding_Control_Set, opcode=0x807C
)


class BTMesh_Model_Directed_Forwarding_Control_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Control Status"
    fields_desc = [
        XLEShortField("net_key_index", None),
        ByteEnumField(
            "directed_forwarding",
            None,
            {0x00: "Directed Forwarding Disable", 0x01: "Directed Forwarding Enable"},
        ),
        ByteEnumField(
            "directed_relay",
            None,
            {0x00: "Directed Relay Disable", 0x01: "Directed Relay Enable"},
        ),
        ByteEnumField(
            "directed_proxy",
            None,
            {0x00: "Directed Proxy Disable", 0x01: "Directed Proxy Enable"},
        ),
        ByteEnumField(
            "directed_proxy_use_directed_default",
            None,
            {
                0x00: "Directed Proxy Use Directed Default Disable",
                0x01: "Directed Proxy Used Directed Default Enable",
                0xFF: "Do not process",
            },
        ),
        ByteEnumField(
            "directed_friend",
            None,
            {
                0x00: "Directed Friend Disable",
                0x01: "Directed Friend Enable",
                0xFF: "Do not process",
            },
        ),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Directed_Forwarding_Control_Status, opcode=0x807D
)


class BTMesh_Model_Directed_Forwarding_Path_Metric_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Metric Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Metric_Get,
    opcode=0x807E,
)


class BTMesh_Model_Directed_Forwarding_Path_Metric_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Metric Set"
    fields_desc = [
        XLEShortField("net_key_index", None),
        BitField("prohibited", 0, 3),
        BitField("path_lifetime", None, 2),
        BitField("path_metric_type", None, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Metric_Set,
    opcode=0x807F,
)


class BTMesh_Model_Directed_Forwarding_Path_Metric_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Metric Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        BitField("prohibited", 0, 3),
        BitField("path_lifetime", None, 2),
        BitField("path_metric_type", None, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Metric_Status,
    opcode=0x8080,
)


class BTMesh_Model_Discovery_Table_Capabilities_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Discovery Table Capabilities Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Discovery_Table_Capabilities_Get, opcode=0x8081
)


class BTMesh_Model_Directed_Forwarding_Discovery_Table_Capabilities_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Discovery Table Capabilities Get"
    fields_desc = [
        XLEShortField("net_key_index", None),
        ByteField("max_concurrent_init", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Discovery_Table_Capabilities_Set,
    opcode=0x8082,
)


class BTMesh_Model_Directed_Forwarding_Discovery_Table_Capabilities_Status(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Discovery Table Capabilities Status"
    )
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        ByteField("max_concurrent_init", None),
        ByteField("max_discovery_table_entries_count", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Discovery_Table_Capabilities_Status,
    opcode=0x8083,
)


class BTMesh_Model_Directed_Forwarding_Table_Add(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Add"
    fields_desc = [
        BitField(
            "backward_path_validated_flag",
            None,
            1,
        ),
        BitField("unicast_destination_flag", None, 1, tot_size=-2),
        BitField("prohibited", 0, 2),
        XBitField("net_key_index", None, 12, end_tot_size=-2),
        PacketField(
            "path_origin_unicast_addr_range",
            None,
            pkt_cls=LEUnicastAddr,
        ),
        ConditionalField(
            PacketField(
                "path_target_unicast_addr_range",
                None,
                pkt_cls=LEUnicastAddr,
            ),
            lambda pkt: pkt.unicast_destination_flag == 0x1,
        ),
        ConditionalField(
            XLEShortField("multicast_destination", None),
            lambda pkt: pkt.unicast_destination_flag == 0x0,
        ),
        XLEShortField("bearer_toward_path_origin", 0),
        XLEShortField("bearer_toward_path_target", 0),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Directed_Forwarding_Table_Add, opcode=0x8084
)


class BTMesh_Model_Directed_Forwarding_Table_Delete(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Delete"
    fields_desc = [
        XLEShortField("net_key_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Directed_Forwarding_Table_Delete, opcode=0x8085
)


class BTMesh_Model_Directed_Forwarding_Table_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
    ]


bind_layers(
    BTMesh_Model_Message, BTMesh_Model_Directed_Forwarding_Table_Status, opcode=0x8086
)


class BTMesh_Model_Directed_Forwarding_Table_Dependents_Add(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Dependents Add"
    fields_desc = [
        XLEShortField("net_key_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
        ByteField("dependent_origin_unicast_addr_range_list_size", 0),  # set manually !
        ByteField("dependent_target_unicast_addr_range_list_size", 0),  # set manually
        PacketListField(
            "dependent_origin_unicast_addr_range_list",
            None,
            pkt_cls=LEUnicastAddr,
            count_from=lambda pkt: pkt.dependent_origin_unicast_addr_range_list_size,
        ),
        PacketListField(
            "dependent_target_unicast_addr_range_list",
            None,
            pkt_cls=LEUnicastAddr,
            count_from=lambda pkt: pkt.dependent_target_unicast_addr_range_list_size,
        ),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Add,
    opcode=0x8087,
)


class BTMesh_Model_Directed_Forwarding_Table_Dependents_Delete(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Dependents Delete"
    fields_desc = [
        XLEShortField("net_key_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
        ByteField("dependent_origin_list_size", 0),  # set manually
        ByteField("dependent_target_list_size", 0),  # set manually
        FieldListField(
            "dependent_origin_list",
            None,
            field=XLEShortField("", None),
            count_from=lambda pkt: pkt.dependent_origin_list_size,
        ),
        FieldListField(
            "dependent_target_list",
            None,
            field=XLEShortField("", None),
            count_from=lambda pkt: pkt.dependent_target_list_size,
        ),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Delete,
    opcode=0x8088,
)


class BTMesh_Model_Directed_Forwarding_Table_Dependents_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Dependents Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Status,
    opcode=0x8089,
)


class BTMesh_Model_Directed_Forwarding_Table_Entries_Count_Get(Packet):
    name = "Blutooth Mesh Model Directed Forwarding Forwarding Table Entries Count Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Count_Get,
    opcode=0x808C,
)


class BTMesh_Model_Directed_Forwarding_Table_Entries_Count_Status(Packet):
    name = (
        "Blutooth Mesh Model Directed Forwarding Forwarding Table Entries Count Status"
    )
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        XLEShortField("forwarding_table_update_identifier", None),
        XLEShortField("fixed_path_entries_count", None),
        XLEShortField("non_fixed_path_entries_count", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Count_Status,
    opcode=0x808D,
)


class BTMesh_Model_Directed_Forwarding_Table_Entries_Get(Packet):
    name = "Blutooth Mesh Model Directed Forwarding Forwarding Table Entries Get"
    fields_desc = [
        BitField("filter_mask", 0, 4, tot_size=-2),
        XBitField("net_key_index", 0, 12, end_tot_size=-2),
        XLEShortField("start_index", None),
        ConditionalField(
            XLEShortField("path_origin", None),
            lambda pkt: pkt.filter_mask & 0b0100 == 0b0100,
        ),
        ConditionalField(
            XLEShortField("destination", None),
            lambda pkt: pkt.filter_mask & 0b1000 == 0b1000,
        ),
        XLEShortField("forwarding_table_update_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Get,
    opcode=0x808E,
)


class BTMesh_Model_Directed_Forwarding_Table_Entries_Status(Packet):
    name = "Blutooth Mesh Model Directed Forwarding Forwarding Table Entries Status"
    fields_desc = [
        ByteField("status", None),
        BitField("filter_mask", 0, 4, tot_size=-2),
        XBitField("net_key_index", 0, 12, end_tot_size=-2),
        XLEShortField("start_index", None),
        ConditionalField(
            XLEShortField("path_origin", None),
            lambda pkt: pkt.filter_mask & 0b0100 == 0b0100,
        ),
        ConditionalField(
            XLEShortField("destination", None),
            lambda pkt: pkt.filter_mask & 0b1000 == 0b1000,
        ),
        ConditionalField(
            XLEShortField("forwarding_table_update_identifier", None),
            lambda pkt: pkt.status == 0x00 or pkt.status == 0x14,
        ),
        PacketListField(
            "forwarding_table_entry_list", [], pkt_cls=ForwardingTableEntry
        ),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Entries_Status,
    opcode=0x808F,
)


class BTMesh_Model_Directed_Forwarding_Table_Dependents_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Dependents Get"
    fields_desc = [
        BitField("prohibited", 0, 1, tot_size=-2),
        BitField("fixed_path_flag", 0, 1),
        BitField("dependents_list_mask", 0, 2),
        XBitField("net_key_index", 0, 12, end_tot_size=-2),
        XLEShortField("start_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
        XLEShortField("forwarding_table_update_identifier", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get,
    opcode=0x808A,
)


class BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Forwarding Table Dependents Get Status"
    fields_desc = [
        ByteField("status", 0),
        BitField("prohibited", 0, 1, tot_size=-2),
        BitField("fixed_path_flag", 0, 1),
        BitField("dependents_list_mask", 0, 2),
        XBitField("net_key_index", 0, 12, end_tot_size=-2),
        XLEShortField("start_index", None),
        XLEShortField("path_origin", None),
        XLEShortField("destination", None),
        ConditionalField(
            XLEShortField("forwarding_table_update_identifier", None),
            lambda pkt: pkt.status == 0x00 or pkt.status == 0x14,
        ),
        ConditionalField(
            ByteField("dependent_origin_unicast_addr_range_list_size", 0),
            lambda pkt: pkt.status == 0x00,
        ),  # set manually !
        ConditionalField(
            ByteField("dependent_target_unicast_addr_range_list_size", 0),
            lambda pkt: pkt.status == 0x00,
        ),  # set manually !
        ConditionalField(
            PacketListField(
                "dependent_origin_unicast_addr_range_list",
                [],
                pkt_cls=LEUnicastAddr,
                count_from=lambda pkt: pkt.dependent_origin_unicast_addr_range_list_size,
            ),
            lambda pkt: pkt.status == 0x00
            and pkt.dependent_origin_unicast_addr_range_list_size > 0,
        ),
        ConditionalField(
            PacketListField(
                "dependent_target_unicast_addr_range_list",
                [],
                pkt_cls=LEUnicastAddr,
                count_from=lambda pkt: pkt.dependent_target_unicast_addr_range_list_size,
            ),
            lambda pkt: pkt.status == 0x00
            and pkt.dependent_target_unicast_addr_range_list_size > 0,
        ),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Table_Dependents_Get_Status,
    opcode=0x808B,
)


class BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Wanted Lanes Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Get,
    opcode=0x8090,
)


class BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Wanted Lanes Set"
    fields_desc = [
        XLEShortField("net_key_index", None),
        ByteField("wanted_lanes", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Set,
    opcode=0x8091,
)


class BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Wanted Lanes Status"
    fields_desc = [
        ByteField("status", 0),
        XLEShortField("net_key_index", None),
        ByteField("wanted_lanes", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Wanted_Lanes_Status,
    opcode=0x8092,
)


class BTMesh_Model_Directed_Forwarding_Two_Way_Path_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Two Way Path Get"
    fields_desc = [XLEShortField("net_key_index", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Two_Way_Path_Get,
    opcode=0x8093,
)


class BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Two Way Path Set"
    fields_desc = [
        XLEShortField("net_key_index", None),
        BitEnumField("two_way_path", 1, 1, {0: "One way path", 1: "Two ways path"}),
        BitField("prohibited", 0, 7),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Two_Way_Path_Set,
    opcode=0x8094,
)


class BTMesh_Model_Directed_Forwarding_Two_Way_Path_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Two Way Path Status"
    fields_desc = [
        ByteField("status", 0),
        XLEShortField("net_key_index", None),
        BitEnumField("two_way_path", 1, 1, {0: "One way path", 1: "Two ways path"}),
        BitField("prohibited", 0, 7),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Two_Way_Path_Status,
    opcode=0x8095,
)


class BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Echo Interval Get"
    fields_desc = [
        XLEShortField("net_key_index", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Get,
    opcode=0x8096,
)


class BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Echo Interval Set"
    fields_desc = [
        XLEShortField("net_key_index", None),
        ByteField("unicast_echo_interval", None),
        ByteField("multicast_echo_interval", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Set,
    opcode=0x8097,
)


class BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Echo Interval Status"
    fields_desc = [
        ByteField("status", None),
        XLEShortField("net_key_index", None),
        ByteField("unicast_echo_interval", None),
        ByteField("multicast_echo_interval", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Echo_Interval_Status,
    opcode=0x8098,
)


class BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Network Trasmit Get"


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Get,
    opcode=0x8099,
)


class BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Network Trasmit Set"
    fields_desc = [
        BitField("directed_network_transmit_interval_steps", 0, 5),
        BitField("directed_network_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Set,
    opcode=0x809A,
)


class BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Network Trasmit Status"
    fields_desc = [
        BitField("directed_network_transmit_interval_steps", 0, 5),
        BitField("directed_network_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Network_Transmit_Status,
    opcode=0x809B,
)


class BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Relay Retransmit Get"


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Get,
    opcode=0x809C,
)


class BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Relay Retransmit Get"
    fields_desc = [
        BitField("directed_relay_retransmit_interval_steps", 0, 5),
        BitField("directed_relay_retransmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Set,
    opcode=0x809D,
)


class BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Relay Retransmit Status"
    fields_desc = [
        BitField("directed_relay_retransmit_interval_steps", 0, 5),
        BitField("directed_relay_retransmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Relay_Retransmit_Status,
    opcode=0x809E,
)


class BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding RSSI Threshold Get"


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Get,
    opcode=0x809F,
)


class BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding RSSI Threshold Set"
    fields_desc = [ByteField("rssi_margin", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Set,
    opcode=0x80A0,
)


class BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding RSSI Threshold Set"
    fields_desc = [
        ByteField("default_rssi_threshold", None),
        ByteField("rssi_margin", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Rssi_Threshold_Status,
    opcode=0x80A1,
)

class BTMesh_Model_Directed_Forwarding_Directed_Paths_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Paths Get"


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Paths_Get,
    opcode=0x80A2,
)


class BTMesh_Model_Directed_Forwarding_Directed_Paths_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Paths Status"
    fields_desc = [
        XLEShortField("directed_node_paths", None),
        XLEShortField("directed_relay_paths", None),
        XLEShortField("directed_proxy_paths", None),
        XLEShortField("directed_friend_paths", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Paths_Status,
    opcode=0x80A3,
)


class BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Publish Policy Get"
    fields_desc = [XLEShortField("element_addr", None), StrField("model_id", None)]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Get,
    opcode=0x80A4,
)


class BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Publish Policy Get"
    fields_desc = [
        XByteField("directed_publish_policy", None),
        XLEShortField("element_addr", None),
        StrField("model_id", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Set,
    opcode=0x80A5,
)


class BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Publish Policy Status"
    fields_desc = [
        ByteField("status", None),
        XByteField("directed_publish_policy", None),
        XLEShortField("element_addr", None),
        StrField("model_id", None),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Publish_Policy_Status,
    opcode=0x80A6,
)


class BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Get(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Discovery Timing Control Get"


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Get,
    opcode=0x80A7,
)


class BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Set(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Path Discovery Timing Control Set"
    fields_desc = [
        LEShortField("path_monitoring_interval", None),
        LEShortField("path_discovery_retry_interval", None),
        BitField("prohibited", 0, 6),
        BitField("lane_discovery_guard_interval", 0, 1),
        BitField("path_discovery_interval", 0, 1),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Set,
    opcode=0x80A8,
)


class BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Status(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Path Discovery Timing Control Status"
    )
    fields_desc = [
        LEShortField("path_monitoring_interval", None),
        LEShortField("path_discovery_retry_interval", None),
        BitField("prohibited", 0, 6),
        BitField("lane_discovery_guard_interval", 0, 1),
        BitField("path_discovery_interval", 0, 1),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Path_Discovery_Timing_Control_Status,
    opcode=0x80A9,
)


class BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Get(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Directed Control Network Transmit Get"
    )


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Get,
    opcode=0x80AB,
)


class BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Set(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Directed Control Network Transmit Get"
    )
    fields_desc = [
        BitField("directed_control_network_transmit_interval_steps", 0, 5),
        BitField("directed_control_network_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Set,
    opcode=0x80AC,
)


class BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Control Network Transmit Status"
    fields_desc = [
        BitField("directed_control_network_transmit_interval_steps", 0, 5),
        BitField("directed_control_network_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Network_Transmit_Status,
    opcode=0x80AD,
)

#####


class BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Get(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Directed Control Relay Transmit Get"
    )


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Get,
    opcode=0x80AE,
)


class BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Set(Packet):
    name = (
        "Bluetooth Mesh Model Directed Forwarding Directed Control Relay Transmit Get"
    )
    fields_desc = [
        BitField("directed_control_relay_transmit_interval_steps", 0, 5),
        BitField("directed_control_relay_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Set,
    opcode=0x80AF,
)


class BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Status(Packet):
    name = "Bluetooth Mesh Model Directed Forwarding Directed Control Relay Transmit Status"
    fields_desc = [
        BitField("directed_control_relay_transmit_interval_steps", 0, 5),
        BitField("directed_control_relay_transmit_count", 0, 3),
    ]


bind_layers(
    BTMesh_Model_Message,
    BTMesh_Model_Directed_Forwarding_Directed_Control_Relay_Transmit_Status,
    opcode=0x80B0,
)


### SOLICITATION PDU RPL (REPLAY PROTECTION LIST MGMT) MESSAGES


class BTMesh_Model_Solicitation_Pdu_Rpl_Items_Clear(Packet):
    name = "Blutooth Mesh Model Solicitation PDU RPL Items Clear"
    fields_desc = [
        PacketField("address_range", None,pkt_cls=LEUnicastAddr)
    ]

bind_layers(BTMesh_Model_Message, BTMesh_Model_Solicitation_Pdu_Rpl_Items_Clear, opcode=0x8078)

class BTMesh_Model_Solicitation_Pdu_Rpl_Items_Clear_Unacknowledged(Packet):
    name = "Blutooth Mesh Model Solicitation PDU RPL Items Clear Unacknowledged"
    fields_desc = [
        PacketField("address_range", None,pkt_cls=LEUnicastAddr)
    ]

bind_layers(BTMesh_Model_Message, BTMesh_Model_Solicitation_Pdu_Rpl_Items_Clear, opcode=0x8079)


class BTMesh_Model_Solicitation_Pdu_Rpl_Items_Status(Packet):
    name = "Blutooth Mesh Model Solicitation PDU RPL Items Status"
    fields_desc = [
        PacketField("address_range", None,pkt_cls=LEUnicastAddr)
    ]

bind_layers(BTMesh_Model_Message, BTMesh_Model_Solicitation_Pdu_Rpl_Items_Clear, opcode=0x807A)


### SAR Configuration (Segment and Reassembly) MESSAGES


class BTMesh_SAR_Transmitter_Get(Packet):
    name = "Bluetooth Mesh Model SAR Transmitter Get"

bind_layers(BTMesh_Model_Message, BTMesh_SAR_Transmitter_Get, opcode=0x806C)

class BTMesh_SAR_Transmitter_Set(Packet):
    name = "Bluetooth Mesh Model SAR Transmitter Set"
    fields_desc = [
        BitField("sar_unicast_retransmissions_count",0, 4),
        BitField("sar_segment_interval_step", 0,4),
        BitField("sar_unicast_restransmissions_interval_step", 0,4),
        BitField("sar_unicast_restransmissions_without_progess_count", 0,4),
        BitField("sar_multicast_retransmissions_count", 0,4),
        BitField("sar_unicast_retransmissions_interval_increment",0,4),
        BitField("RFU", 0,4),
        BitField("sar_multicast_retransmissions_interval_step", 0,4)
    ]


bind_layers(BTMesh_Model_Message, BTMesh_SAR_Transmitter_Set, opcode=0x806D)

class BTMesh_SAR_Transmitter_Status(Packet):
    name = "Bluetooth Mesh Model SAR Transmitter Status"
    fields_desc = [
        BitField("sar_unicast_retransmissions_count",0, 4),
        BitField("sar_segment_interval_step", 0,4),
        BitField("sar_unicast_restransmissions_interval_step", 0,4),
        BitField("sar_unicast_restransmissions_without_progess_count", 0,4),
        BitField("sar_multicast_retransmissions_count", 0,4),
        BitField("sar_unicast_retransmissions_interval_increment",0,4),
        BitField("RFU", 0,4),
        BitField("sar_multicast_retransmissions_interval_step", 0,4)
    ]


bind_layers(BTMesh_Model_Message, BTMesh_SAR_Transmitter_Status, opcode=0x806E)

class BTMesh_SAR_Receiver_Get(Packet):
    name = "Bluetooth Mesh Model SAR Receiver Get"


bind_layers(BTMesh_Model_Message, BTMesh_SAR_Receiver_Get, opcode=0x806F)

class BTMesh_SAR_Receiver_Set(Packet):
    name = "Bluetooth Mesh Model SAR Receiver Set"
    fields_desc = [
        BitField("sar_acknowledgment_delay_increment", 0, 3),
        BitField("sar_segments_threshold", 0, 5),
        BitField("sar_receiver_segment_interval_step", 0, 4),
        BitField("sar_discard_timout", 0, 4),
        BitField("RFU", 0, 6),
        BitField("sar_acknowledgment_retransmission_count", 0,2)
    ]

bind_layers(BTMesh_Model_Message, BTMesh_SAR_Receiver_Set, opcode=0x8070)

class BTMesh_SAR_Receiver_Status(Packet):
    name = "Bluetooth Mesh Model SAR Receiver Status"
    fields_desc = [
        BitField("sar_acknowledgment_delay_increment", 0, 3),
        BitField("sar_segments_threshold", 0, 5),
        BitField("sar_receiver_segment_interval_step", 0, 4),
        BitField("sar_discard_timout", 0, 4),
        BitField("RFU", 0, 6),
        BitField("sar_acknowledgment_retransmission_count", 0,2)
    ]

bind_layers(BTMesh_Model_Message, BTMesh_SAR_Receiver_Status, opcode=0x8071)








"""
ACCESS LAYER
=================
"""


"""
UPPER TRANSPORT
=================
"""


class BTMesh_Upper_Transport_Access_PDU(Packet):
    # 2 fields (cipher and MIC) since too complicated to guess the size of MIC from scapy ...
    name = "Bluetooth Mesh Upper Transport Access Message"
    fields_desc = [
        StrField("enc_access_message_and_mic", None),
    ]


class BTMesh_Upper_Transport_Control_Friend_Poll(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Poll"
    fields_desc = [BitField("padding", 0, 7), BitField("friend_sequence_number", 0, 0)]


class BTMesh_Upper_Transport_Control_Friend_Update(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Update"
    field_desc = [
        BitEnumField(
            "key_refresh_flag", None, 1, {0b0: "Not-In-Phase2", 0b1: "In-Phase2"}
        ),
        BitEnumField(
            "iv_update_flag",
            None,
            1,
            {0b0: "Normal Operation", 0b1: "IV Update in Progress"},
        ),
        BitField("RFU", 0, 6),
        XIntField("iv_index", None),
        ByteEnumField(
            "md",
            None,
            {0x00: "Friend Queue is Empty", 0x01: "Friend Queue is not Empty"},
        ),
    ]


class BTMesh_Upper_Transport_Control_Friend_Request(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Request"
    fields_desc = [
        BitField("RFU", 0, 1),
        BitEnumField(
            "rssi_factor", 0, 2, {0b00: "1", 0b01: "1.5", 0b10: "2", 0b11: "2.5"}
        ),
        BitEnumField(
            "receive_window_factor",
            0,
            2,
            {0b00: "1", 0b01: "1.5", 0b10: "2", 0b11: "2.5"},
        ),
        BitEnumField(
            "min_queue_size_log",
            0,
            3,
            {
                0b000: "Prohibited",
                0b001: "N=2",
                0b010: "N=4",
                0b011: "N=8",
                0b100: "N=16",
                0b101: "N=32",
                0b110: "N=64",
                0b111: "N=128",
            },
        ),
        ByteField("receive_delay", None),
        ThreeBytesField("poll_timeout", None),
        XShortField("previous_address", None),
        ByteField("number_elements", None),
        ShortField("lpn_counter", None),
    ]


class BTMesh_Upper_Transport_Control_Friend_Offer(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Offer"
    fields_desc = [
        ByteField("receive_window", None),
        ByteField("queue_size", None),
        ByteField("subscription_list_size", None),
        ByteField("rssi", None),
        ShortField("friend_counter", None),
    ]


class BTMesh_Upper_Transport_Control_Friend_Clear(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Clear"
    fields_desc = [XShortField("lpn_address", None), XShortField("lpn_counter", None)]


class BTMesh_Upper_Transport_Control_Friend_Clear_Confirm(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Clear Confirm"
    fields_desc = [XShortField("lpn_address", None), XShortField("lpn_counter", None)]


class BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Subscription List Add"
    fields_desc = [
        ByteField("transaction_number", None),
        FieldListField(
            "addr_list",
            [],
            XShortField("addr", None),
        ),
    ]


class BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove(Packet):
    name = (
        "Bluetooth Mesh Upper Transport Control Message Friend Subscription List Remove"
    )
    fields_desc = [
        ByteField("transaction_number", None),
        FieldListField(
            "addr_list",
            [],
            XShortField("addr", None),
        ),
    ]


class BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Friend Subscription List Confirm"
    fields_desc = [ByteField("transaction_number", None)]


class BTMesh_Upper_Transport_Control_Heartbeat(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Hearbeat"
    fields_desc = [
        BitField("RFU", 0, 1),
        BitField("init_ttl", None, 7),
        FlagsField(
            "features",
            0,
            16,
            ["Relay", "Proxy", "Friend", "Low Power"] + ["RFU" for i in range(4, 16)],
        ),
    ]


class BTMesh_Upper_Transport_Control_Path_Request(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Path Request"
    fields_desc = [
        BitField("on_behalf_of_dependent_origin", None, 1),
        BitField("path_origin_path_metric_type", None, 3),
        BitField("path_origin_path_lifetime", None, 2),
        BitField("path_discovery_interval", None, 1),
        BitField("prohibited", 0, 1),
        ByteField("path_origin_forwarding_number", None),
        ByteField("path_origin_path_metric", None),
        XShortField("destination", None),
        PacketField(
            "path_origin_unicast_addr_range",
            None,
            pkt_cls=UnicastAddr,
        ),
        ConditionalField(
            PacketField(
                name="dependent_origin_unicast_addr_range",
                default=None,
                pkt_cls=UnicastAddr,
            ),
            lambda pkt: pkt.on_behalf_of_dependent_origin == 1,
        ),
    ]


class BTMesh_Upper_Transport_Control_Path_Reply(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Path Reply"
    fields_desc = [
        BitField("unicast_destination", None, 1),
        BitField("on_behalf_of_dependent_target", None, 1),
        BitField("confirmation_request", None, 1),
        BitField("prohibited", 0, 5),
        XShortField("path_origin", None),
        ByteField("path_origin_forwarding_number", None),
        ConditionalField(
            PacketField(
                "path_target_unicast_addr_range",
                None,
                pkt_cls=UnicastAddr,
            ),
            lambda pkt: pkt.unicast_destination == 1,
        ),
        ConditionalField(
            PacketField(
                "dependent_target_unicast_addr_range", None, pkt_cls=UnicastAddr
            ),
            lambda pkt: pkt.on_behalf_of_dependent_target == 1,
        ),
    ]


class BTMesh_Upper_Transport_Control_Path_Confirmation(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Path Confirmation"
    fields_desc = [XShortField("path_origin", None), XShortField("path_target", None)]


class BTMesh_Upper_Transport_Control_Path_Echo_Request(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Path Echo Request"
    field_desc = []


class BTMesh_Upper_Transport_Control_Path_Echo_Reply(Packet):
    name = "Bluetooth Mesh Upper Transport Control Message Path Echo Reply"
    fields_desc = [XShortField("destination", None)]


class BTMesh_Upper_Transport_Control_Dependent_Node_Update(Packet):
    name = "Bluetooth Upper Transport Control Dependent Node Update"
    fields_desc = [
        BitEnumField(
            "type",
            None,
            1,
            {
                0b0: "The dependent node addr is removed",
                0b1: "The dependent node addr is added",
            },
        ),
        BitField("prohibited", 0, 7),
        XShortField("path_endpoint", None),
        # dependent_node_unicast_addr_range
        PacketField("dependent_node_unicast_addr_range", None, pkt_cls=UnicastAddr),
    ]


class BTMesh_Upper_Transport_Control_Path_Request_Solicitation(Packet):
    name = "Bluetooth Upper Transport Control Message Path Request Solicitation"
    fields_desc = [
        FieldListField(
            "addr_list",
            [],
            XShortField("addr", None),
        ),
    ]


"""
LOWER TRANSPORT
====================
"""

OPCODE_TP_PAYLOAD_CLASS_LOWER_TRANSPORT = {
    0x01: BTMesh_Upper_Transport_Control_Friend_Poll,
    0x02: BTMesh_Upper_Transport_Control_Friend_Update,
    0x03: BTMesh_Upper_Transport_Control_Friend_Request,
    0x04: BTMesh_Upper_Transport_Control_Friend_Offer,
    0x05: BTMesh_Upper_Transport_Control_Friend_Clear,
    0x06: BTMesh_Upper_Transport_Control_Friend_Clear_Confirm,
    0x07: BTMesh_Upper_Transport_Control_Friend_Subscription_List_Add,
    0x08: BTMesh_Upper_Transport_Control_Friend_Subscription_List_Remove,
    0x09: BTMesh_Upper_Transport_Control_Friend_Subscription_List_Confirm,
    0x0A: BTMesh_Upper_Transport_Control_Heartbeat,
    0x0B: BTMesh_Upper_Transport_Control_Path_Request,
    0x0C: BTMesh_Upper_Transport_Control_Path_Reply,
    0x0D: BTMesh_Upper_Transport_Control_Path_Confirmation,
    0x0E: BTMesh_Upper_Transport_Control_Path_Echo_Request,
    0x0F: BTMesh_Upper_Transport_Control_Path_Echo_Reply,
    0x10: BTMesh_Upper_Transport_Control_Dependent_Node_Update,
    0x11: BTMesh_Upper_Transport_Control_Path_Request_Solicitation,
}


class BTMesh_Lower_Transport_Unsegmented_Control_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Unsegmented Control Message"
    fields_desc = [
        BitField("opcode", None, 7),
    ]

    # Binding to Upper Transport PDUS depending on opcode (same as bind_layers but les verbose)
    def guess_payload_class(self, payload):
        opcode = self.getfieldval("opcode")
        if opcode == 0x00:
            return BTMesh_Lower_Transport_Segment_Acknoledgment_Message
        if opcode not in OPCODE_TP_PAYLOAD_CLASS_LOWER_TRANSPORT:
            return Packet.guess_payload_class(self, payload)
        else:
            return OPCODE_TP_PAYLOAD_CLASS_LOWER_TRANSPORT[opcode]

    # Added to have an empty packet Echo Request payload (otherwise we get nothing after Lower Transport)
    # Since Echo Request is empty
    def dissection_done(self, pkt):
        if self.opcode == 0x0E:
            self.add_payload(BTMesh_Upper_Transport_Control_Path_Echo_Request())


class BTMesh_Lower_Transport_Segment_Acknoledgment_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Segment Acknowledgment Message"
    fields_desc = [
        BitField("obo", None, 1),
        BitField("seq_zero", None, 13),
        BitField("RFU", 0, 0),
        BitField("acked_segments", 0, 32),
    ]


class BTMesh_Lower_Transport_Unsegmented_Access_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Unsegmented Access Message"
    fields_desc = [
        BitField("application_key_flag", None, 1),
        BitField("application_key_id", None, 6),
    ]


class BTMesh_Lower_Transport_Segmented_Access_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Segmented Access Message"
    fields_desc = [
        BitField("application_key_flag", None, 1),
        BitField("application_key_id", None, 6),
        BitField("aszmic", None, 1),
        BitField("seq_zero", None, 13),
        BitField("seg_offset", None, 5),
        BitField("last_seg_number", None, 5),
    ]


class BTMesh_Lower_Transport_Segmented_Control_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Segmented Control Message"
    fields_desc = [
        BitField("opcode", None, 7),
        BitField("RFU", 0, 1),
        BitField("seq_zero", None, 13),
        BitField("seg_offset", None, 5),
        BitField("last_seg_number", None, 5),
    ]


# Lower Transport Control Message (Unsegmented or Segmented)
class BTMesh_Lower_Transport_Access_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Access Message"
    fields_desc = [
        BitField("seg", None, 1),
        MultipleTypeField(
            [
                (
                    PacketField(
                        "payload",
                        None,
                        BTMesh_Lower_Transport_Unsegmented_Access_Message,
                    ),
                    lambda pkt: pkt.seg == 0,
                )
            ],
            PacketField(
                "payload", None, BTMesh_Lower_Transport_Segmented_Access_Message
            ),
        ),
    ]


# Lower Transport Control Message (Unsegmented or Segmented)
class BTMesh_Lower_Transport_Control_Message(Packet):
    name = "Bluetooth Mesh Lower Transport Control Message"
    fields_desc = [
        BitField("seg", None, 1),
        MultipleTypeField(
            [
                (
                    PacketField(
                        "payload",
                        None,
                        BTMesh_Lower_Transport_Unsegmented_Control_Message,
                    ),
                    lambda pkt: pkt.seg == 0,
                )
            ],
            PacketField(
                "payload", None, BTMesh_Lower_Transport_Segmented_Control_Message
            ),
        ),
    ]


bind_layers(
    BTMesh_Lower_Transport_Access_Message, BTMesh_Upper_Transport_Access_PDU, seg=0
)

bind_layers(
    BTMesh_Lower_Transport_Access_Message, BTMesh_Upper_Transport_Access_PDU, seg=0
)

bind_layers(
    BTMesh_Lower_Transport_Unsegmented_Control_Message,
    BTMesh_Lower_Transport_Segment_Acknoledgment_Message,
    opcode=0x00,
)

"""
NETWORK
================
"""

"""
class BTMesh_Network_PDU_Bis(Packet):
    name = "Bluetooth Network PDU"
    fields_desc = [
        BitField("ivi", 0, 1),
        BitField("nid", 0, 7),
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

    def do_build(self):
        built_fields = [
            (self.iv_index << 7 | self.network_id).to_bytes(1, "big"),
            (self.network_ctl << 7 | self.ttl).to_bytes(1, "big"),
            self.seq_number.to_bytes(3, "big"),
            self.src_addr.to_bytes(2, "big"),
            self.dst_addr.to_bytes(2, "big"),
        ]

        print(built_fields)
        if self.payload:
            built_fields.append(raw(self.payload))

        built_fields.append(self.network_mic)

        return b"".join(f for f in built_fields)
"""


class BTMesh_Network_PDU(Packet):
    """
    Simpler version of Network PDU, with one field for
    the encrypted lower_transport_pdu and the following MIC
    """

    name = "Bluetooth Network PDU (no obfuscation)"
    fields_desc = [
        BitField("ivi", 0, 1),
        BitField("nid", 0, 7),
        BitEnumField(
            "network_ctl", 0, 1, {0b0: "Access Message", 0b1: "Control message"}
        ),
        BitField("ttl", 0, 7),
        ThreeBytesField("seq_number", None),
        XShortField("src_addr", None),
        # EncDST||EncTransport||MIC
        StrField(
            "enc_dst_enc_transport_pdu_mic",
            None,
        ),
    ]


class BTMesh_Obfuscated_Network_PDU(Packet):
    name = "Bluetooth Mesh Obfuscated/Encrypted Network PDU"
    fields_desc = [
        BitField("ivi", 0, 1),
        BitField("nid", 0, 7),
        StrFixedLenField("obfuscated_data", None, length=6),
        # EncDST||EncTransport||MIC
        StrField("enc_dst_enc_transport_pdu_mic", None),
    ]


"""
BEACONS
=================
"""


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
        BitField("unused", 0, 6),
        BitEnumField(
            "iv_update_flag", 0, 1, ["normal_operation", "iv_update_in_progress"]
        ),
        BitEnumField("key_refresh_flag", 0, 1, [False, True]),
        XLongField("nid", None),
        XIntField("ivi", None),
        StrFixedLenField("authentication_value", None, length=8),
    ]


class BTMesh_Obfuscated_Private_Beacon(Packet):
    name = "Bluetooth Mesh Obfuscated Private Beacon"
    fields_desc = [
        StrFixedLenField("random", None, length=13),
        StrFixedLenField("obfuscated_private_beacon_data", None, length=5),
        StrFixedLenField("authentication_tag", None, length=8),
    ]


class BTMesh_Private_Beacon(Packet):
    name = "Bluetooth Mesh Private Beacon (no obfuscation)"
    fields_desc = [
        StrFixedLenField("random", None, length=13),
        BitField("unused", 0, 6),
        BitEnumField(
            "iv_update_flag", 0, 1, ["normal_operation", "iv_update_in_progress"]
        ),
        BitEnumField("key_refresh_flag", 0, 1, [False, True]),
        XIntField("ivi", None),
        StrFixedLenField("authentication_tag", None, length=8),
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
            PacketField(
                "private_beacon_data", None, pkt_cls=BTMesh_Obfuscated_Private_Beacon
            ),
            lambda pkt: pkt.mesh_beacon_type == 2,
        ),
    ]


class EIR_BTMesh_Message(EIR_Element):
    name = "EIR Bluetooth Mesh Message"
    fields_desc = [PacketField("mesh_message", None, pkt_cls=BTMesh_Network_PDU)]


split_layers(EIR_Hdr, EIR_Raw)
bind_layers(EIR_Hdr, EIR_BTMesh_Message, type=0x2A)
bind_layers(EIR_Hdr, EIR_BTMesh_Beacon, type=0x2B)
bind_layers(EIR_Hdr, EIR_PB_ADV_PDU, type=0x29)
bind_layers(BTMesh_Lower_Transport_Unsegmented_Access_Message, BTMesh_Model_Message)
bind_layers(BTMesh_Proxy_Hdr, BTMesh_Provisioning_Hdr, message_type=0x03)

# need to remove this one, fragments and all ...
bind_layers(BTMesh_Generic_Provisioning_Hdr, BTMesh_Provisioning_Hdr)


def unbind():
    split_layers(EIR_Hdr, EIR_BTMesh_Beacon)
    split_layers(EIR_Hdr, EIR_BTMesh_Message)
    bind_layers(EIR_Hdr, EIR_Raw)
