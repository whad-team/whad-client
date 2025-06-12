from scapy.fields import ByteField, LenField, ByteEnumField, StrField, \
    BitField, BitEnumField, LEIntField
from scapy.packet import Packet, bind_layers

antstick_message_ids = {
    0x00 : "invalid",
    0x41 : "unassign_channel",
    0x42 : "assign_channel",
    0x51 : "set_channel_id",
    0x43 : "set_channel_period",
    0x44 : "set_channel_search_timeout",
    0x45 : "set_channel_rf_freq",
    0x46 : "set_network_key",
    0x47 : "set_transmit_power",
    0x49 : "set_search_waveform",
    0x59 : "add_channel_id",
    0x59 : "add_encryption_id",
    0x5A : "config_list",
    0x5A : "config_encryption_list",
    0x60 : "set_channel_tx_power",
    0x63 : "low_priority_channel_search_timeout",
    0x65 : "serial_number_set_channel",
    0x66 : "enable_ext_rx_mesgs",
    0x68 : "enable_led",
    0x6D : "enable_crystal",
    0x6E : "lib_config",
    0x70 : "frequency_agility",
    0x71 : "proximity_search",
    0x74 : "config_event_buffer",
    0x75 : "channel_search_priority",
    0x76 : "set_128_network_key",
    0x77 : "high_duty_search",
    0x78 : "config_advanced_burst",
    0x79 : "config_event_filter",
    0x7A : "config_selective_data_update",
    0x7B : "set_sdu_mask",
    0x7C : "config_user_nvm",
    0x7D : "enable_single_channel_encryption",
    0x7E : "set_encryption_key",
    0x7F : "set_encryption_info",
    0x81 : "channel_search_sharing",
    0x83 : "load_store_encryption_key",
    0xC7 : "set_usb_descriptor_string",
    0x6F : "startup_message",
    0xAE : "serial_error_message",
    0x4A : "reset_system",
    0x4B : "open_channel",
    0x4C : "close_channel",
    0x4D : "request_message",
    0x5B : "open_rx_scan_mode",
    0xC5 : "sleep_message",
    0x4E : "broadcast_data",
    0x4F : "acknowledged_data",
    0x50 : "burst_transfer_data",
    0x72 : "advanced_burst_transfer_data",
    0x40 : "response_channel",
    0x52 : "response_channel_status",
    0x51 : "response_channel_id",
    0x3E : "response_ant_version",
    0x54 : "response_capabilities",
    0x61 : "response_serial_number",
    0x74 : "response_event_buffer_config",
    0x78 : "response_advanced_burst_capabilities",
    0x79 : "response_event_filter",
    0x53 : "test_mode_cw_init",
    0x48 : "test_mode_cw_test",
    0x5D : "legacy_extended_broadcast_data",
    0x5E : "legacy_extended_acknowledged_data",
    0x5F : "legacy_extended_burst_data",
}


class ANTStick_Message(Packet):
    name = "ANTStick Message"
    fields_desc = [
        ByteField("sync", 0xA4), 
        ByteField("length", None), 
        ByteEnumField("id", None, antstick_message_ids), 
        ByteField("checksum", None)
    ]

    def post_build(self, p, pay):
        """Effectively build the ANTStick message and re-arrange it.
        """
        if self.length is None:
            self.length = len(pay)

        if self.checksum is None:
            self.checksum = self.sync ^ self.length ^ self.id
            for a in pay:
                self.checksum ^= a
        
        # Build the final frame
        return bytes([self.sync, self.length, self.id]) + bytes(pay) + bytes([self.checksum])

    def post_dissect(self, s):
        """Override layer post_dissect() function to reset raw packet cache.
        """
        self.raw_packet_cache = None  # Reset packet to allow post_build
        return s

    def pre_dissect(self,s):
        """Pre-dissect an ANTStick message to re-arrange fields.
        """
        return s[0:3] + s[-1:] + s[3:-1]



class ANTStick_Command_Request_Message(Packet):
    name = "ANTStick Command (Request Message)"
    fields_desc = [
        ByteField("channel_number", 0), 
        ByteField("message_id_req", 0x61) 
    ]


class ANTStick_Requested_Message_Serial_Number(Packet):
    name = "ANTStick Requested Message (Serial Number)"
    fields_desc = [
        LEIntField("serial_number", None)
    ]


class ANTStick_Requested_Message_ANT_Version(Packet):
    name = "ANTStick Requested Message (ANT Version)"
    fields_desc = [
        StrField("version", None)
    ]


class ANTStick_Requested_Message_Capabilities(Packet):
    name = "ANTStick Requested Message (Capabilities)"
    fields_desc = [
        ByteField("max_channels", None), 
        ByteField("max_networks", None), 

        # Standard options
        BitField("reserved_1", 0, 2), 
        BitField("cap_no_burst_messages", 0, 1), 
        BitField("cap_no_ackd_messages", 0, 1), 
        BitField("cap_no_transmit_messages", 0, 1), 
        BitField("cap_no_receive_messages", 0, 1), 
        BitField("cap_no_transmit_channels", 0, 1), 
        BitField("cap_no_receive_channels", 0, 1),

        # Advanced options
        BitField("cap_search_list_enabled", 0, 1), 
        BitField("cap_script_enabled", 0, 1), 
        BitField("cap_low_priority_search_enabled", 0, 1), 
        BitField("cap_per_channel_tx_power_enabled", 0, 1), 
        BitField("cap_serial_number_enabled", 0, 1), 
        BitField("reserved_2", 0, 1), 
        BitField("cap_network_enabled", 0, 1), 
        BitField("reserved_3", 0, 1), 

        # Advanced options (2)
        BitField("cap_fit1_enabled", 0, 1), 
        BitField("cap_fs_antfs_enabled", 0, 1), 
        BitField("cap_ext_assign_enabled", 0, 1), 
        BitField("cap_prox_search_enabled", 0, 1), 
        BitField("reserved4", 0, 1), 
        BitField("cap_scan_mode_enabled", 0, 1), 
        BitField("cap_ext_msg_enabled", 0, 1), 
        BitField("cap_led_enabled", 0, 1), 

        ByteField("max_sensrcore_channels", None), 
    
        # Advanced options (3)
        BitField("cap_encrypted_channel_enabled", 0, 1), 
        BitField("cap_selective_data_updates_enabled", 0, 1), 
        BitField("reserved5", 0, 1), 
        BitField("cap_search_sharing_enabled", 0, 1), 
        BitField("cap_high_duty_search", 0, 1), 
        BitField("cap_event_filtering_enabled", 0, 1), 
        BitField("cap_event_buffering_enabled", 0, 1), 
        BitField("cap_advanced_burst_enabled", 0, 1),     

        # Advanced options (4)
        BitField("reserved6", 0, 7),
        BitField("cap_rfactive_notification_enabled", 0, 1), 

    ]

bind_layers(ANTStick_Message, ANTStick_Command_Request_Message, id=0x4D)
bind_layers(ANTStick_Message, ANTStick_Requested_Message_Serial_Number, id=0x61)
bind_layers(ANTStick_Message, ANTStick_Requested_Message_ANT_Version, id=0x3E)
bind_layers(ANTStick_Message, ANTStick_Requested_Message_Capabilities, id=0x54)