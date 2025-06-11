from scapy.packet import bind_layers, Packet
from scapy.fields import BitField, LEShortField, ByteField, StrFixedLenField, \
    FlagsField, ByteEnumField, BitEnumField
from scapy.layers.bluetooth import SM_Hdr, HCI_Event_LE_Meta, HCI_Command_Hdr, \
    HCI_Event_Command_Complete, _bluetooth_features, _bluetooth_error_codes, \
    HCI_Cmd_Complete_LE_Read_White_List_Size, ATT_Hdr

_bluetooth_supported_commands = [
    # Byte 0
    "inquiry",
    "inquiry_cancel",
    "periodic_inquiry_mode",
    "exit_periodic_inquiry_mode",
    "create_connection",
    "disconnect",
    "previously_used",
    "create_connection_cancel",

    # Byte 1
    "accept_connection_request",
    "reject_connection_request",
    "link_key_request_reply",
    "link_key_request_negative_reply",
    "pin_code_request_reply",
    "pin_code_request_negative_reply",
    "change_connection_packet_type",
    "authentication_requested",

    # Byte 2
    "set_connection_encryption",
    "change_connection_link_key",
    "link_key_selection",
    "remote_name_request",
    "remote_name_request_cancel",
    "read_remote_supported_features",
    "read_remote_extended_features",
    "read_remote_version_info",

    # Byte 3
    "read_clock_offset",
    "read_lmp_handle",
    "rfu",
    "rfu",
    "rfu",
    "rfu",
    "rfu",
    "rfu",

    # Byte 4
    "rfu",
    "hold_mode",
    "sniff_mode",
    "exit_sniff_mode",
    "previously_used",
    "previously_used",
    "qos_setup",
    "role_discovery",

    # Byte 5
    "switch_role",
    "read_link_policy_settings",
    "write_link_policy_settings",
    "read_default_link_policy_settings",
    "write_default_link_policy_settings",
    "flow_specification",
    "set_event_mask",
    "reset",

    # Byte 6
    "set_event_filter",
    "flush",
    "read_pin_type",
    "write_pin_type",
    "previously_used",
    "read_stored_link_key",
    "write_stored_link_key",
    "delete_stored_link_key",

    # Byte 7
    "write_local_name",
    "read_local_name",
    "read_connection_accept_timeout",
    "write_connection_accept_timeout",
    "read_page_timeout",
    "write_page_timeout",
    "read_scan_enable",
    "write_scan_enable",

    # Byte 8
    "read_page_scan_activity",
    "write_page_scan_activity",
    "read_inquiry_scan_activity",
    "write_inquiry_scan_activity",
    "read_authentication_enable",
    "write_authentication_enable",
    "previously_used",
    "previously_used",

    # Byte 9
    "read_class_of_device",
    "write_class_of_device",
    "read_voice_setting",
    "write_voice_setting",
    "read_automatic_flush_timeout",
    "write_automatic_flush_timeout",
    "read_num_broadcast_retransmissions",
    "write_num_broadcast_retransmissions",

    # Byte 10
    "read_hold_mode_activity",
    "write_hold_mode_activity",
    "read_transmit_power_level",
    "read_synchronous_flow_control_enable",
    "write_synchronous_flow_control_enable",
    "set_controller_to_host_flow_control",
    "host_buffer_size",
    "host_number_of_completed_packets",

    # Byte 11
    "read_link_supervision_timeout",
    "write_link_supervision_timeout",
    "read_number_of_supported_iac",
    "read_current_iac_lap",
    "write_current_iac_lap",
    "previously_used",
    "previously_used",
    "previously_used",

    # Byte 12
    "previously_used",
    "set_afh_host_channel_classification",
    "rfu",
    "rfu",
    "read_inquiry_scan_type",
    "write_inquiry_scan_type",
    "read_inquiry_mode",
    "write_inquiry_mode",

    # Byte 13
    "read_page_scan_type",
    "write_page_scan_type",
    "read_afh_channel_assessment_mode",
    "write_afh_channel_assessment_mode",
    "rfu",
    "rfu",
    "rfu",
    "rfu",

    # Byte 14
    "rfu",
    "rfu",
    "rfu",
    "read_local_version_information",
    "rfu",
    "read_local_supported_features",
    "read_local_extended_features",
    "read_buffer_size",

    # Byte 15
    "previously_used",
    "read_bd_addr",
    "read_failed_contact_counter",
    "reset_failed_contact_counter",
    "read_link_quality",
    "read_rssi",
    "read_afh_channel_map",
    "read_clock",

    # Byte 16
    "read_loopback_mode",
    "write_loopback_mode",
    "enable_device_under_test_mode",
    "setup_synchronous_connection_request",
    "accept_synchronous_connection_request",
    "reject_synchronous_connection_request",
    "rfu",
    "rfu",

    # Byte 17
    "read_extended_inquiry_response",
    "write_extended_inquiry_response",
    "refresh_encryption_key",
    "rfu",
    "sniff_subrating",
    "read_simple_pairing_mode",
    "write_simple_pairing_mode",
    "read_local_oob_data",

    # Byte 18
    "read_inquiry_response_transmit_power_level",
    "write_inquiry_transmit_power_level",
    "read_default_erroneous_data_reporting",
    "write_default_erroneous_data_reporting",
    "rfu",
    "rfu",
    "rfu",
    "io_capability_request_reply",

    # Byte 19
    "user_confirmation_request_reply",
    "user_confirmation_request_negative_reply",
    "user_passkey_request_reply",
    "user_passkey_request_negative_reply",
    "remote_oob_data_request_reply",
    "write_simple_pairing_debug_mode",
    "enhanced_flush",
    "remote_oob_data_request_negative_reply",

    # Byte 20
    "rfu",
    "rfu",
    "send_keypress_notification",
    "io_capability_request_negative_reply",
    "read_encryption_key_size",
    "rfu",
    "rfu",
    "rfu",

    # Byte 21
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",

    # Byte 22
    "previously_used",
    "previously_used",
    "set_event_mask_page_2",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",
    "previously_used",

    # Byte 23
    "read_flow_control_mode",
    "write_flow_control_mode",
    "read_data_block_size",
    "rfu",
    "rfu",
    "previously_used",
    "previously_used",
    "previously_used",

    # Byte 24
    "read_enhanced_transmit_power_level",
    "rfu",
    "previously_used",
    "previously_used",
    "previously_used",
    "read_le_host_support",
    "write_le_host_support",
    "rfu",

    # Byte 25
    "le_set_event_mask",
    "le_read_buffer_size_v1",
    "le_read_local_supported_features",
    "rfu",
    "le_set_random_address",
    "le_set_advertising_parameters",
    "le_read_advertising_physical_channel_tx_power",
    "le_set_advertising_data",

    # Byte 26
    "le_set_scan_response_data",
    "le_set_advertising_enable",
    "le_set_scan_parameters",
    "le_set_scan_enable",
    "le_create_connection",
    "le_create_connection_cancel",
    "le_read_filter_accept_list_size",
    "le_clear_filter_accept_list",

    # Byte 27
    "le_add_device_to_filter_accept_list",
    "le_remove_device_from_filter_accept_list",
    "le_connection_update",
    "le_set_host_channel_classification",
    "le_read_channel_map",
    "le_read_remote_features",
    "le_encrypt",
    "le_rand",

    # Byte 28
    "le_enable_encryption",
    "le_long_term_key_request_reply",
    "le_long_term_key_request_negative_reply",
    "le_read_supported_states",
    "le_receiver_test_v1",
    "le_transmitter_test_v1",
    "le_test_end",
    "rfu",

    # Byte 29
    "rfu",
    "rfu",
    "rfu",
    "enhanced_setup_synchronous_connection",
    "enhanced_accept_synchronous_connection",
    "read_local_supported_codecs",
    "set_mws_channel_parameters",
    "set_external_frame_configuration",

    # Byte 30
    "set_mws_signaling",
    "set_mws_transport_layer",
    "set_mws_scan_frequency_table",
    "get_mws_transport_layer_configuration",
    "set_mws_pattern_configuration",
    "set_triggered_clock_capture",
    "truncated_page",
    "truncated_page_cancel",

    # Byte 31
    "set_connectionless_peripheral_broadcast",
    "set_connectionless_peripheral_broadcast_receive",
    "start_synchronization_train",
    "receive_synchronization_train",
    "set_reserved_lt_addr",
    "delete_reserved_lt_addr",
    "set_connectionless_peripheral_broadcast_data",
    "read_synchronization_train_parameters",

    # Byte 32
    "write_synchronization_train_parameters",
    "remote_oob_extended_data_request_reply",
    "read_secure_connections_host_support",
    "write_secure_connections_host_support",
    "read_authenticated_payload_timeout",
    "write_authenticated_payload_timeout",
    "read_local_oob_extended_data",
    "write_secure_connections_test_mode",

    # Byte 33
    "read_extended_page_timeout",
    "write_extended_page_timeout",
    "read_extended_inquiry_length",
    "write_extended_inquiry_length",
    "le_remote_connection_parameter_request_reply",
    "le_remote_connection_parameter_request_negative_reply",
    "le_set_data_length",
    "le_read_suggested_default_data_length",

    # Byte 34
    "le_write_suggested_default_data_length",
    "le_read_local_p_256_public_key",
    "le_generate_dhkey_v1",
    "le_add_device_to_resolving_list",
    "le_remove_device_from_resolving_list",
    "le_clear_resolving_list",
    "le_read_resolving_list_size",
    "le_read_peer_resolvable_address",

    # Byte 35
    "le_read_local_resolvable_address",
    "le_set_address_resolution_enable",
    "le_set_resolvable_private_address_timeout",
    "le_read_maximum_data_length",
    "le_read_phy",
    "le_set_default_phy",
    "le_set_phy",
    "le_receiver_test_v2",

    # Byte 36
    "le_transmitter_test_v2",
    "le_set_advertising_set_random_address",
    "le_set_extended_advertising_parameters",
    "le_set_extended_advertising_data",
    "le_set_extended_scan_response_data",
    "le_set_extended_advertising_enable",
    "le_read_maximum_advertising_data_length",
    "le_read_number_of_supported_advertising_sets",

    # Byte 37
    "le_remove_advertising_set",
    "le_clear_advertising_sets",
    "le_set_periodic_advertising_parameters",
    "le_set_periodic_advertising_data",
    "le_set_periodic_advertising_enable",
    "le_set_extended_scan_parameters",
    "le_set_extended_scan_enable",
    "le_extended_create_connection",

    # Byte 38
    "le_periodic_advertising_create_sync",
    "le_periodic_advertising_create_sync_cancel",
    "le_periodic_advertising_terminate_sync",
    "le_add_device_to_periodic_advertiser_list",
    "le_remove_device_from_periodic_advertiser_list",
    "le_clear_periodic_advertiser_list",
    "le_read_periodic_advertiser_list_size",
    "le_read_transmit_power",

    # Byte 39
    "le_read_rf_path_compensation",
    "le_write_rf_path_compensation",
    "le_set_privacy_mode",
    "le_receiver_test_v3",
    "le_transmitter_test_v3",
    "le_set_connectionless_cte_transmit_parameters",
    "le_set_connectionless_cte_transmit_enable",
    "le_set_connectionless_iq_sampling_enable",

    # Byte 40
    "le_set_connection_cte_receive_parameters",
    "le_set_connection_cte_transmit_parameters",
    "le_connection_cte_request_enable",
    "le_connection_cte_response_enable",
    "le_read_antenna_information",
    "le_set_periodic_advertising_receive_enable",
    "le_periodic_advertising_sync_transfer",
    "le_periodic_advertising_set_info_transfer",

    # Byte 41
    "le_set_periodic_advertising_sync_transfer_parameters",
    "le_set_default_periodic_advertising_sync_transfer_parameters",
    "le_generate_dhkey_v2",
    "read_local_simple_pairing_options",
    "le_modify_sleep_clock_accuracy",
    "le_read_buffer_size_v2",
    "le_read_iso_tx_sync",
    "le_set_cig_parameters",

    # Byte 42
    "le_set_cig_parameters_test",
    "le_create_cis",
    "le_remove_cig",
    "le_accept_cis_request",
    "le_reject_cis_request",
    "le_create_big",
    "le_create_big_test",
    "le_terminate_big",

    # Byte 43
    "le_big_create_sync",
    "le_big_terminate_sync",
    "le_request_peer_sca",
    "le_setup_iso_data_path",
    "le_remove_iso_data_path",
    "le_iso_transmit_test",
    "le_iso_receive_test",
    "le_iso_read_test_counters",

    # Byte 44
    "le_iso_test_end",
    "le_set_host_feature",
    "le_read_iso_link_quality",
    "le_enhanced_read_transmit_power_level",
    "le_read_remote_transmit_power_level",
    "le_set_path_loss_reporting_parameters",
    "le_set_path_loss_reporting_enable",
    "le_set_transmit_power_reporting_enable",

    # Byte 45
    "le_transmitter_test_v4",
    "set_ecosystem_base_interval",
    "read_local_supported_codecs_v2",
    "read_local_supported_codec_capabilities",
    "read_local_supported_controller_delay",
    "configure_data_path",
    "le_set_data_related_address_changes",
    "set_min_encryption_key_size",

    # Byte 46
    "le_set_default_subrate_parameters",
    "le_subrate_request",
    "le_subrate_response",
    "le_set_periodic_advertising_sync_transfer_parameters_v2",
    "le_set_default_periodic_advertising_sync_transfer_parameters_v2",
    "le_read_transmit_power_level",
    "le_read_default_subrate_parameters",
    "le_read_max_subrate_parameters"

]

_bluetooth_le_features = [
    "encryption",                         # Bit 0
    "connection_parameters_request_procedure", # Bit 1
    "extended_reject_indication",           # Bit 2
    "peripheral_initiated_features_exchange", # Bit 3
    "ping",                               # Bit 4
    "data_packet_length_extension",       # Bit 5
    "ll_privacy",                            # Bit 6
    "extended_scanner_filter_policies",      # Bit 7
    "2m_phy",                              # Bit 8
    "stable_modulation_index_transmitter",   # Bit 9
    "stable_modulation_index_receiver",      # Bit 10
    "coded_phy",                          # Bit 11
    "extended_advertising",               # Bit 12
    "periodic_advertising",               # Bit 13
    "channel_selection_algorithm_2",         # Bit 14
    "power_class_1",                      # Bit 15
    "minimum_number_of_used_channels_procedure", # Bit 16
    "connection_cte_request",                # Bit 17
    "connection_cte_response",               # Bit 18
    "connectionless_cte_transmitter",        # Bit 19
    "connectionless_cte_receiver",           # Bit 20
    "antenna_switching_during_cte_transmission_aod", # Bit 21
    "antenna_switching_during_cte_reception_aoa",    # Bit 22
    "receiving_constant_tone_extensions",    # Bit 23
    "periodic_advertising_sync_transfer_sender",     # Bit 24
    "periodic_advertising_sync_transfer_recipient",  # Bit 25
    "sleep_clock_accuracy_updates",          # Bit 26
    "remote_public_key_validation",          # Bit 27
    "connected_isochronous_stream_central",  # Bit 28
    "connected_isochronous_stream_peripheral", # Bit 29
    "isochronous_broadcaster",               # Bit 30
    "synchronized_receiver",                 # Bit 31
    "connected_isochronous_stream",          # Bit 32
    "power_control_request",              # Bit 33
    "power_control_request",              # Bit 34
    "path_loss_monitoring",               # Bit 35
    "periodic_advertising_adi_support",      # Bit 36
    "connection_subrating",                  # Bit 37
    "connection_subrating_host_support",     # Bit 38
    "channel_classification",                # Bit 39
    "rfu",                                    # Bit 40
    "rfu",                                    # Bit 41
    "rfu",                                    # Bit 42
    "rfu",                                    # Bit 43
    "rfu",                                    # Bit 44
    "rfu",                                    # Bit 45
    "rfu",                                    # Bit 46
    "rfu",                                    # Bit 47
    "rfu",                                    # Bit 48
    "rfu",                                    # Bit 49
    "rfu",                                    # Bit 50
    "rfu",                                    # Bit 51
    "rfu",                                    # Bit 52
    "rfu",                                    # Bit 53
    "rfu",                                    # Bit 54
    "rfu",                                    # Bit 55
    "rfu",                                    # Bit 56
    "rfu",                                    # Bit 57
    "rfu",                                    # Bit 58
    "rfu",                                    # Bit 59
    "rfu",                                    # Bit 60
    "rfu",                                    # Bit 61
    "rfu",                                    # Bit 62
    "rfu",                                    # Bit 63
]

# Add missing ATT_Handle_Value_Confirmation class
class ATT_Handle_Value_Confirmation(Packet):
    """ATT Handle value confirmation packet, missing from Scapy BLE definitions
    """
    name = "Handle Value Confirmation"

class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [
       BitField("authentication", 0, 8)
    ]

bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0b)

class HCI_LE_Meta_Data_Length_Change(Packet):
    name = "Data Length Change"
    fields_desc = [LEShortField("handle", 0),
                   LEShortField("max_tx_octets", 0x001B),
                   LEShortField("max_tx_time", 0x0148),
                   LEShortField("max_rx_octets", 0x001B),
                   LEShortField("max_rx_time", 0x0148)
                   ]

class HCI_LE_Set_Data_Length(Packet):
    name = "Set Data Length"
    fields_desc = [LEShortField("handle", 0),
                   LEShortField("tx_octets", 0x001B),
                   LEShortField("tx_time", 0x0148),
                   ]

class HCI_Cmd_LE_Complete_Read_Buffer_Size(Packet):
    name = "LE Read Buffer Size response"
    fields_desc = [LEShortField("acl_pkt_len", 0),
                   ByteField("total_num_acl_pkts", 0)]

class HCI_Cmd_LE_Set_Event_Mask(Packet):
    name = "LE Set Event Mask"
    fields_desc = [StrFixedLenField("mask", b"\x1f\x00\x00\x00\x00\x00\x00\x00", 8)]

class HCI_Cmd_Read_Buffer_Size(Packet):
    name = "Read Buffer Size"

class HCI_Cmd_Complete_Read_Buffer_Size(Packet):
    name = "Read Buffer Size response"
    fields_desc = [LEShortField("acl_pkt_len", 0),
                   ByteField("total_num_acl_pkts", 0)]

class HCI_Cmd_Read_Local_Supported_Commands(Packet):
    name = "Read Local Supported Commands"

class HCI_Cmd_Complete_Supported_Commands(Packet):
    name = "Supported Commands response"
    fields_desc = [
        FlagsField("supported_commands", 0, -512, _bluetooth_supported_commands)
    ]

class HCI_Cmd_Read_Local_Supported_Features(Packet):
    name = "Read Local Supported Features"

class HCI_Cmd_Complete_Supported_Features(Packet):
    """
    7.7.11 Read Remote Supported Features Complete event
    """
    name = "HCI_Read_Remote_Supported_Features_Complete"
    fields_desc = [
        FlagsField('lmp_features', 0, -64, _bluetooth_features)
    ]

class HCI_Cmd_LE_Read_Local_Supported_Features(Packet):
    name = "Read Local Supported Features"

class HCI_Cmd_LE_Complete_Supported_Features(Packet):
    name = "HCI_Read_LE_Local_Supported_Features_Complete"
    fields_desc = [
        FlagsField('le_features', 0, -64, _bluetooth_le_features)
    ]

class HCI_Cmd_LE_Complete_Read_Filter_Accept_List_Size(Packet):
    name = "HCI_Read_Filter_Accept_List_Size_Complete"
    fields_desc = [
        ByteField("list_size", 0)
    ]

class HCI_Cmd_LE_Write_Suggested_Default_Data_Length(Packet):
    name = "HCI_LE_Write_Suggested_Default_Data_Length"
    fields_desc = [
        LEShortField("max_tx_octets", 0x1B),
        LEShortField("max_tx_time", 0x148),
    ]

class HCI_Cmd_LE_Read_Suggested_Default_Data_Length(Packet):
    name = "HCI_LE_Read_Suggested_Default_Data_Length"

class HCI_Cmd_LE_Complete_Suggested_Default_Data_Length(Packet):
    name = "Suggested Default Length"
    fields_desc = [
        LEShortField("max_tx_octets", 0x1B),
        LEShortField("max_tx_time", 0x148)
    ]

class HCI_Cmd_Write_Simple_Pairing_Mode(Packet):
    name = "Write Simple Pairing Mode"
    fields_desc = [ ByteField("enable", 0), ]

class HCI_Cmd_Write_Default_Link_Policy_Settings(Packet):
    name = "Write Default Link Policy Settings"
    fields_desc = [ LEShortField("policy", 7),] 

class HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power(Packet):
    name = "HCI_LE_Read_Advertising_Physical_Channel_Tx_Power"
    fields_desc = []

class HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level(Packet):
    name = "Advertising Tx Power Level"
    fields_desc = [ ByteField("tx_power_level", 0), ]

class HCI_Cmd_Write_Class_Of_Device(Packet):
    name = "Set Class of Device"
    fields_desc = [
        FlagsField('major_service_classes', 0, 11, [
            'limited_discoverable_mode',
            'le_audio',
            'reserved',
            'positioning',
            'networking',
            'rendering',
            'capturing',
            'object_transfer',
            'audio',
            'telephony',
            'information'
        ], tot_size=-3),
        BitEnumField('major_device_class', 0, 5, {
            0x00: 'miscellaneous',
            0x01: 'computer',
            0x02: 'phone',
            0x03: 'lan',
            0x04: 'audio_video',
            0x05: 'peripheral',
            0x06: 'imaging',
            0x07: 'wearable',
            0x08: 'toy',
            0x09: 'health',
            0x1f: 'uncategorized'
        }),
        BitField('minor_device_class', 0, 6),
        BitField('fixed', 0, 2, end_tot_size=-3)
    ]

def unbind_layer(cls, pkt_cls):
    # Unbind bottom/up
    item = None
    for guess in cls.payload_guess:
        if guess[1] == pkt_cls:
            item = guess
            break
    if item is not None:
        cls.payload_guess.remove(item)
    # Unbind top/down
    item = None
    for guess in pkt_cls.payload_guess:
        if guess[1] == cls:
            item = guess
            break
    if item is not None:
        pkt_cls.payload_guess.remove(item)

# HCI LE events
bind_layers(HCI_Command_Hdr, HCI_LE_Set_Data_Length, ogf=0x08, ocf=0x0022)
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Buffer_Size, ogf=0x04, ocf=0x0005)

# HCI LE commands
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Data_Length_Change, event=7)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Event_Mask, ogf=0x08, ocf=0x0001) # noqa: E501

# HCI Commands
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Supported_Commands, ogf=0x04, ocf=0x0002) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Read_Local_Supported_Features, ogf=0x04, ocf=0x0003) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Class_Of_Device, ogf=0x03, ocf=0x0024) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Local_Supported_Features, ogf=0x08, ocf=0x0003) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power, ogf=0x08, ocf=0x0007) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Read_Suggested_Default_Data_Length, ogf=0x08, ocf=0x0023) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Write_Suggested_Default_Data_Length, ogf=0x08, ocf=0x0024) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Simple_Pairing_Mode, ogf=0x03, ocf=0x0056) # noqa: E501
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Default_Link_Policy_Settings, ogf=0x02, ocf=0x000f) # noqa: E501


# HCI Event Command Complete dispatch
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Read_Buffer_Size, opcode=0x2002)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Supported_Features, opcode=0x2003)  # noqa: E501
unbind_layer(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Read_White_List_Size)
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Read_Filter_Accept_List_Size, opcode=0x200F)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_LE_Complete_Suggested_Default_Data_Length, opcode=0x2023)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level, opcode=0x2007) # noaq: E501


bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Supported_Commands, opcode=0x1002)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Supported_Features, opcode=0x1003)  # noqa: E501
bind_layers(HCI_Event_Command_Complete, HCI_Cmd_Complete_Read_Buffer_Size, opcode=0x1005)  # noqa: E501


# Bind ATT_Handle_Value_Confirmation with ATT_Hdr
bind_layers(ATT_Hdr, ATT_Handle_Value_Confirmation, opcode=0x1e)

