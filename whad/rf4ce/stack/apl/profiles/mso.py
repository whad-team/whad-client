from whad.rf4ce.stack.apl.profile import APLProfile
from whad.scapy.layers.rf4ce import RC_COMMAND_CODES, RF4CE_Vendor_MSO_Hdr, \
    RF4CE_Vendor_MSO_User_Control_Pressed, \
    RF4CE_Vendor_MSO_User_Control_Released, \
    RF4CE_Vendor_MSO_User_Control_Repeated, \
    RF4CE_Vendor_MSO_Get_Attribute_Response,\
    RF4CE_Vendor_MSO_Check_Validation_Response

class MSOProfile(APLProfile):
    """
    APL service implementing the MSO Profile.
    """

    def __init__(self):
        super().__init__(name="mso", profile_id=0xC0)

    def init(self):
        """
        Initialize the NWK layer database according to MSO profile.
        """
        nwk_layer = self.manager.get_layer('nwk')
        nwk_layer.database.set("nwkDiscoveryLQIThreshold", 0) # no filtering at NWK layer
        nwk_layer.database.set("nwkDiscoveryRepetitionInterval", 0x00927c) # 600ms
        nwk_layer.database.set("nwkIndicateDiscoveryRequest", True)
        nwk_layer.database.set("nwkMaxDiscoveryRepetitions", 2)
        nwk_layer.database.set("nwkMaxReportedNodeDescriptors", 16)
        self.discoverable = False
        self.bindable = False

    def enable_discovery(self):
        """
        Enable discovery mode (automatic response to discovery request).
        """
        self.discoverable = True

    def disable_discovery(self):
        """
        Disable discovery mode (automatic response to discovery request).
        """
        self.discoverable = False


    def enable_binding(self):
        """
        Enable binding mode (automatic response to pair request).
        """
        self.bindable = True

    def disable_binding(self):
        """
        Disable binding mode (automatic response to pair request).
        """
        self.bindable = False

    def wait_for_binding(self, timeout=30):
        """
        Wait for a binding.
        """
        self.enable_discovery()
        self.enable_binding()

    def on_user_control_pressed_payload(self, payload):
        """
        Callback processing user control pressed payload.
        """
        if payload.code in RC_COMMAND_CODES:
            print("[i] MSO - control pressed - ", RC_COMMAND_CODES[payload.code])
        else:
            print("[i] MSO - control pressed - unknown")


    def on_user_control_repeated_payload(self, payload):
        """
        Callback processing user control repeated payload.
        """
        print("[i] MSO - control repeated")


    def on_user_control_released_payload(self, payload):
        """
        Callback processing user control released payload.
        """
        print("[i] MSO - control released")

    def on_data(self, npdu, pairing_reference, vendor_id, link_quality, rx_flags):
        """
        Callback processing incoming data for the profile.
        """

        if RF4CE_Vendor_MSO_User_Control_Pressed in npdu:
            self.on_user_control_pressed_payload(npdu[RF4CE_Vendor_MSO_User_Control_Pressed])

        elif RF4CE_Vendor_MSO_User_Control_Released in npdu:
            self.on_user_control_released_payload(npdu[RF4CE_Vendor_MSO_User_Control_Released])

        elif RF4CE_Vendor_MSO_User_Control_Repeated in npdu:
            self.on_user_control_repeated_payload(npdu[RF4CE_Vendor_MSO_User_Control_Repeated])

    def on_discovery(self, status, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, requested_device_type, link_quality):
        """
        Callback processing incoming discovery request for the profile.
        """
        if not self.discoverable:
            return

        print("[i] MSO - discovery")
        nwk_layer = self.manager.get_layer('nwk')
        apl_layer = self.manager.get_layer('apl')

        # we don't match specification of MSO here, spoof vendor identifier instead of checking it
        nwk_layer.database.set("nwkVendorIdentifier", vendor_identifier)

        # we don't match specification of MSO here, spoof requested device type instead of checking it
        if requested_device_type == 0xFF:
            apl_layer.database.set("aplDeviceType", 9) # default
        else:
            apl_layer.database.set("aplDeviceType", requested_device_type)

        # we only filter by profile ID
        if self.profile_id not in profile_identifier_list:
            return

        list_of_supported_profiles = [profile_id for profile_id in self.manager.profiles.keys()]

        nwk_layer.get_service('management').discovery_response(
            0,
            source_address,
            list_of_device_types=[apl_layer.database.get("aplDeviceType")],
            list_of_profiles=list_of_supported_profiles,
            link_quality=link_quality
        )


    def on_pair(self, status, source_pan_id, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, key_exchange_transfer_count, pairing_reference):
        """
        Callback processing incoming pairing request for the profile.
        """
        if not self.bindable:
            return

        print("[i] MSO - pairing request")
        mac_layer = self.manager.get_layer('mac')
        nwk_layer = self.manager.get_layer('nwk')
        apl_layer = self.manager.get_layer('apl')

        nwk_layer.database.set("nwkUserString", apl_layer.database.get("aplUserString"))
        list_of_supported_profiles = [profile_id for profile_id in self.manager.profiles.keys()]

        nwk_layer.get_service('management').pair_response(
            source_address,
            accept=True,
            list_of_device_types=[apl_layer.database.get("aplDeviceType")],
            list_of_profiles=list_of_supported_profiles,
            pairing_reference=pairing_reference
        )
