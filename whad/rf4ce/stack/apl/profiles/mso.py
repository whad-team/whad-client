from whad.rf4ce.stack.apl.profile import APLProfile
from whad.scapy.layers.rf4ce import RC_COMMAND_CODES, RF4CE_Vendor_MSO_Hdr, \
    RF4CE_Vendor_MSO_User_Control_Pressed, \
    RF4CE_Vendor_MSO_User_Control_Released, \
    RF4CE_Vendor_MSO_User_Control_Repeated, \
    RF4CE_Vendor_MSO_Get_Attribute_Response, \
    RF4CE_Vendor_MSO_Check_Validation_Request, \
    RF4CE_Vendor_MSO_Check_Validation_Response, \
    RF4CE_Vendor_MSO_Check_Validation_Request
from whad.rf4ce.stack.apl.exceptions import APLTimeoutException

from enum import IntEnum
from time import sleep, time

class MSOEvent(IntEnum):
    """
    Enum representing types of MSO events.
    """
    DISCOVERY_REQ   = 1
    PAIRING_REQ     = 2


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


    def process_discovery(self, discovery):
        """
        Process a discovery request.
        """
        nwk_layer = self.manager.get_layer('nwk')
        apl_layer = self.manager.get_layer('apl')
        (
            status,
            source_address,
            node_capability,
            vendor_identifier,
            vendor_string,
            application_capability,
            user_string,
            device_type_list,
            profile_identifier_list,
            requested_device_type,
            link_quality
        ) = discovery

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

    def process_pairing(self, pairing):
        '''
        Process a pairing event.
        '''
        (
            status,
            source_pan_id,
            source_address,
            node_capability,
            vendor_identifier,
            vendor_string,
            application_capability,
            user_string,
            device_type_list,
            profile_identifier_list,
            key_exchange_transfer_count,
            pairing_reference
        ) = pairing

        mac_layer = self.manager.get_layer('mac')
        nwk_layer = self.manager.get_layer('nwk')
        apl_layer = self.manager.get_layer('apl')

        nwk_layer.database.set("nwkUserString", apl_layer.database.get("aplUserString"))
        list_of_supported_profiles = [profile_id for profile_id in self.manager.profiles.keys()]
        list_of_device_types = [apl_layer.database.get("aplDeviceType")]


        if nwk_layer.get_service('management').pair_response(
            source_address,
            accept=True,
            list_of_device_types=[apl_layer.database.get("aplDeviceType")],
            list_of_profiles=list_of_supported_profiles,
            pairing_reference=pairing_reference
        ):
            return pairing_reference
        else:
            return None

    def wait_for_binding(self, timeout=30):
        """
        Allow binding until timeout is reached.
        """
        start_time = time()

        while (time() - start_time) < timeout:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.DISCOVERY_REQ:
                    self.process_discovery(event[1:])
                elif event[0] == MSOEvent.PAIRING_REQ:
                    reference = self.process_pairing(event[1:])
                    if reference is None:
                        return None
                    else:
                        self.pairing_reference = reference
                        return self.manager.get_layer('nwk').database.get("nwkPairingTable")[reference]
            except APLTimeoutException:
                pass
        return None

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

    def on_check_validation_request(self, payload):
        """
        Callback processing check validation request payload.
        """
        sleep(0.5)
        nwk_layer = self.manager.get_layer('nwk')
        nwk_layer.get_service('data').data(
            RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                check_validation_status=0
            ),
            pairing_reference = self.pairing_reference,
            profile_id = 0xc0,
            vendor_id = 4417,
            tx_options = (
             0 | (1 << 1) | (0 << 2) | (1 << 3) | (0 << 4)| (0 << 5) | (1 << 6)
            )
        )

    def on_get_attribute_request(self, payload):
        """
        Callback processing Get Attribute Request payload.
        """
        pass

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

        #elif RF4CE_Vendor_MSO_Get_Attribute_Request in npdu:
        #    self.on_get_attribute_request(npdu[RF4CE_Vendor_MSO_Get_Attribute_Request])

        elif RF4CE_Vendor_MSO_Check_Validation_Request in npdu:
            self.on_check_validation_request(npdu[RF4CE_Vendor_MSO_Check_Validation_Request])

    def on_discovery(self, status, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, requested_device_type, link_quality):
        """
        Callback processing incoming discovery request for the profile.
        """
        self.add_packet_to_queue(
            (
                MSOEvent.DISCOVERY_REQ,
                status,
                source_address,
                node_capability,
                vendor_identifier,
                vendor_string,
                application_capability,
                user_string,
                device_type_list,
                profile_identifier_list,
                requested_device_type,
                link_quality
            )
        )




    def on_pair(self, status, source_pan_id, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, key_exchange_transfer_count, pairing_reference):
        """
        Callback processing incoming pairing request for the profile.
        """
        print("[i] MSO - pairing request")
        self.add_packet_to_queue(
            (
                MSOEvent.PAIRING_REQ,
                status,
                source_pan_id,
                source_address,
                node_capability,
                vendor_identifier,
                vendor_string,
                application_capability,
                user_string,
                device_type_list,
                profile_identifier_list,
                key_exchange_transfer_count,
                pairing_reference
            )
        )
