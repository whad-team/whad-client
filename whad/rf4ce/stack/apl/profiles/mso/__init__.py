from whad.rf4ce.stack.apl.profile import APLProfile
from whad.scapy.layers.rf4ce import RC_COMMAND_CODES, RF4CE_Vendor_MSO_Hdr, \
    RF4CE_Vendor_MSO_Audio, RF4CE_Vendor_MSO_Audio_Data_Notify, \
    RF4CE_Vendor_MSO_Audio_Stop_Request, RF4CE_Vendor_MSO_Audio_Stop_Response, \
    RF4CE_Vendor_MSO_Audio_Start_Request, RF4CE_Vendor_MSO_Audio_Start_Response, \
    RF4CE_Vendor_MSO_User_Control_Pressed, RF4CE_Vendor_MSO_User_Control_Released, \
    RF4CE_Vendor_MSO_User_Control_Repeated, RF4CE_Vendor_MSO_Get_Attribute_Request, \
    RF4CE_Vendor_MSO_Get_Attribute_Response, RF4CE_Vendor_MSO_Check_Validation_Request, \
    RF4CE_Vendor_MSO_Check_Validation_Response, RF4CE_Vendor_MSO_Check_Validation_Request

from whad.rf4ce.stack.apl.exceptions import APLTimeoutException
from whad.rf4ce.stack.apl.profiles.mso.database import InformationBase
from whad.rf4ce.stack.apl.profiles.mso.parsers import TXOptionsValue
from whad.rf4ce.utils.adpcm import ADPCM

from enum import IntEnum
from time import sleep, time

class MSOEvent(IntEnum):
    """
    Enum representing types of MSO events.
    """
    DISCOVERY_REQ       = 1
    PAIRING_REQ         = 2
    GET_ATTRIBUTE_REQ   = 3
    VALIDATION_REQ      = 4
    KEY_PRESSED         = 5
    KEY_RELEASED        = 6
    KEY_REPEATED        = 7
    AUDIO_START_REQ     = 8
    AUDIO_STOP_REQ      = 9
    AUDIO_DATA          = 10
    VALIDATION_RSP      = 11

class MSOProfile(APLProfile):
    """
    APL service implementing the MSO Profile.
    """

    def __init__(self):
        self.information_base = InformationBase()
        self.validation = False
        self.keystrokes = False
        self.audio = None
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


    def send_audio(self, audio_filename="/tmp/trololo.wav"):
        """
        Transmit audio packets.
        """
        nwk_layer = self.manager.get_layer('nwk')

        for p in ADPCM.convert_input_file(audio_filename):
            pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Audio()/p

            nwk_layer.get_service('data').data(
                pkt,
                pairing_reference = self.pairing_reference,
                profile_id = self.profile_id,
                vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                tx_options = (
                    TXOptionsValue.pack(
                        broadcast_transmission = False,
                        extended_address_mode = False,
                        acknowledgement_mode = False,
                        security_enabled = True,
                        channel_agility_mode = False,
                        channel_normalization_mode = False,
                        vendor_specific = True
                    )[0]
                )
            )



    def send_key(self, keystroke):
        """
        Transmit a key to target.
        """
        nwk_layer = self.manager.get_layer('nwk')
        code = None
        for key, value in RC_COMMAND_CODES.items():
            if value == keystroke:
                code = key
                break
        pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_User_Control_Pressed(
            code= code
        )

        nwk_layer.get_service('data').data(
            pkt,
            pairing_reference = self.pairing_reference,
            profile_id = self.profile_id,
            vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
            tx_options = (
                TXOptionsValue.pack(
                    broadcast_transmission = False,
                    extended_address_mode = False,
                    acknowledgement_mode = False,
                    security_enabled = True,
                    channel_agility_mode = False,
                    channel_normalization_mode = False,
                    vendor_specific = True
                )[0]
            )
        )

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

    def pairing(self, address, pan_id):
        """
        Establish pairing.
        """
        nwk_layer = self.manager.get_layer('nwk')
        pairing_reference = nwk_layer.get_service('management').pair_request(
            destination_ieee_address=address,
            destination_pan_id=pan_id
        )
        return pairing_reference


    def bind(self, address, pan_id, timeout=30, validation_code_callback = input):

        self.pairing_reference = self.pairing(address, pan_id)

        nwk_layer = self.manager.get_layer('nwk')

        pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Get_Attribute_Request(
            attribute_identifier = 0xDC,
            index = 0,
            value_length = 4
        )

        nwk_layer.get_service('data').data(
            pkt,
            pairing_reference = self.pairing_reference,
            profile_id = self.profile_id,
            vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
            tx_options = (
                TXOptionsValue.pack(
                    broadcast_transmission = False,
                    extended_address_mode = False,
                    acknowledgement_mode = False,
                    security_enabled = True,
                    channel_agility_mode = False,
                    channel_normalization_mode = False,
                    vendor_specific = True
                )[0]
            )
        )

        self.validation = True

        while True:
            pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Request(
                request_automatic_validation = "yes"
            )

            nwk_layer.get_service('data').data(
                pkt,
                pairing_reference = self.pairing_reference,
                profile_id = self.profile_id,
                vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                tx_options = (
                    TXOptionsValue.pack(
                        broadcast_transmission = False,
                        extended_address_mode = False,
                        acknowledgement_mode = False,
                        security_enabled = True,
                        channel_agility_mode = False,
                        channel_normalization_mode = False,
                        vendor_specific = True
                    )[0]
                )
            )
            start_time = time()
            while (time() - start_time) < 1:

                try:
                    event = self.wait_for_packet(lambda _ : True)
                    if event[0] == MSOEvent.VALIDATION_RSP:
                        if event[1].check_validation_status == 0:
                            return True
                        elif event[1].check_validation_status > 0xc0:
                            return False
                except APLTimeoutException:
                    pass

                if validation_code_callback is not None:
                    for i in str(validation_code_callback()):
                        self.send_key(i)

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

    def wait_for_validation_code(self, code, timeout=30):
        self.keystrokes = True
        self.validation = True

        if isinstance(code, int):
            validation_code = str(code)
        elif isinstance(code, str):
            validation_code = code
        else:
            return False

        start_time = time()

        while (time() - start_time) < timeout:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.KEY_PRESSED:
                    if validation_code.startswith(event[1][0]):
                        validation_code = validation_code[1:]
                        if len(validation_code) == 0:
                            self.keystrokes = False
                            return True
                    else:
                        self.keystrokes = False
                        return False

                elif event[0] == MSOEvent.VALIDATION_REQ:
                    pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                        check_validation_status = 0xC0 # pending
                    )

                    nwk_layer = self.manager.get_layer('nwk')

                    nwk_layer.get_service('data').data(
                        pkt,
                        pairing_reference = self.pairing_reference,
                        profile_id = self.profile_id,
                        vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                        tx_options = (
                            TXOptionsValue.pack(
                                broadcast_transmission = False,
                                extended_address_mode = True,
                                acknowledgement_mode = False,
                                security_enabled = True,
                                channel_agility_mode = False,
                                channel_normalization_mode = False,
                                vendor_specific = True
                            )[0]
                        )
                    )
            except APLTimeoutException:
                pass

        self.keystrokes = False
        return False

    def accept_validation(self):
        """
        Accept validation phase.
        """
        self.validation = True

        while True:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.VALIDATION_REQ:
                    pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                        check_validation_status = 0x00
                    )

                    nwk_layer = self.manager.get_layer('nwk')

                    for _ in range(3):
                        nwk_layer.get_service('data').data(
                            pkt,
                            pairing_reference = self.pairing_reference,
                            profile_id = self.profile_id,
                            vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                            tx_options = (
                                TXOptionsValue.pack(
                                    broadcast_transmission = False,
                                    extended_address_mode = True,
                                    acknowledgement_mode = False,
                                    security_enabled = True,
                                    channel_agility_mode = False,
                                    channel_normalization_mode = False,
                                    vendor_specific = True
                                )[0]
                            )
                        )
                    return True

            except APLTimeoutException:
                pass
        return False

    def deny_validation(self):
        """
        Deny validation phase.
        """
        self.validation = True

        while True:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.VALIDATION_REQ:
                    pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Check_Validation_Response(
                        check_validation_status = 0xC3
                    )

                    nwk_layer = self.manager.get_layer('nwk')

                    for _ in range(3):
                        nwk_layer.get_service('data').data(
                            pkt,
                            pairing_reference = self.pairing_reference,
                            profile_id = self.profile_id,
                            vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                            tx_options = (
                                TXOptionsValue.pack(
                                    broadcast_transmission = False,
                                    extended_address_mode = True,
                                    acknowledgement_mode = False,
                                    security_enabled = True,
                                    channel_agility_mode = False,
                                    channel_normalization_mode = False,
                                    vendor_specific = True
                                )[0]
                            )
                        )
                    return True

            except APLTimeoutException:
                pass
        return False

    def key_stream(self):
        self.keystrokes = True
        while True:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.KEY_PRESSED:
                    yield event[1]
            except APLTimeoutException:
                pass

    def audio_stream(self):
        while True:
            try:
                event = self.wait_for_packet(lambda _ : True)
                if event[0] == MSOEvent.AUDIO_DATA:
                    yield event[2]
            except APLTimeoutException:
                pass

    def save_audio(self, filename):
        self.audio = ADPCM(output_filename = filename)

    def live_audio(self):
        self.audio = ADPCM(live_play = True)

    def on_audio_payload(self, payload):
        if self.audio is not None:
            self.audio.process_packet(payload)

        if RF4CE_Vendor_MSO_Audio_Start_Request in payload:
            self.add_packet_to_queue(
                (
                    MSOEvent.AUDIO_START_REQ,
                    payload.sample_rate,
                    payload.resolution_bits,
                    payload.mic_channel_number,
                    payload.codec_type,
                    payload.packet_size,
                    payload.interval,
                    payload.channel_number,
                    payload.duration,
                )
            )
            pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Audio()/RF4CE_Vendor_MSO_Audio_Start_Response()

            nwk_layer = self.manager.get_layer('nwk')
            nwk_layer.get_service('data').data(
                pkt,
                pairing_reference = self.pairing_reference,
                profile_id = self.profile_id,
                vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                tx_options = (
                    TXOptionsValue.pack(
                        broadcast_transmission = False,
                        extended_address_mode = True,
                        acknowledgement_mode = False,
                        security_enabled = True,
                        channel_agility_mode = False,
                        channel_normalization_mode = False,
                        vendor_specific = True
                    )[0]
                )
            )

        elif RF4CE_Vendor_MSO_Audio_Stop_Request in payload:
            self.add_packet_to_queue(
                (
                    MSOEvent.AUDIO_STOP_REQ,
                )
            )
            pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Audio()/RF4CE_Vendor_MSO_Audio_Stop_Response()

            nwk_layer = self.manager.get_layer('nwk')
            nwk_layer.get_service('data').data(
                pkt,
                pairing_reference = self.pairing_reference,
                profile_id = self.profile_id,
                vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
                tx_options = (
                    TXOptionsValue.pack(
                        broadcast_transmission = False,
                        extended_address_mode = True,
                        acknowledgement_mode = False,
                        security_enabled = True,
                        channel_agility_mode = False,
                        channel_normalization_mode = False,
                        vendor_specific = True
                    )[0]
                )
            )
        elif RF4CE_Vendor_MSO_Audio_Data_Notify in payload:
            self.add_packet_to_queue(
                (
                    MSOEvent.AUDIO_DATA,
                    payload.header,
                    payload.samples
                )
            )

    def on_user_control_pressed_payload(self, payload):
        """
        Callback processing user control pressed payload.
        """
        if payload.code in RC_COMMAND_CODES:
            print("[i] MSO - control pressed - ", RC_COMMAND_CODES[payload.code])
        else:
            print("[i] MSO - control pressed - unknown")

        if self.keystrokes:
            self.add_packet_to_queue(
                (
                    MSOEvent.KEY_PRESSED,
                    RC_COMMAND_CODES[payload.code]
                )
            )

    def on_user_control_repeated_payload(self, payload):
        """
        Callback processing user control repeated payload.
        """
        print("[i] MSO - control repeated")

        if self.keystrokes:
            self.add_packet_to_queue(
                (
                    MSOEvent.KEY_REPEATED
                )
            )

    def on_user_control_released_payload(self, payload):
        """
        Callback processing user control released payload.
        """
        print("[i] MSO - control released")

        if self.keystrokes:
            self.add_packet_to_queue(
                (
                    MSOEvent.KEY_RELEASED
                )
            )

    def on_check_validation_request_payload(self, payload):
        """
        Callback processing check validation request payload.
        """
        if self.validation:
            self.add_packet_to_queue(
                (
                    MSOEvent.VALIDATION_REQ,
                    payload
                )
            )
        return


    def on_check_validation_response_payload(self, payload):
        """
        Callback processing check validation response payload.
        """
        if self.validation:
            self.add_packet_to_queue(
                (
                    MSOEvent.VALIDATION_RSP,
                    payload
                )
            )
        return



    def on_get_attribute_response_payload(self, payload):
        """
        Callback processing Get Attribute Response payload.
        """
        print("[i] Get attribute response:", payload.value.hex())

    def on_get_attribute_request_payload(self, payload):
        """
        Callback processing Get Attribute Request payload.
        """
        attribute = self.information_base.get(lambda attribute : attribute.identifier == payload.attribute_identifier)
        if attribute is not None:
            value = attribute.value[payload.index:payload.index + payload.value_length]
            status = 0
        else:
            value = b""
            status = 1

        pkt = RF4CE_Vendor_MSO_Hdr()/RF4CE_Vendor_MSO_Get_Attribute_Response(
            attribute_identifier = payload.attribute_identifier,
            index = payload.index,
            status = status,
            value = value,
            value_length = len(value)
        )

        nwk_layer = self.manager.get_layer('nwk')
        nwk_layer.get_service('data').data(
            pkt,
            pairing_reference = self.pairing_reference,
            profile_id = self.profile_id,
            vendor_id = self.manager.get_layer('nwk').database.get("nwkVendorIdentifier"),
            tx_options = (
                TXOptionsValue.pack(
                    broadcast_transmission = False,
                    extended_address_mode = True,
                    acknowledgement_mode = False,
                    security_enabled = True,
                    channel_agility_mode = False,
                    channel_normalization_mode = False,
                    vendor_specific = True
                )[0]
            )
        )

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

        elif RF4CE_Vendor_MSO_Get_Attribute_Request in npdu:
            self.on_get_attribute_request_payload(npdu[RF4CE_Vendor_MSO_Get_Attribute_Request])

        elif RF4CE_Vendor_MSO_Get_Attribute_Response in npdu:
            self.on_get_attribute_response_payload(npdu[RF4CE_Vendor_MSO_Get_Attribute_Response])

        elif RF4CE_Vendor_MSO_Check_Validation_Request in npdu:
            self.on_check_validation_request_payload(npdu[RF4CE_Vendor_MSO_Check_Validation_Request])
        elif RF4CE_Vendor_MSO_Check_Validation_Response in npdu:
            self.on_check_validation_response_payload(npdu[RF4CE_Vendor_MSO_Check_Validation_Response])
        elif RF4CE_Vendor_MSO_Audio in npdu:
            self.on_audio_payload(npdu[RF4CE_Vendor_MSO_Audio])

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
