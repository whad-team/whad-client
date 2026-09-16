"""
ANT+ Weight Scale profile.
"""
from whad.ant.stack.app.profiles.antplus import (
    DataPageDescriptor,
    AntPlusGenericSensor,
    AntPlusGenericDisplay,
)
from whad.scapy.layers.ant import (
    ANT_Plus_Weight_Scale_Header_Hdr,
    ANT_Plus_Weight_Scale_Body_Weight_Data_Page,
    ANT_Plus_Weight_Scale_Body_Composition_Percentage_Data_Page,
    ANT_Plus_Weight_Scale_Body_Metabolic_Information_Data_Page,
    ANT_Plus_Weight_Scale_Body_Composition_Mass_Data_Page,
    ANT_Weight_Scale_Manufacturer_Information_Data_Page,
    ANT_Weight_Scale_Product_Information_Data_Page,
    ANT_Weight_Scale_Battery_Status_Data_Page,
    ANT_Plus_User_Profile_Data_Page,
    ANT_MANUFACTURERS_ID,
    ANT_Request_Data_Page,
)
from time import sleep
from queue import Empty

WEIGHT_SCALE_PAGE_DESCRIPTORS = {
    1: DataPageDescriptor(
        ANT_Plus_Weight_Scale_Body_Weight_Data_Page,
        page_number=1,
        is_background=False,
    ),
    2: DataPageDescriptor(
        ANT_Plus_Weight_Scale_Body_Composition_Percentage_Data_Page,
        page_number=2,
        is_background=False,
    ),
    3: DataPageDescriptor(
        ANT_Plus_Weight_Scale_Body_Metabolic_Information_Data_Page,
        page_number=3,
        is_background=False,
    ),
    4: DataPageDescriptor(
        ANT_Plus_Weight_Scale_Body_Composition_Mass_Data_Page,
        page_number=4,
        is_background=False,
    ),
    0x50: DataPageDescriptor(
        ANT_Weight_Scale_Manufacturer_Information_Data_Page,
        page_number=0x50,
        is_background=True,
    ),
    0x51: DataPageDescriptor(
        ANT_Weight_Scale_Product_Information_Data_Page,
        page_number=0x51,
        is_background=True,
    ),
    0x52: DataPageDescriptor(
        ANT_Weight_Scale_Battery_Status_Data_Page,
        page_number=0x52,
        is_background=True,
    ),
    0x3A: DataPageDescriptor(
        ANT_Plus_User_Profile_Data_Page,
        page_number=0x3A,
        is_background=False,
    ),
}


class WeightScaleSensor(AntPlusGenericSensor):
    """ANT+ Weight Scale (Device Type 119).

    Transmits body weight data (page 1) at  1 Hz, with optional user-specific data pages (2-4) when a
    valid user profile has been received.

    Background pages (Manufacturer, Product, Battery) are sent according to the recommended transmission pattern.
    """
    DEVICE_TYPE = 119
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8192
    SEARCH_TIMEOUT = 0

    header_class = ANT_Plus_Weight_Scale_Header_Hdr
    has_page_number_in_header = True

    cumulative_operating_time_attr = None

    data_page_descriptors = WEIGHT_SCALE_PAGE_DESCRIPTORS
    default_page_index = 1  # Body Weight

    update_rate = 1 / 4.0

    def __init__(self):
        super().__init__()

        self.user_profile_id = 0xFFFF
        self.user_profile_locked = False
        self.user_specific_data_enabled = False

        self.body_weight = None
        self.hydration = None
        self.body_fat = None
        self.active_metabolic_rate = None
        self.basal_metabolic_rate = None
        self.muscle_mass = None
        self.bone_mass = None

        self._ws_request = None

    def reset(self):
        """
        Reset weight scale state.
        """
        super().reset()
        self.body_weight = None
        self.hydration = None
        self.body_fat = None
        self.active_metabolic_rate = None
        self.basal_metabolic_rate = None
        self.muscle_mass = None
        self.bone_mass = None
        self.user_profile_id = 0xFFFF
        self.user_profile_locked = False
        self.user_specific_data_enabled = False
        self._ws_request = None

    def set_weight(self, weight_kg):
        """
        Set the weight measurement (in kg).
        """
        if weight_kg is not None:
            self.body_weight = int(weight_kg * 100)
        else:
            self.body_weight = 0xFFFE  # Computing/Idle

    def set_body_composition_percentage(
        self,
        hydration_percent=None,
        body_fat_percent=None
    ):
        """
        Set body composition percentage data.
        """
        if hydration_percent is not None:
            self.hydration = int(hydration_percent * 100)
        if body_fat_percent is not None:
            self.body_fat = int(body_fat_percent * 100)

    def set_metabolic_information(self, active_met_kcal=None, basal_met_kcal=None):
        """
        Set metabolic information (in kcal, resolution 0.25 kcal).
        """
        if active_met_kcal is not None:
            self.active_metabolic_rate = int(active_met_kcal * 4)
        if basal_met_kcal is not None:
            self.basal_metabolic_rate = int(basal_met_kcal * 4)

    def set_body_composition_mass(self, muscle_mass_kg=None, bone_mass_kg=None):
        """
        Set body composition mass data.
        """
        if muscle_mass_kg is not None:
            self.muscle_mass = int(muscle_mass_kg * 100)
        if bone_mass_kg is not None:
            self.bone_mass = int(bone_mass_kg * 10)

    @property
    def _capabilities_byte(self):
        """
        Build the capabilities bit for page 1.
        """
        value = 0
        # bit 0: Scale User Profile Selected
        if self.user_profile_locked and self.user_profile_id != 0xFFFF:
            value |= (1 << 0)
        # bit 1: Scale User Profile Exchange
        value |= (1 << 1) # supported
        # bit 2: Scale ANT-FS support (not implemented)
        # bits 3-4: Scale User Specific Data Transmission
        if self.user_specific_data_enabled:
            value |= (0b01 << 3)  # send user specific data
        else:
            value |= (0b10 << 3)  # never send user specific data
        # bit 7: Display User Profile Storage
        return value

    def _get_page_kwargs(self, descriptor):
        """
        Build arguments for a weight scale data page.
        """
        kwargs = {}
        layer = descriptor.layer_class()
        for field in layer.fields_desc:
            if field.name in ('reserved', 'reserved1', 'reserved2',
                              'reserved_2', 'reserved_3', 'reserved_4'):
                continue
            if descriptor.layer_class == ANT_Plus_Weight_Scale_Body_Weight_Data_Page:
                if field.name == 'user_profile_identification':
                    kwargs[field.name] = self.user_profile_id
                elif field.name == 'body_weight':
                    kwargs[field.name] = (self.body_weight if self.body_weight
                                          is not None else 0xFFFE)
            elif descriptor.layer_class in (
                ANT_Plus_Weight_Scale_Body_Composition_Percentage_Data_Page,
                ANT_Plus_Weight_Scale_Body_Metabolic_Information_Data_Page,
                ANT_Plus_Weight_Scale_Body_Composition_Mass_Data_Page,
            ):
                if field.name == 'user_profile_identification':
                    kwargs[field.name] = self.user_profile_id
                elif field.name == 'hydration':
                    kwargs[field.name] = (
                        self.hydration
                        if self.hydration is not None
                        else 0xFFFF
                    )
                elif field.name == 'body_fat':
                    kwargs[field.name] = (
                        self.body_fat
                        if self.body_fat is not None
                        else 0xFFFF
                    )
                elif field.name == 'active_metabolic_rate':
                    kwargs[field.name] = (
                        self.active_metabolic_rate
                        if self.active_metabolic_rate
                        is not None else 0xFFFF
                    )
                elif field.name == 'basal_metabolic_rate':
                    kwargs[field.name] = (
                        self.basal_metabolic_rate
                        if self.basal_metabolic_rate
                        is not None else 0xFFFF
                    )
                elif field.name == 'muscle_mass':
                    kwargs[field.name] = (
                        self.muscle_mass
                        if self.muscle_mass is not None
                        else 0xFFFF
                    )
                elif field.name == 'bone_mass':
                    kwargs[field.name] = (
                        self.bone_mass
                        if self.bone_mass is not None
                        else 0xFF
                    )
                elif field.name == 'reserved':
                    kwargs[field.name] = 0xFF
            elif descriptor.layer_class == ANT_Weight_Scale_Manufacturer_Information_Data_Page:
                if field.name == 'manufacturer_id':
                    kwargs[field.name] = ANT_MANUFACTURERS_ID.get(
                        self.manufacturer_id, 0
                    )
                elif field.name == 'serial_number':
                    kwargs[field.name] = self.serial_number
            elif descriptor.layer_class == ANT_Weight_Scale_Product_Information_Data_Page:
                if field.name == 'hardware_version':
                    kwargs[field.name] = self.hardware_version
                elif field.name == 'software_version':
                    kwargs[field.name] = self.software_version
                elif field.name == 'model_number':
                    kwargs[field.name] = self.model_number
            elif descriptor.layer_class == ANT_Weight_Scale_Battery_Status_Data_Page:
                if field.name == 'fractional_battery_voltage':
                    kwargs[field.name] = self.fractional_battery_voltage
                elif field.name == 'coarse_battery_voltage':
                    kwargs[field.name] = self.coarse_battery_voltage
                elif field.name == 'battery_status':
                    kwargs[field.name] = 3  # OK
        return kwargs

    def send_default_page(self):
        """
        Send body weight data page (page 1).
        """
        header = self._build_header(data_page_number=1)
        packet = header / ANT_Plus_Weight_Scale_Body_Weight_Data_Page(
            user_profile_identification=self.user_profile_id,
            display_user_profile_storage=0,
            reserved1=0,
            scale_user_specific_data=(
                0b01 if self.user_specific_data_enabled else 0b10
            ),
            scale_antfs_support=0,
            scale_user_profile_exchange=1,
            scale_user_profile_selected=(
                1 if (self.user_profile_locked
                      and self.user_profile_id != 0xFFFF) else 0
            ),
            reserved2=0xFFFF,
            body_weight=(self.body_weight if self.body_weight is not None else 0xFFFE),
        )
        self.broadcast(packet)

    def send_page(self, descriptor):
        """
        Send a specific data page.
        """
        if descriptor.layer_class == ANT_Plus_Weight_Scale_Body_Weight_Data_Page:
            self.send_default_page()
        else:
            kwargs = self._get_page_kwargs(descriptor)
            header = self._build_header(
                data_page_number=descriptor.page_number
            )
            packet = header / descriptor.build(**kwargs)
            self.broadcast(packet)

    def on_user_profile_received(self, user_profile_id, gender, age,
                                  height, athlete_setting, activity_class):
        """
        Called when a valid user profile is received from the display.
        Override in subclasses to handle user profile data.
        """
        pass

    def on_ack_burst(self, payload):
        """
        Handle ACK burst messages.
        """
        if ANT_Request_Data_Page in payload:
            self._ws_request = (
                payload[ANT_Request_Data_Page].requested_page_number
            )
        elif ANT_Plus_User_Profile_Data_Page in payload:
            profile = payload[ANT_Plus_User_Profile_Data_Page]
            pid = profile.user_profile_identification

            if pid != 0xFFFF: # if a valid profile is received
                self.user_profile_id = pid
                self.user_profile_locked = True
                self.user_specific_data_enabled = True
                self.on_user_profile_received(
                    user_profile_id=pid,
                    gender=profile.gender,
                    age=profile.age,
                    height=profile.user_height,
                    athlete_setting=profile.athlete_setting,
                    activity_class=profile.activity_class,
                )

    def main_loop(self):
        """
        This method implements the Weight Scale main loop.
        20 body weight pages then background pages are transmitted repeatedly.
        """
        bg_descriptors = self._get_background_descriptors()
        bg_index = 0

        while self.is_started():
            # Transmit 20 body weight pages
            for i in range(20):
                if not self.is_started():
                    return
                req = self._ws_request
                if req is not None:
                    self._ws_request = None
                    self._handle_request(req)
                else:
                    self.send_default_page()

                if (i + 1) % 4 == 0:
                    self.toggle_bit = 1 - self.toggle_bit
                self._update_counters()
                sleep(self.update_rate)

            # Transmit background pages
            for _ in range(len(bg_descriptors)):
                if not self.is_started():
                    return
                self.send_page(bg_descriptors[bg_index])
                self.toggle_bit = 1 - self.toggle_bit
                self._update_counters()
                sleep(self.update_rate)
            bg_index = (bg_index + 1) % len(bg_descriptors)


class WeightScaleDisplay(AntPlusGenericDisplay):
    """
    ANT+ Weight Scale Display (Device Type 119).
    """
    DEVICE_TYPE = 119
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8192
    SEARCH_TIMEOUT = 10
    
    header_class = ANT_Plus_Weight_Scale_Header_Hdr
    data_page_descriptors = WEIGHT_SCALE_PAGE_DESCRIPTORS

    def __init__(self):
        super().__init__()
        
        self.body_weight = None             # kg * 100
        self.hydration = None               # % * 100
        self.body_fat = None                # % * 100
        self.active_metabolic_rate = None   # kcal * 4
        self.basal_metabolic_rate = None    # kcal * 4
        self.muscle_mass = None             # kg * 100
        self.bone_mass = None               # kg * 10

        # User profile
        self.user_profile_id = None
        self.user_gender = None
        self.user_age = None
        self.user_height = None
        self.user_athlete_setting = None
        self.user_activity_class = None

        # Capabilities
        self.scale_user_profile_selected = False
        self.scale_user_profile_exchange = False
        self.scale_antfs_support = False
        self.scale_user_specific_data = False

    # Callbacks
    def on_weight_received(self, weight_kg):
        """
        This callback is called when a weight measurement is received.
        It can be overriden in subclasses.
        """
        pass

    def on_body_composition_received(self, hydration_percent=None, body_fat_percent=None):
        """
        This callback is called when a body composition data is received.
        It can be overriden in subclasses.
        """
        pass

    def on_metabolic_information_received(self, active_met_kcal=None, basal_met_kcal=None):
        """
        This callback is called when a metabolic information is received.
        It can be overriden in subclasses.
        """
        pass

    def on_body_composition_mass_received(self, muscle_mass_kg=None, bone_mass_kg=None):
        """
        This callback is called when a body composition mass data is received.
        It can be overriden in subclasses.
        """
        pass

    def on_user_profile_received(self, profile_id, gender, age, height, athlete, activity):
        """
        This callback is called when a user data profile is received.
        It can be overriden in subclasses.
        """
        pass

    def on_broadcast(self, payload):
        """
        Handle weight scale broadcast.
        """

        if self.header_class in payload:
            header = payload[self.header_class]
            data_page_number = header.data_page_number

            if ANT_Plus_Weight_Scale_Body_Weight_Data_Page in payload:
                data = payload[ANT_Plus_Weight_Scale_Body_Weight_Data_Page]
                self.user_profile_id = data.user_profile_identification
                self.scale_user_profile_selected = bool(
                    data.scale_user_profile_selected
                )
                self.scale_user_profile_exchange = bool(
                    data.scale_user_profile_exchange
                )
                self.scale_antfs_support = bool(data.scale_antfs_support)
                self.scale_user_specific_data = (
                    data.scale_user_specific_data == 1
                )

                raw_weight = data.body_weight
                if raw_weight == 0xFFFF:
                    self.body_weight = None # failed
                elif raw_weight == 0xFFFE:
                    self.body_weight = None  # computing/idle
                else:
                    self.body_weight = raw_weight / 100.0

                self.on_weight_received(self.body_weight)

                self._data_queue.put({
                    "body_weight": self.body_weight,
                    "user_profile_id": self.user_profile_id,
                })

            if (ANT_Plus_Weight_Scale_Body_Composition_Percentage_Data_Page in payload):
                data = payload[
                    ANT_Plus_Weight_Scale_Body_Composition_Percentage_Data_Page
                ]
                self.user_profile_id = data.user_profile_identification
                if data.hydration != 0xFFFF:
                    self.hydration = data.hydration / 100.0
                else:
                    self.hydration = None
                if data.body_fat != 0xFFFF:
                    self.body_fat = data.body_fat / 100.0
                else:
                    self.body_fat = None
                self.on_body_composition_received(
                    hydration_percent=self.hydration,
                    body_fat_percent=self.body_fat,
                )

            if (ANT_Plus_Weight_Scale_Body_Metabolic_Information_Data_Page
                    in payload):
                data = payload[
                    ANT_Plus_Weight_Scale_Body_Metabolic_Information_Data_Page
                ]
                self.user_profile_id = data.user_profile_identification
                if data.active_metabolic_rate != 0xFFFF:
                    self.active_metabolic_rate = (
                        data.active_metabolic_rate / 4.0
                    )
                else:
                    self.active_metabolic_rate = None
                if data.basal_metabolic_rate != 0xFFFF:
                    self.basal_metabolic_rate = (
                        data.basal_metabolic_rate / 4.0
                    )
                else:
                    self.basal_metabolic_rate = None
                self.on_metabolic_information_received(
                    active_met_kcal=self.active_metabolic_rate,
                    basal_met_kcal=self.basal_metabolic_rate,
                )

            if (ANT_Plus_Weight_Scale_Body_Composition_Mass_Data_Page
                    in payload):
                data = payload[
                    ANT_Plus_Weight_Scale_Body_Composition_Mass_Data_Page
                ]
                self.user_profile_id = data.user_profile_identification
                if data.muscle_mass != 0xFFFF:
                    self.muscle_mass = data.muscle_mass / 100.0
                else:
                    self.muscle_mass = None
                if data.bone_mass != 0xFF:
                    self.bone_mass = data.bone_mass / 10.0
                else:
                    self.bone_mass = None
                self.on_body_composition_mass_received(
                    muscle_mass_kg=self.muscle_mass,
                    bone_mass_kg=self.bone_mass,
                )

            if ANT_Plus_User_Profile_Data_Page in payload:
                data = payload[ANT_Plus_User_Profile_Data_Page]
                self.user_profile_id = data.user_profile_identification
                self.user_gender = data.gender
                self.user_age = data.age
                self.user_height = data.user_height
                self.user_athlete_setting = data.athlete_setting
                self.user_activity_class = data.activity_class
                self.on_user_profile_received(
                    profile_id=self.user_profile_id,
                    gender=self.user_gender,
                    age=self.user_age,
                    height=self.user_height,
                    athlete=self.user_athlete_setting,
                    activity=self.user_activity_class,
                )

        self._extract_known_attributes(payload)

    def send_user_profile(self, profile_id, gender=0, age=0, height=0, athlete_setting=0, activity_class=0):
        """Send a user profile data page (0x3A) to the weight scale.

        :param profile_id: User profile ID (256-65534 for mobile display, 16-255 for stationary display)
        :param gender: 0 = Female, 1 = Male
        :param age: 0-127 years
        :param height: Height in cm (0-255)
        :param athlete_setting: 0 = Standard, 1 = Lifetime Athlete
        :param activity_class: 0-7 activity level (see spec Table 6-9)
        """
        header = ANT_Plus_Weight_Scale_Header_Hdr(data_page_number=0x3A)
        profile = ANT_Plus_User_Profile_Data_Page(
            user_profile_identification=profile_id,
            display_user_profile_storage=1,
            reserved1=0,
            scale_user_specific_data=0,
            scale_antfs_support=0,
            scale_user_profile_exchange=1,
            scale_user_profile_selected=0,
            reserved2=0xFF,
            age=age & 0x7F,
            gender=gender & 0x01,
            user_height=height,
            athlete_setting=athlete_setting & 0x01,
            reserved3=0,
            activity_class=activity_class & 0x07,
        )
        packet = header / profile
        self.ack(packet)

    def weight_values(self):
        """
        Iterator over received body weight values (in kg).
        """
        while self.is_started() or not self._data_queue.empty():
            try:
                item = self._data_queue.get(timeout=0.5)
                yield item.get("body_weight")
            except Empty:
                continue