"""
ANT+ Bicycle profiles (Speed, Cadence, Combined Speed & Cadence).
"""
from whad.ant.stack.app.profiles.antplus import (
    DataPageDescriptor,
    AntPlusGenericSensor,
    AntPlusGenericDisplay,
)
from whad.scapy.layers.ant import (
    ANT_Plus_Bicycle_Speed_And_Cadence,
    ANT_Plus_Bicycle_Speed_Header_Hdr,
    ANT_Bicycle_Speed_Default_Data_Page,
    ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page,
    ANT_Bicycle_Speed_Manufacturer_Information_Data_Page,
    ANT_Bicycle_Speed_Product_Information_Data_Page,
    ANT_Bicycle_Speed_Battery_Status_Data_Page,
    ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page,
    ANT_Plus_Bicycle_Cadence_Header_Hdr,
    ANT_Bicycle_Cadence_Default_Data_Page,
    ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page,
    ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page,
    ANT_Bicycle_Cadence_Product_Information_Data_Page,
    ANT_Bicycle_Cadence_Battery_Status_Data_Page,
    ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page,
)
from time import time


SPEED_PAGE_DESCRIPTORS = {
    0: DataPageDescriptor(
        ANT_Bicycle_Speed_Default_Data_Page,
        page_number=0,
        is_background=False,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
    1: DataPageDescriptor(
        ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page,
        page_number=1,
        is_background=True,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
    2: DataPageDescriptor(
        ANT_Bicycle_Speed_Manufacturer_Information_Data_Page,
        page_number=2,
        is_background=True,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
    3: DataPageDescriptor(
        ANT_Bicycle_Speed_Product_Information_Data_Page,
        page_number=3,
        is_background=True,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
    4: DataPageDescriptor(
        ANT_Bicycle_Speed_Battery_Status_Data_Page,
        page_number=4,
        is_background=True,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
    5: DataPageDescriptor(
        ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page,
        page_number=5,
        is_background=True,
        event_time_field="bike_speed_event_time",
        cumulative_field="cumulative_speed_revolution_count",
    ),
}

CADENCE_PAGE_DESCRIPTORS = {
    0: DataPageDescriptor(
        ANT_Bicycle_Cadence_Default_Data_Page,
        page_number=0,
        is_background=False,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
    1: DataPageDescriptor(
        ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page,
        page_number=1,
        is_background=True,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
    2: DataPageDescriptor(
        ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page,
        page_number=2,
        is_background=True,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
    3: DataPageDescriptor(
        ANT_Bicycle_Cadence_Product_Information_Data_Page,
        page_number=3,
        is_background=True,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
    4: DataPageDescriptor(
        ANT_Bicycle_Cadence_Battery_Status_Data_Page,
        page_number=4,
        is_background=True,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
    5: DataPageDescriptor(
        ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page,
        page_number=5,
        is_background=True,
        event_time_field="bike_cadence_event_time",
        cumulative_field="cumulative_cadence_revolution_count",
    ),
}

class BikeSpeedSensor(AntPlusGenericSensor):
    """
    ANT+ Bike Speed Sensor (Device Type 123).
    """
    DEVICE_TYPE = 123
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8118

    header_class = ANT_Plus_Bicycle_Speed_Header_Hdr
    has_page_number_in_header = True

    data_page_descriptors = SPEED_PAGE_DESCRIPTORS
    default_page_index = 0
    
    cumulative_count_attr = "cumulative_speed_revolution_count"
    event_time_attr = "bike_speed_event_time"


class BikeSpeedDisplay(AntPlusGenericDisplay):
    """
    ANT+ Bike Speed Display (Device Type 123).
    """
    DEVICE_TYPE = 123
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8118

    header_class = ANT_Plus_Bicycle_Speed_Header_Hdr
    data_page_descriptors = SPEED_PAGE_DESCRIPTORS
    cumulative_count_attr = "cumulative_speed_revolution_count"
    event_time_attr = "bike_speed_event_time"
    
    def on_speed_received(self, cumulative_rev_count, event_time):
        """
        This callback is called when speed data is received.
        It can be overriden in subclasses.
        """
        pass

    def on_data_received(self, **kwargs):
        """
        Forwards generic callback to profile-specific callback.
        """
        cumulative = kwargs.get(self.cumulative_count_attr)
        event_time = kwargs.get(self.event_time_attr)
        if cumulative is not None and event_time is not None:
            self.on_speed_received(cumulative, event_time)


class BikeCadenceSensor(AntPlusGenericSensor):
    """
    ANT+ Bike Cadence Sensor (Device Type 122)
    """
    DEVICE_TYPE = 122
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8102

    header_class = ANT_Plus_Bicycle_Cadence_Header_Hdr
    has_page_number_in_header = True

    data_page_descriptors = CADENCE_PAGE_DESCRIPTORS
    default_page_index = 0

    cumulative_count_attr = "cumulative_cadence_revolution_count"
    event_time_attr = "bike_cadence_event_time"
    


class BikeCadenceDisplay(AntPlusGenericDisplay):
    """
    ANT+ Bike Cadence Display (Device Type 122)
    """
    DEVICE_TYPE = 122
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8102

    header_class = ANT_Plus_Bicycle_Cadence_Header_Hdr
    data_page_descriptors = CADENCE_PAGE_DESCRIPTORS

    cumulative_count_attr = "cumulative_cadence_revolution_count"
    event_time_attr = "bike_cadence_event_time"
    
    def on_cadence_received(self, cumulative_rev_count, event_time):
        """
        This callback is called when cadence data is received. 
        It can be overriden in subclass.
        """
        pass

    def on_data_received(self, **kwargs):
        """
        Forwards generic callback to profile-specific callback.
        """
        cumulative = kwargs.get(self.cumulative_count_attr)
        event_time = kwargs.get(self.event_time_attr)
        if cumulative is not None and event_time is not None:
            self.on_cadence_received(cumulative, event_time)

class CombinedSpeedAndCadenceSensor(AntPlusGenericSensor):
    """
    ANT+ Combined Bike Speed and Cadence Sensor (Device Type 121).
    """
    DEVICE_TYPE = 121
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8086

    header_class = None
    has_page_number_in_header = False

    data_page_descriptors = {
        0 :
            DataPageDescriptor(
                ANT_Plus_Bicycle_Speed_And_Cadence,
                page_number=None,
                is_background=False,
                event_time_field="bike_speed_event_time",
                cumulative_field="cumulative_speed_revolution_count",
            ),
    }

    default_page_index = 0

    def reset(self):
        super().reset()
        self.__start_time = time()
        self.bike_cadence_event_time = 0
        self.cumulative_cadence_revolution_count = 0
        self.cumulative_speed_revolution_count = 0

    def _update_counters(self):
        """
        Update speed and cadence counters.
        """
        elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
        self.bike_speed_event_time = elapsed
        self.bike_cadence_event_time = elapsed
        self.cumulative_speed_revolution_count = (
            self.cumulative_speed_revolution_count + 1
        ) & 0xFFFF
        self.cumulative_cadence_revolution_count = (
            self.cumulative_cadence_revolution_count + 1
        ) & 0xFFFF


class CombinedSpeedAndCadenceDisplay(AntPlusGenericDisplay):
    """
    ANT+ Combined Bike Speed and Cadence Display (Device Type 121)
    """
    DEVICE_TYPE = 121
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8086

    header_class = None
    data_page_descriptors = CombinedSpeedAndCadenceSensor.data_page_descriptors
    event_time_attr = "bike_speed_event_time"
    cumulative_count_attr = "cumulative_speed_revolution_count"

    def __init__(self):
        super().__init__()
        self.bike_cadence_event_time = None
        self.cumulative_cadence_revolution_count = None

    def on_cadence_received(self, cumulative_rev_count, event_time):
        """
        This callback is called when cadence data is received.
        It can be overriden in subclass.
        """
        pass

    def on_speed_received(self, cumulative_rev_count, event_time):
        """
        This callback is called when speed data is received.
        It can be overriden in subclass.
        """
        pass

    def on_broadcast(self, payload):
        """
        Extraction of speed and cadence from broadcast.
        """
        if ANT_Plus_Bicycle_Speed_And_Cadence in payload:
            data = payload[ANT_Plus_Bicycle_Speed_And_Cadence]
            self.bike_cadence_event_time = data.bike_cadence_event_time
            self.cumulative_cadence_revolution_count = (
                data.cumulative_cadence_revolution_count
            )
            self.bike_speed_event_time = data.bike_speed_event_time
            self.cumulative_speed_revolution_count = (
                data.cumulative_speed_revolution_count
            )

            self.on_cadence_received(
                data.cumulative_cadence_revolution_count,
                data.bike_cadence_event_time,
            )
            self.on_speed_received(
                data.cumulative_speed_revolution_count,
                data.bike_speed_event_time,
            )

            self._data_queue.put({
                "bike_speed_event_time": data.bike_speed_event_time,
                "cumulative_speed_revolution_count": (
                    data.cumulative_speed_revolution_count
                ),
                "bike_cadence_event_time": data.bike_cadence_event_time,
                "cumulative_cadence_revolution_count": (
                    data.cumulative_cadence_revolution_count
                ),
            })