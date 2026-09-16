"""
ANT+ profiles base module.
"""
from whad.ant.stack.app.profiles import AntProfile
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.ant.channel import ChannelDirection
from whad.scapy.layers.ant import ANT_MANUFACTURERS_ID, ANT_Plus_Header_Hdr, \
    ANT_Plus_HR_Header_Hdr, ANT_Request_Data_Page
from time import sleep, time
from threading import Thread
from queue import Queue, Empty
import re

class AntPlusProfile(AntProfile):
    """
    Basic ANT+ Profile.
    """

    NETWORK_KEY = ANT_PLUS_NETWORK_KEY
    DEFAULT_RF_CHANNEL = 57

    @property
    def human_readable_name(self):
        name = self.__class__.__name__
        human_readable_name = re.sub(r'(?<!^)(?=[A-Z])', ' ', name)
        return human_readable_name


class AntPlusMasterProfile(AntPlusProfile):
    CHANNEL_DIRECTION = ChannelDirection.TX


class AntPlusSlaveProfile(AntPlusProfile):
    CHANNEL_DIRECTION = ChannelDirection.RX


class DataPageDescriptor:
    """
    Describes a single ANT+ data page in a generic way.
    """

    def __init__(self, layer_class, page_number=None, is_background=False,
                 event_time_field=None, cumulative_field=None):
        self.layer_class = layer_class
        self.page_number = page_number
        self.is_background = is_background
        self.event_time_field = event_time_field
        self.cumulative_field = cumulative_field

    def build(self, **kwargs):
        """
        Build the Scapy layer according to keywords.
        """
        return self.layer_class(**kwargs)

    def extract_fields(self, packet):
        """
        Extract all fields from this page in a packet.
        """
        if self.layer_class not in packet:
            return {}

        fields_structure = {}
        layer = packet[self.layer_class]
        for f in layer.fields_desc:
            if hasattr(layer, f.name):
                fields_structure[f.name] = getattr(layer, f.name) 
        
        return fields_structure
 
class AntPlusGenericSensor(AntPlusMasterProfile):
    """
    Generic ANT+ sensor.

    Subclasses need to define:
    - DEVICE_TYPE, CHANNEL_PERIOD, TRANSMISSION_TYPE
    - data_page_descriptors (list of DataPageDescriptor)
    - default_page_index, background_pages
    - header_class (optional, e.g. ANT_Plus_Bicycle_Speed_Header_Hdr)
    - has_page_number_in_header (True if header carries a data_page_number)
    - event_time_attr, cumulative_count_attr (attribute names on self)
    - update_rate (default 1/4.04)
    """

    # Profile parameters
    DEVICE_TYPE = None
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0

    data_page_descriptors = []
    default_page_index = 0

    header_class = None
    has_page_number_in_header = False

    # Rate
    update_rate = 1 / 4.04

    event_time_attr = None
    cumulative_count_attr = None
    cumulative_operating_time_attr = "cumulative_operating_time"

    def __init__(self):
        super().__init__()
        self.manufacturer_id = "Garmin"
        self.reset()
        self.__thread = None
        self.__start_time = 0
        self._request = None
        
        if (self.event_time_attr is None or self.cumulative_count_attr is None):
            event_time, cumulative = self._infer_specific_attributes()
            if self.event_time_attr is None:
                self.event_time_attr = event_time
            if self.cumulative_count_attr is None:
                self.cumulative_count_attr = cumulative
    
    def _get_descriptor_list(self):
        """
        Get data_page_descriptors as a list (convert from dict if needed).
        """
        if isinstance(self.data_page_descriptors, dict):
            return list(self.data_page_descriptors.values())
        return self.data_page_descriptors
    
    def _get_background_descriptors(self):
        """
        Get all background data page descriptors.
        """
        return [desc for desc in self._get_descriptor_list() 
                if desc.is_background]
    
    def _infer_specific_attributes(self):
        """
        Infer event_time_attr and cumulative_count_attr from descriptors.
        """
        event_time_attr = None
        cumulative_count_attr = None
        
        for desc in self._get_descriptor_list():
            if desc.event_time_field and not event_time_attr:
                event_time_attr = desc.event_time_field
            if desc.cumulative_field and not cumulative_count_attr:
                cumulative_count_attr = desc.cumulative_field
        
        return event_time_attr, cumulative_count_attr

    def reset(self):
        """
        Reset sensor state.
        """
        self.toggle_bit = 0
        self.serial_number = 1234
        self.hardware_version = 1
        self.software_version = 12
        self.model_number = 44
        self.battery_level = 98
        self.fractional_battery_voltage = 251
        self.coarse_battery_voltage = 8
        self.cumulative_operating_time = 0
        self.stop_indicator = 0

        if self.event_time_attr is not None:
            setattr(self, self.event_time_attr, 0)
        if self.cumulative_count_attr is not None:
            setattr(self, self.cumulative_count_attr, 0)

    def _build_header(self, data_page_number=None):
        """
        Build the ANT+ header (with optional sub-header).
        """
        if self.header_class is not None:
            if self.has_page_number_in_header and data_page_number is not None:
                return ANT_Plus_Header_Hdr() / self.header_class(
                    toggle_bit=self.toggle_bit,
                    data_page_number=data_page_number
                )
            else:
                return ANT_Plus_Header_Hdr() / self.header_class(
                    toggle_bit=self.toggle_bit
                )
        return ANT_Plus_Header_Hdr()

    def _get_page_kwargs(self, descriptor):
        """
        Build keyword arguments for a data page layer.
        """
        kwargs = {}
        layer = descriptor.layer_class()
        for field in layer.fields_desc:
            if field.name in ('reserved', 'reserved_2'):
                continue
            if (descriptor.event_time_field is not None
                    and field.name == descriptor.event_time_field):
                kwargs[field.name] = getattr(self, self.event_time_attr, 0)
            elif (descriptor.cumulative_field is not None
                  and field.name == descriptor.cumulative_field):
                kwargs[field.name] = getattr(self, self.cumulative_count_attr, 0)
            elif field.name == 'cumulative_operating_time':
                kwargs[field.name] = self.cumulative_operating_time
            elif field.name == 'manufacturer_id':
                kwargs[field.name] = ANT_MANUFACTURERS_ID.get(
                    self.manufacturer_id, 0
                )
            elif field.name == 'serial_number':
                kwargs[field.name] = self.serial_number
            elif field.name == 'hardware_version':
                kwargs[field.name] = self.hardware_version
            elif field.name == 'software_version':
                kwargs[field.name] = self.software_version
            elif field.name == 'model_number':
                kwargs[field.name] = self.model_number
            elif field.name == 'fractional_battery_voltage':
                kwargs[field.name] = self.fractional_battery_voltage
            elif field.name == 'battery_level':
                kwargs[field.name] = self.battery_level
            elif field.name == 'battery_status':
                kwargs[field.name] = 3  # OK
            elif field.name == 'coarse_battery_voltage':
                kwargs[field.name] = self.coarse_battery_voltage
            elif field.name == 'flags':
                kwargs[field.name] = self.stop_indicator
        return kwargs

    def _get_extra_layers(self, descriptor):
        """
        Return extra Scapy layers to append after the data page.
        It must be overriden in subclasses (for example, HRM common payload).
        """
        return []

    def send_page(self, descriptor):
        """
        Broadcast a data page.
        """
        kwargs = self._get_page_kwargs(descriptor)
        header = self._build_header(data_page_number=descriptor.page_number)
        packet = header / descriptor.build(**kwargs)
        for extra in self._get_extra_layers(descriptor):
            packet = packet / extra
        self.broadcast(packet)

    def send_default_page(self):
        """
        Send the default data page.
        """
        descriptors = self._get_descriptor_list()
        self.send_page(descriptors[self.default_page_index])

    def start(self):
        """
        Start the sensor main loop.
        """
        super().start()
        self.__start_time = time()
        self.__thread = Thread(target=self.main_loop, daemon=True)
        self.__thread.start()

    def main_loop(self):
        """
        Implementation of the main loop of the sensor.
        By default, main loop is 64 main pages + background pages, repeated.
        This method must be overriden in subclasses to change the pattern.
        """
        background_descriptors = self._get_background_descriptors()
        background_index = 0

        while self.is_started():
            # Transmit 64 main pages
            for i in range(64):
                if not self.is_started():
                    return
                req = self._request
                if req is not None:
                    self._request = None
                    self._handle_request(req)
                else:
                    self.send_default_page()
                if (i + 1) % 4 == 0:
                    self.toggle_bit = 1 - self.toggle_bit
                self._update_counters()
                sleep(self.update_rate)

            # Transmit background pages
            for _ in range(len(background_descriptors)):
                if not self.is_started():
                    return
                self.send_page(background_descriptors[background_index])
                self.toggle_bit = 1 - self.toggle_bit
                self._update_counters()
                sleep(self.update_rate)
            if len(background_descriptors) > 0:
                background_index = (background_index + 1) % len(background_descriptors)

    def _handle_request(self, requested_page):
        """
        Handle a data page request transmitted by a display.
        """
        if isinstance(self.data_page_descriptors, dict):
            if requested_page in self.data_page_descriptors:
                self.send_page(self.data_page_descriptors[requested_page])
                return
        else:
            for desc in self.data_page_descriptors:
                if desc.page_number == requested_page:
                    self.send_page(desc)
                    return
        self.send_default_page()

    def _update_counters(self):
        """
        Update event_time, cumulative_count and operating_time.
        """
        elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
        if self.event_time_attr is not None:
            setattr(self, self.event_time_attr, elapsed)
        if self.cumulative_count_attr is not None:
            current = getattr(self, self.cumulative_count_attr, 0)
            setattr(self, self.cumulative_count_attr, (current + 1) & 0xFFFF)
        if self.cumulative_operating_time_attr is not None:
            self.cumulative_operating_time = (
                int(time() - self.__start_time) // 2
            ) & 0xFFFFFF

    def on_ack_burst(self, payload):
        """
        Handle ACK burst (used for data page requests).
        """
        if ANT_Request_Data_Page in payload:
            self._request = payload[ANT_Request_Data_Page].requested_page_number

    def stop(self):
        """
        Stop the sensor.
        """
        super().stop()
        if self.__thread is not None:
            self.__thread.join()


class AntPlusGenericDisplay(AntPlusSlaveProfile):
    """
    Generic ANT+ display.

    Subclasses need to implement or override:
    - DEVICE_TYPE, CHANNEL_PERIOD, TRANSMISSION_TYPE
    - data_page_descriptors
    - header_class
    - event_time_attr, cumulative_count_attr
    """

    DEVICE_TYPE = None
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 30

    data_page_descriptors = []
    header_class = None
    event_time_attr = None
    cumulative_count_attr = None

    def __init__(self):
        super().__init__()
        self.manufacturer_id = None
        self.serial_number = None
        self.hardware_version = None
        self.software_version = None
        self.model_number = None
        self.battery_level = None
        self.fractional_battery_voltage = None
        self.coarse_battery_voltage = None
        self.cumulative_operating_time = None
        self.stop_indicator = None
        self._data_page_response = None

        if self.event_time_attr is not None:
            setattr(self, self.event_time_attr, None)
        if self.cumulative_count_attr is not None:
            setattr(self, self.cumulative_count_attr, None)

        self._data_queue = Queue()


    def request_data_page(self, requested_page_number, number_of_responses=2,
                          acknowledged_response=False, timeout=3):
        request = (ANT_Plus_Header_Hdr() /
            ANT_Plus_HR_Header_Hdr() /
            ANT_Request_Data_Page(
                requested_transmission_response_using_ack=(
                    1 if acknowledged_response else 0
                ),
                requested_transmission_response_count=number_of_responses,
                requested_page_number=requested_page_number
            )
        )
        self._data_page_response = None
        self.ack(request)
        start = time()
        while self._data_page_response is None or self._data_page_response.data_page_number != requested_page_number:
            sleep(0.1)
            if time() - start >= timeout:
                return None

        return self._data_page_response

    def on_data_received(self, **kwargs):
        """
        Called when measurement data is received.
        This method must be overriden in subclasses.
        """
        pass

    def on_page_received(self, page_descriptor, fields):
        """
        Called for every received data page.
        This method must be overriden in subclasses.
        """
        pass

    def _extract_known_attributes(self, payload):
        """
        Extract common attributes from any received data page.
        """
        for (desc_number, desc) in self.data_page_descriptors.items():
            if desc.layer_class not in payload:
                continue
            data = payload[desc.layer_class]

            # Standard attributes
            for attr_name in [
                "manufacturer_id",
                "serial_number",
                "hardware_version",
                "software_version",
                "model_number",
                "battery_level",
                "fractional_battery_voltage",
                "coarse_battery_voltage",
                "cumulative_operating_time",
            ]:
                if hasattr(data, attr_name):
                    value = getattr(data, attr_name)
                    if attr_name == "manufacturer_id" and isinstance(value, int):
                        for name, mid in ANT_MANUFACTURERS_ID.items():
                            if mid == value:
                                setattr(self, attr_name, name)
                                break
                    else:
                        setattr(self, attr_name, value)

            # Specific fields
            fields = {}
            if (desc.event_time_field is not None
                    and hasattr(data, desc.event_time_field)):
                value = getattr(data, desc.event_time_field)
                if self.event_time_attr is not None:
                    setattr(self, self.event_time_attr, value)
                fields[desc.event_time_field] = value

            if (desc.cumulative_field is not None
                    and hasattr(data, desc.cumulative_field)):
                value = getattr(data, desc.cumulative_field)
                if self.cumulative_count_attr is not None:
                    setattr(self, self.cumulative_count_attr, value)
                fields[desc.cumulative_field] = value

            self._data_page_response = payload
            self.on_page_received(desc, fields)
            if fields:
                self.on_data_received(**fields)
                self._data_queue.put(fields)
            return True
        return False

    def on_broadcast(self, payload):
        """
        Generic broadcast handler.
        """
        if self.header_class is not None and self.header_class not in payload:
            return
        self._extract_known_attributes(payload)

    def data_iterator(self):
        """
        Iterate over received data dicts.
        """
        while self.is_started() or not self._data_queue.empty():
            try:
                yield self._data_queue.get(timeout=0.5)
            except Empty:
                continue


from whad.ant.stack.app.profiles.antplus.hrm import HeartRateDisplay, HeartRateMonitor
from whad.ant.stack.app.profiles.antplus.bsc import (
    CombinedSpeedAndCadenceSensor,
    BikeSpeedSensor,
    BikeCadenceSensor,
    CombinedSpeedAndCadenceDisplay,
    BikeSpeedDisplay,
    BikeCadenceDisplay,
)
from whad.ant.stack.app.profiles.antplus.ws import (
    WeightScaleSensor,
    WeightScaleDisplay,
)

ANTPLUS_PROFILES = (
    HeartRateDisplay,
    HeartRateMonitor,
    CombinedSpeedAndCadenceSensor,
    CombinedSpeedAndCadenceDisplay,
    BikeSpeedSensor,
    BikeSpeedDisplay,
    BikeCadenceSensor,
    BikeCadenceDisplay,
    WeightScaleSensor,
    WeightScaleDisplay,
)


def find_slave_profile(device_type):
    for profile in ANTPLUS_PROFILES:
        if profile.DEVICE_TYPE == device_type and issubclass(profile, AntPlusSlaveProfile):
            return profile
    return None


def find_master_profile(device_type):
    for profile in ANTPLUS_PROFILES:
        if profile.DEVICE_TYPE == device_type and issubclass(profile, AntPlusMasterProfile):
            return profile
    return None