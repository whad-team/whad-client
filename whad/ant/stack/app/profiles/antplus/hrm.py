"""
ANT+ Heart Rate Monitor profile.
"""
from whad.ant.stack.app.profiles.antplus import (
    DataPageDescriptor,
    AntPlusGenericSensor,
    AntPlusGenericDisplay,
)
from whad.scapy.layers.ant import (
    ANT_Plus_HR_Header_Hdr,
    ANT_HR_Default_Data_Page,
    ANT_HR_Manufacturer_Information_Data_Page,
    ANT_HR_Product_Information_Data_Page,
    ANT_HR_Battery_Status_Data_Page,
    ANT_HR_Previous_Heart_Beat_Data_Page,
    ANT_HR_Cumulative_Operating_Time_Data_Page,
    ANT_HR_Swim_Interval_Summary_Data_Page,
    ANT_HR_Common_Payload,
    ANT_MANUFACTURERS_ID,
    ANT_Request_Data_Page,
)
from time import sleep, time
from queue import Empty


HRM_PAGE_DESCRIPTORS = {
    0: DataPageDescriptor(
        ANT_HR_Default_Data_Page,
        page_number=0,
        is_background=False,
    ),
    1: DataPageDescriptor(
        ANT_HR_Cumulative_Operating_Time_Data_Page,
        page_number=1,
        is_background=True,
    ),
    2: DataPageDescriptor(
        ANT_HR_Manufacturer_Information_Data_Page,
        page_number=2,
        is_background=True,
    ),
    3: DataPageDescriptor(
        ANT_HR_Product_Information_Data_Page,
        page_number=3,
        is_background=True,
    ),
    4: DataPageDescriptor(
        ANT_HR_Previous_Heart_Beat_Data_Page,
        page_number=4,
        is_background=True,
    ),

    5: DataPageDescriptor(
        ANT_HR_Swim_Interval_Summary_Data_Page,
        page_number=5,
        is_background=True,
    ),

    6: DataPageDescriptor(
        ANT_HR_Previous_Heart_Beat_Data_Page,
        page_number=6,
        is_background=True,
    ),
    7: DataPageDescriptor(
        ANT_HR_Battery_Status_Data_Page,
        page_number=7,
        is_background=True,
    ),


}

class HeartRateMonitor(AntPlusGenericSensor):
    """
    ANT+ Heart Rate Monitor sensor (Device Type 120).
    """
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0

    header_class = ANT_Plus_HR_Header_Hdr
    has_page_number_in_header = False

    cumulative_operating_time_attr = None

    update_rate = 1 / 4.06

    data_page_descriptors = HRM_PAGE_DESCRIPTORS
    default_page_index = 4

    def reset(self):
        """
        Reset HRM state.
        """
        super().reset()
        self.computed_heart_rate = 60
        self.previous_heart_beat = 60
        self.heart_beat_event_time = 0
        self.heart_beat_count = 0

    def _get_extra_layers(self, descriptor):
        """
        HRM always appends the common payload (heart rate data)
        after every data page.
        """
        return [
            ANT_HR_Common_Payload(
                heart_beat_event_time=self.heart_beat_event_time,
                heart_beat_count=self.heart_beat_count,
                computed_heart_rate=self.computed_heart_rate,
            )
        ]

    def _handle_request(self, requested_page):
        """
        Handle data page request using page number directly.
        """
        if requested_page in self.data_page_descriptors:
            self.send_page(self.data_page_descriptors[requested_page])
        else:
            self.send_default_page()


    def main_loop(self):
        """
        Implement the HRM-specific main loop:
        - 16x Previous Heart Beat
        - 1x Manufacturer Information
        - 16x Previous Heart Beat
        - 1x Product Information
        - 16x Previous Heart Beat
        - 1x Battery Status
        """
        manufacturer = self.data_page_descriptors[2]
        product = self.data_page_descriptors[3]
        battery = self.data_page_descriptors[7]
        previous_heart_beat = self.data_page_descriptors[4]

        sequence = (
            [previous_heart_beat] * 16 +
            [manufacturer] +
            [previous_heart_beat] * 16 +
            [product] +
            [previous_heart_beat] * 16 +
            [battery]
        )
        sequence_index = 0

        while self.is_started():
            for _ in range(4):
                if not self.is_started():
                    return
                req = self._request
                if req is not None:
                    self._request = None
                    self._handle_request(req)
                else:
                    self.send_page(sequence[sequence_index])
                sleep(self.update_rate)

            # Toggle bit every 4 messages
            self.toggle_bit = 1 - self.toggle_bit

            # Update counters
            self._update_counters()
            sequence_index = (sequence_index + 1) % len(sequence)



class HeartRateDisplay(AntPlusGenericDisplay):
    """
    ANT+ Heart Rate Display (Device Type 120).
    """
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 30

    header_class = ANT_Plus_HR_Header_Hdr
    data_page_descriptors = HRM_PAGE_DESCRIPTORS
    event_time_attr = "heart_beat_event_time"
    cumulative_count_attr = "heart_beat_count"

    def __init__(self):
        super().__init__()
        self.computed_heart_rate = None

    def on_heart_rate_received(self, computed_heart_rate):
        """
        Callback called when a heart rate value is received.
        """
        pass

    def on_heart_rate_update(self, computed_heart_rate):
        """
        Callback called when heart rate changes.
        """
        pass

    def on_data_received(self, **kwargs):
        """
        Forwards generic callback to profile-specific callbacks.
        """
        hb = kwargs.get("computed_heart_rate")
        if hb is not None:
            self.on_heart_rate_received(hb)
            if self.computed_heart_rate != hb:
                self.on_heart_rate_update(hb)

    def on_broadcast(self, payload):
        """
        Handle HRM broadcast.
        """
        # Extract the common payload (heart rate data)
        if ANT_HR_Common_Payload in payload:
            common = payload[ANT_HR_Common_Payload]
            self.computed_heart_rate = common.computed_heart_rate
            self.heart_beat_count = common.heart_beat_count
            self.heart_beat_event_time = common.heart_beat_event_time

            self.on_data_received(
                computed_heart_rate=self.computed_heart_rate,
                heart_beat_count=self.heart_beat_count,
                heart_beat_event_time=self.heart_beat_event_time,
            )

            self._data_queue.put({
                "computed_heart_rate": self.computed_heart_rate,
                "heart_beat_count": self.heart_beat_count,
                "heart_beat_event_time": self.heart_beat_event_time,
            })

        self._extract_known_attributes(payload)

    def heart_rates(self):
        """
        Iterator over received heart rate values.
        """
        while self.is_started() or not self._data_queue.empty():
            try:
                item = self._data_queue.get(timeout=0.5)
                yield item.get("computed_heart_rate")
            except Empty:
                continue