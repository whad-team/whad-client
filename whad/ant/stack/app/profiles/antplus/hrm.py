from whad.ant.stack.app.profiles.antplus import AntPlusMasterProfile, AntPlusSlaveProfile
from whad.scapy.layers.ant import ANT_MANUFACTURERS_ID, ANT_Plus_HR_Header_Hdr, ANT_HR_Default_Data_Page,\
    ANT_HR_Battery_Status_Data_Page, ANT_HR_Manufacturer_Information_Data_Page, ANT_HR_Product_Information_Data_Page,\
    ANT_HR_Common_Payload, ANT_Plus_Header_Hdr, ANT_Request_Data_Page, ANT_HR_Previous_Heart_Beat_Data_Page
from time import sleep, time
from queue import Queue, Empty
from threading import Thread

class HeartRateMonitor(AntPlusMasterProfile):
    """ANT+ Heart Rate Monitor (Device Type 120).

    This acts as a HRM sensor transmitting on a single ANT channel.
    """
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    
    def __init__(self):
        super().__init__()
        self.reset()
        self.__thread = None

    def reset(self):
        """Reset the display.
        """
        self.__request = None
        self.computed_heart_rate = 60 
        self.previous_heart_beat = self.computed_heart_rate
        self.heart_beat_count = 0
        self.heart_beat_event_time = 0
        self.manufacturer = "Garmin"
        self.serial_number = 1234
        self.toggle_bit = 0
        self.hardware_version = 1
        self.software_version = 12
        self.model_number = 44
        self.battery_level = 98
        self.fractional_battery_voltage = 251
        self.coarse_battery_voltage = 8

    def _send_page(self, data_page_layer):
        """Send a data page."""
        self.broadcast(
            ANT_Plus_Header_Hdr() / 
            ANT_Plus_HR_Header_Hdr(toggle_bit=self.toggle_bit) / 
            data_page_layer / 
            ANT_HR_Common_Payload(
                heart_beat_event_time=self.heart_beat_event_time, 
                heart_beat_count=self.heart_beat_count, 
                computed_heart_rate=self.computed_heart_rate
            )
        )

    def send_manufacturer_information(self):
        """ Send Manufacturer Information Data Page."""
        try:
            manufacturer_id = ANT_MANUFACTURERS_ID[self.manufacturer]
        except IndexError:
            manufacturer_id = 0

        self._send_page(
            ANT_HR_Manufacturer_Information_Data_Page(
                manufacturer_id=manufacturer_id,
                serial_number=self.serial_number
            )
        )

    def send_product_information(self):
        """Send Product Information Data Page."""
        self._send_page(
            ANT_HR_Product_Information_Data_Page(
                hardware_version=self.hardware_version, 
                software_version=self.software_version,
                model_number=self.model_number 
            )
        )

    def send_battery_level(self):
        """Send Battery Level Data Page."""
        self._send_page(
            ANT_HR_Battery_Status_Data_Page(
                battery_level=self.battery_level, 
                fractional_battery_voltage=self.fractional_battery_voltage, 
                coarse_battery_voltage=self.coarse_battery_voltage
            )
        )

    def send_default_page(self):
        """Send Default Data Page."""
        self._send_page(ANT_HR_Default_Data_Page())

    def send_previous_heart_rate_beat(self):
        """Send Previous Heart Rate Beat"""
        try:
            manufacturer_id = ANT_MANUFACTURERS_ID[self.manufacturer]
        except IndexError:
            manufacturer_id = 0
        
        self._send_page(
            ANT_HR_Previous_Heart_Beat_Data_Page(
                manufacturer=manufacturer_id,
                previous_heart_beat=self.previous_heart_beat
            )
        )

    def start(self):
        """ Start the main loop."""
        super().start()
        self.__thread = Thread(target=self.main_loop, daemon=True)
        self.__thread.start()

    def main_loop(self):
        """ Main loop sending the transmission pattern. """
        start_time = time()
        
        sequence = (
            [self.send_previous_heart_rate_beat] * 16 +
            [self.send_manufacturer_information] +
            [self.send_previous_heart_rate_beat] * 16 +
            [self.send_product_information] +
            [self.send_previous_heart_rate_beat] * 16 +
            [self.send_battery_level]
        )
        sequence_index = 0
        
        while self.is_started():
            for _ in range(4):
                req = self.__request
                if req is not None:
                    self.__request = None
                    
                    if req == 2:
                        self.send_manufacturer_information()
                    elif req == 3:
                        self.send_product_information()
                    elif req == 7:
                        self.send_battery_level()
                else:
                    sequence[sequence_index]()
                    
                sleep(1 / 4.06)
                
            # Change the toggle bit
            self.toggle_bit = 1 - self.toggle_bit

            # Update the counters
            self.heart_beat_count = (self.heart_beat_count + 1) & 0xFF 
            self.heart_beat_event_time = int((time() - start_time) * 1024) & 0xFFFF
            sequence_index = (sequence_index + 1) % len(sequence)

    def on_ack_burst(self, payload):
        """On Acknowledged Burst method."""
        if ANT_Request_Data_Page in payload:
            self.__request = payload[ANT_Request_Data_Page].requested_page_number

    def stop(self):
        """Stops the main thread."""
        super().stop()
        if self.__thread is not None:
            self.__thread.join()

class HeartRateDisplay(AntPlusSlaveProfile):
    """ANT+ Heart Rate Display (Device Type 120).

    Receives and decodes Heart Rate data from a sensor.
    """
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        self.computed_heart_rate = None 
        self.heart_beat_count = None
        self.heart_beat_event_time = None
        
        self._hr_queue = Queue()

    def on_heart_rate_received(self, computed_heart_rate):
        """Called when a heart rate data is received.
        
        Override this method in a subclass to handle heart rate data.
        """
        pass

    def on_heart_rate_update(self, computed_heart_rate):
        """Called when a heart rate data is updated.
        
        Override this method in a subclass to handle heart rate data.
        """
        pass

    def on_broadcast(self, payload):
        """Called a broadcast payload is received."""
        if ANT_Plus_HR_Header_Hdr in payload and ANT_HR_Common_Payload in payload:
            common = payload[ANT_HR_Common_Payload]
            rx_heart_rate = common.computed_heart_rate

            self.on_heart_rate_received(rx_heart_rate)
            if self.computed_heart_rate != rx_heart_rate:
                self.on_heart_rate_update(rx_heart_rate)
                
            self.computed_heart_rate = rx_heart_rate
            self.heart_beat_count = common.heart_beat_count
            self.heart_beat_event_time = common.heart_beat_event_time
            
            self._hr_queue.put(rx_heart_rate)

    def heart_rates(self):
        """ Iterator allowing to get received heart rates values."""
        while self.is_started():
            try:
                yield self._hr_queue.get(timeout=0.5)
            except Empty:
                continue
