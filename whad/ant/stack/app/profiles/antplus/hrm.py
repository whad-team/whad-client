from whad.ant.stack.app.profiles.antplus import AntPlusMasterProfile, AntPlusSlaveProfile
from whad.scapy.layers.ant import ANT_MANUFACTURERS_ID, ANT_Plus_HR_Header_Hdr, ANT_HR_Default_Data_Page,\
    ANT_HR_Battery_Status_Data_Page, ANT_HR_Manufacturer_Information_Data_Page, ANT_HR_Product_Information_Data_Page,\
    ANT_HR_Common_Payload, ANT_Plus_Header_Hdr, ANT_Request_Data_Page
from time import sleep
from threading import Thread
class HeartRateMonitor(AntPlusMasterProfile):
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 0
    
    def __init__(self):
        self.reset()
        self.__thread = None

    def reset(self):
        self.__request = None
        self.computed_heart_rate = 60 
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

    def send_manufacturer_information(self):
        self.broadcast(
            ANT_Plus_Header_Hdr () / 
            ANT_Plus_HR_Header_Hdr(
                toggle_bit = self.toggle_bit
            ) / 
            ANT_HR_Manufacturer_Information_Data_Page(
                manufacturer_id =(
                    ANT_MANUFACTURERS_ID[self.manufacturer] if 
                    self.manufacturer in ANT_MANUFACTURERS_ID else 
                    0
                ),
                serial_number = self.serial_number
            ) / 
            ANT_HR_Common_Payload(
                heart_beat_event_time = self.heart_beat_event_time, 
                heart_beat_count = self.heart_beat_count, 
                computed_heart_rate = self.computed_heart_rate
            )
        )

    def send_product_information(self):
        self.broadcast(
            ANT_Plus_Header_Hdr () / 
            ANT_Plus_HR_Header_Hdr(
                toggle_bit = self.toggle_bit
            ) / 
            ANT_HR_Product_Information_Data_Page(
                hardware_version = self.hardware_version, 
                software_version = self.software_version,
                model_number = self.model_number 

            ) / 
            ANT_HR_Common_Payload(
                heart_beat_event_time = self.heart_beat_event_time, 
                heart_beat_count = self.heart_beat_count, 
                computed_heart_rate = self.computed_heart_rate
            )
        )


    def send_battery_level(self):
        self.broadcast(
            ANT_Plus_Header_Hdr () / 
            ANT_Plus_HR_Header_Hdr(
                toggle_bit = self.toggle_bit
            ) / 
            ANT_HR_Battery_Status_Data_Page(
                battery_level = self.battery_level, 
                fractional_battery_voltage = self.fractional_battery_voltage, 
                coarse_battery_voltage = self.coarse_battery_voltage
            ) / 
            ANT_HR_Common_Payload(
                heart_beat_event_time = self.heart_beat_event_time, 
                heart_beat_count = self.heart_beat_count, 
                computed_heart_rate = self.computed_heart_rate
            )
        )

    def send_default_page(self):
        self.broadcast(
            ANT_Plus_Header_Hdr () / 
            ANT_Plus_HR_Header_Hdr(
                toggle_bit = self.toggle_bit
            ) / 
            ANT_HR_Default_Data_Page() / 
            ANT_HR_Common_Payload(
                heart_beat_event_time = self.heart_beat_event_time, 
                heart_beat_count = self.heart_beat_count, 
                computed_heart_rate = self.computed_heart_rate
            )
        )


    def start(self):
        super().start()
        self.__thread = Thread(target=self.main_loop)
        self.__thread.start()

    def main_loop(self):
        sequence = (
            [self.send_default_page for _ in range(16)] + 
            [self.send_manufacturer_information] + 
            [self.send_default_page for _ in range(16)] + 
            [self.send_product_information] +
            [self.send_default_page for _ in range(16)] + 
            [self.send_battery_level]
        )
        sequence_index = 0
        while self.is_started():
            if self.__request is None:
                sequence[sequence_index]()
            else:
                print(self.__request)
                if self.__request == 2:
                    self.send_manufacturer_information()
                elif self.__request == 3:
                    self.send_product_information()
                elif self.__request == 7:
                    self.send_battery_level()
                else:
                    self.__request = None
            self.toggle_bit = 1 - self.toggle_bit
            self.heart_beat_count = (self.heart_beat_count + 1) & 0xFF 
            self.heart_beat_event_time = (self.heart_beat_event_time + 1000) & 0xFFFF
            sequence_index = (sequence_index + 1) % len(sequence)
            sleep(0.8)

    def on_ack_burst(self, payload):
        if ANT_Request_Data_Page in payload:
            self.__request = payload.requested_page_number
            

    def stop(self):
        super().stop()
        self.__thread.join()

class HeartRateDisplay(AntPlusSlaveProfile):
    DEVICE_TYPE = 120
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8070
    SEARCH_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        self.computed_heart_rate = None 
        self.heart_beat_count = None
        self.heart_beat_event_time = None

    def on_heart_rate_received(self, computed_heart_rate):
        pass

    def on_heart_rate_update(self, computed_heart_rate):
        pass

    def on_broadcast(self, payload):
        if ANT_Plus_HR_Header_Hdr in payload:

            if ANT_HR_Common_Payload in payload:
                self.on_heart_rate_received(payload.computed_heart_rate)
                if self.computed_heart_rate != payload.computed_heart_rate:
                    self.on_heart_rate_update(payload.computed_heart_rate)
                self.computed_heart_rate = payload.computed_heart_rate

                self.heart_beat_count = payload.heart_beat_count
                self.heart_beat_event_time = payload.heart_beat_event_time