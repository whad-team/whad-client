from whad.ant.stack.app.profiles.antplus import AntPlusMasterProfile, AntPlusSlaveProfile
from whad.scapy.layers.ant import ANT_MANUFACTURERS_ID, ANT_Plus_Header_Hdr, \
    ANT_Plus_Bicycle_Speed_And_Cadence, ANT_Plus_Bicycle_Speed_Header_Hdr, \
    ANT_Plus_Bicycle_Cadence_Header_Hdr, \
    ANT_Bicycle_Speed_Default_Data_Page, ANT_Bicycle_Speed_Manufacturer_Information_Data_Page, \
    ANT_Bicycle_Speed_Product_Information_Data_Page, ANT_Bicycle_Speed_Battery_Status_Data_Page, \
    ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page, ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page, \
    ANT_Bicycle_Cadence_Default_Data_Page, ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page, \
    ANT_Bicycle_Cadence_Product_Information_Data_Page, ANT_Bicycle_Cadence_Battery_Status_Data_Page, \
    ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page, ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page, \
    ANT_Request_Data_Page
from time import sleep, time
from threading import Thread
from queue import Queue, Empty


class CombinedSpeedAndCadenceSensor(AntPlusMasterProfile):
    """ANT+ Combined Bike Speed and Cadence Sensor (Device Type 121).

    This sensor transmits both speed and cadence data on a single ANT channel.
    """
    DEVICE_TYPE = 121
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8086
    SEARCH_TIMEOUT = 0

    def __init__(self):
        super().__init__()
        self.reset()
        self.__thread = None
        self.__start_time = 0

    def reset(self):
        """Reset sensor state."""
        self.bike_cadence_event_time = 0
        self.cumulative_cadence_revolution_count = 0
        self.bike_speed_event_time = 0
        self.cumulative_speed_revolution_count = 0

    def send_data_page(self):
        """Send the combined speed and cadence data page."""
        self.broadcast(
            ANT_Plus_Header_Hdr() /
            ANT_Plus_Bicycle_Speed_And_Cadence(
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def start(self):
        """Start the sensor main loop."""
        super().start()
        self.__start_time = time()
        self.__thread = Thread(target=self.main_loop, daemon=True)
        self.__thread.start()

    def main_loop(self):
        """Main loop."""
        while self.is_started():
            self.send_data_page()

            # Update counters
            elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
            self.bike_cadence_event_time = elapsed
            self.bike_speed_event_time = elapsed

            self.cumulative_cadence_revolution_count = (
                self.cumulative_cadence_revolution_count + 1
            ) & 0xFFFF
            self.cumulative_speed_revolution_count = (
                self.cumulative_speed_revolution_count + 1
            ) & 0xFFFF

            sleep(1 / 4.05)

    def stop(self):
        """Stop the sensor."""
        super().stop()
        if self.__thread is not None:
            self.__thread.join()


class CombinedSpeedAndCadenceDisplay(AntPlusSlaveProfile):
    """ANT+ Combined Bike Speed and Cadence Display (Device Type 121).

    Receives and decodes combined speed and cadence data from a sensor.
    """
    DEVICE_TYPE = 121
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8086
    SEARCH_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        self.bike_cadence_event_time = None
        self.cumulative_cadence_revolution_count = None
        self.bike_speed_event_time = None
        self.cumulative_speed_revolution_count = None

        self._cadence_queue = Queue()
        self._speed_queue = Queue()

    def on_cadence_received(self, cumulative_rev_count, event_time):
        """Called when a cadence data is received.
        
        Override this method in a subclass to handle cadence data.
        """
        pass

    def on_speed_received(self, cumulative_rev_count, event_time):
        """Called when a speed data is received.
        
        Override this method in a subclass to handle speed data.
        """
        pass

    def on_broadcast(self, payload):
        """Handle received broadcast messages."""
        if ANT_Plus_Bicycle_Speed_And_Cadence in payload:
            data = payload[ANT_Plus_Bicycle_Speed_And_Cadence]

            self.bike_cadence_event_time = data.bike_cadence_event_time
            self.cumulative_cadence_revolution_count = data.cumulative_cadence_revolution_count
            self.bike_speed_event_time = data.bike_speed_event_time
            self.cumulative_speed_revolution_count = data.cumulative_speed_revolution_count

            self.on_cadence_received(
                data.cumulative_cadence_revolution_count,
                data.bike_cadence_event_time
            )
            self.on_speed_received(
                data.cumulative_speed_revolution_count,
                data.bike_speed_event_time
            )

            self._cadence_queue.put(data.cumulative_cadence_revolution_count)
            self._speed_queue.put(data.cumulative_speed_revolution_count)

    @property
    def cadence_revolution_counts(self):
        """Iterator over received cadence revolution counts."""
        while self.is_started() or not self._cadence_queue.empty():
            try:
                yield self._cadence_queue.get(timeout=0.5)
            except Empty:
                continue

    @property
    def speed_revolution_counts(self):
        """Iterator over received speed revolution counts."""
        while self.is_started() or not self._speed_queue.empty():
            try:
                yield self._speed_queue.get(timeout=0.5)
            except Empty:
                continue


class BikeSpeedSensor(AntPlusMasterProfile):
    """ANT+ Bike Speed Sensor (Device Type 123).

    Transmits wheel revolution data.
    """
    DEVICE_TYPE = 123
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8118
    SEARCH_TIMEOUT = 0

    def __init__(self):
        super().__init__()
        self.reset()
        self.__thread = None
        self.__start_time = 0

    def reset(self):
        """Reset sensor state."""
        self.bike_speed_event_time = 0
        self.cumulative_speed_revolution_count = 0
        self.toggle_bit = 0
        self.manufacturer = "Garmin"
        self.serial_number = 1234
        self.hardware_version = 1
        self.software_version = 12
        self.model_number = 44
        self.battery_level = 98
        self.fractional_battery_voltage = 251
        self.coarse_battery_voltage = 8
        self.cumulative_operating_time = 0
        self.stop_indicator = 0
        self.__request = None

    def _send_page(self, data_page_number, data_page_layer):
        """Send a data page."""
        self.broadcast(
            ANT_Plus_Header_Hdr() /
            ANT_Plus_Bicycle_Speed_Header_Hdr(
                toggle_bit=self.toggle_bit,
                data_page_number=data_page_number
            ) /
            data_page_layer
        )

    def send_default_page(self):
        """Send main data page (Page 0)."""
        self._send_page(
            0,
            ANT_Bicycle_Speed_Default_Data_Page(
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def send_manufacturer_information(self):
        """Send manufacturer information (Page 2)."""
        manufacturer_id = ANT_MANUFACTURERS_ID.get(self.manufacturer, 0)
        self._send_page(
            2,
            ANT_Bicycle_Speed_Manufacturer_Information_Data_Page(
                manufacturer_id=manufacturer_id,
                serial_number=self.serial_number,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def send_product_information(self):
        """Send product information (Page 3)."""
        self._send_page(
            3,
            ANT_Bicycle_Speed_Product_Information_Data_Page(
                hardware_version=self.hardware_version,
                software_version=self.software_version,
                model_number=self.model_number,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def send_cumulative_operating_time(self):
        """Send cumulative operating time (Page 1)."""
        self._send_page(
            1,
            ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page(
                cumulative_operating_time=self.cumulative_operating_time,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def send_battery_status(self):
        """Send battery status (Page 4)."""
        self._send_page(
            4,
            ANT_Bicycle_Speed_Battery_Status_Data_Page(
                fractional_battery_voltage=self.fractional_battery_voltage,
                battery_status=3,  # Ok
                coarse_battery_voltage=self.coarse_battery_voltage,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def send_motion_and_speed(self):
        """Send motion and speed page (Page 5)."""
        self._send_page(
            5,
            ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page(
                flags=self.stop_indicator,
                bike_speed_event_time=self.bike_speed_event_time,
                cumulative_speed_revolution_count=self.cumulative_speed_revolution_count
            )
        )

    def start(self):
        """Start the sensor main loop."""
        super().start()
        self.__start_time = time()
        self.__thread = Thread(target=self.main_loop)
        self.__thread.start()

    def main_loop(self):
        """Main loop implementing the transmission pattern."""

        background_sequence = [
            self.send_manufacturer_information,
            self.send_product_information,
            self.send_battery_status,
            self.send_cumulative_operating_time,
        ]

        bg_index = 0

        while self.is_started():
            for i in range(64):
                if not self.is_started():
                    return

                req = self.__request
                if req is not None:
                    self.__request = None
                    if req == 0:
                        self.send_default_page()
                    elif req == 1:
                        self.send_cumulative_operating_time()
                    elif req == 2:
                        self.send_manufacturer_information()
                    elif req == 3:
                        self.send_product_information()
                    elif req == 4:
                        self.send_battery_status()
                    elif req == 5:
                        self.send_motion_and_speed()
                else:
                    self.send_default_page()

                # Change toggle bit
                if (i + 1) % 4 == 0:
                    self.toggle_bit = 1 - self.toggle_bit

                # Update counters
                elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
                self.bike_speed_event_time = elapsed
                self.cumulative_speed_revolution_count = (
                    self.cumulative_speed_revolution_count + 1
                ) & 0xFFFF
                self.cumulative_operating_time = (
                    int(time() - self.__start_time) // 2
                ) & 0xFFFFFF

                sleep(1 / 4.04)

            for _ in range(4):
                if not self.is_started():
                    return

                background_sequence[bg_index]()

                # Change toggle bit
                self.toggle_bit = 1 - self.toggle_bit

                # Update counters
                elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
                self.bike_speed_event_time = elapsed
                self.cumulative_speed_revolution_count = (
                    self.cumulative_speed_revolution_count + 1
                ) & 0xFFFF
                self.cumulative_operating_time = (
                    int(time() - self.__start_time) // 2
                ) & 0xFFFFFF

                sleep(1 / 4.04)

            bg_index = (bg_index + 1) % len(background_sequence)

    def on_ack_burst(self, payload):
        """Handle request data page requests from the display."""
        if ANT_Request_Data_Page in payload:
            self.__request = payload[ANT_Request_Data_Page].requested_page_number

    def stop(self):
        """Stop the sensor."""
        super().stop()
        if self.__thread is not None:
            self.__thread.join()


class BikeSpeedDisplay(AntPlusSlaveProfile):
    """ANT+ Bike Speed Display (Device Type 123).

    Receives and decodes bike speed data from a speed sensor.
    """
    DEVICE_TYPE = 123
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8118
    SEARCH_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        self.bike_speed_event_time = None
        self.cumulative_speed_revolution_count = None
        self._speed_queue = Queue()

    def on_speed_received(self, cumulative_rev_count, event_time):
        """Called when speed data is received.
        
        Override this method in a subclass to handle speed data.
        """
        pass

    def on_broadcast(self, payload):
        """Handle received broadcast messages."""
        if ANT_Plus_Bicycle_Speed_Header_Hdr in payload:
            
            for layer_class in (
                ANT_Bicycle_Speed_Default_Data_Page,
                ANT_Bicycle_Speed_Manufacturer_Information_Data_Page,
                ANT_Bicycle_Speed_Product_Information_Data_Page,
                ANT_Bicycle_Speed_Battery_Status_Data_Page,
                ANT_Bicycle_Speed_Cumulative_Operating_Time_Data_Page,
                ANT_Bicycle_Speed_Motion_And_Cadence_Data_Page
            ):
                if layer_class in payload:
                    data = payload[layer_class]
                    self.bike_speed_event_time = data.bike_speed_event_time
                    self.cumulative_speed_revolution_count = data.cumulative_speed_revolution_count

                    self.on_speed_received(
                        data.cumulative_speed_revolution_count,
                        data.bike_speed_event_time
                    )
                    self._speed_queue.put(data.cumulative_speed_revolution_count)
                    break

    @property
    def speed_revolution_counts(self):
        """Iterator over received speed revolution counts."""
        while self.is_started() or not self._speed_queue.empty():
            try:
                yield self._speed_queue.get(timeout=0.5)
            except Empty:
                continue


class BikeCadenceSensor(AntPlusMasterProfile):
    """ANT+ Bike Cadence Sensor (Device Type 122).

    Transmits pedal revolution data.
    """
    DEVICE_TYPE = 122
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8102
    SEARCH_TIMEOUT = 0

    def __init__(self):
        super().__init__()
        self.reset()
        self.__thread = None
        self.__start_time = 0

    def reset(self):
        """Reset sensor state."""
        self.bike_cadence_event_time = 0
        self.cumulative_cadence_revolution_count = 0
        self.toggle_bit = 0
        self.manufacturer = "Garmin"
        self.serial_number = 1234
        self.hardware_version = 1
        self.software_version = 12
        self.model_number = 44
        self.battery_level = 98
        self.fractional_battery_voltage = 251
        self.coarse_battery_voltage = 8
        self.cumulative_operating_time = 0
        self.stop_indicator = 0
        self.__request = None

    def _send_page(self, data_page_number, data_page_layer):
        """Send a data page with the specified page number and toggle bit."""
        self.broadcast(
            ANT_Plus_Header_Hdr() /
            ANT_Plus_Bicycle_Cadence_Header_Hdr(
                toggle_bit=self.toggle_bit,
                data_page_number=data_page_number
            ) /
            data_page_layer
        )

    def send_default_page(self):
        """Send main data page (Page 0) with current cadence data."""
        self._send_page(
            0,
            ANT_Bicycle_Cadence_Default_Data_Page(
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def send_manufacturer_information(self):
        """Send manufacturer information (Page 2)."""
        manufacturer_id = ANT_MANUFACTURERS_ID.get(self.manufacturer, 0)
        self._send_page(
            2,
            ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page(
                manufacturer_id=manufacturer_id,
                serial_number=self.serial_number,
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def send_product_information(self):
        """Send product information (Page 3)."""
        self._send_page(
            3,
            ANT_Bicycle_Cadence_Product_Information_Data_Page(
                hardware_version=self.hardware_version,
                software_version=self.software_version,
                model_number=self.model_number,
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def send_cumulative_operating_time(self):
        """Send cumulative operating time (Page 1)."""
        self._send_page(
            1,
            ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page(
                cumulative_operating_time=self.cumulative_operating_time,
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def send_battery_status(self):
        """Send battery status (Page 4)."""
        self._send_page(
            4,
            ANT_Bicycle_Cadence_Battery_Status_Data_Page(
                fractional_battery_voltage=self.fractional_battery_voltage,
                battery_status=3,  # Ok
                coarse_battery_voltage=self.coarse_battery_voltage,
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def send_motion_and_cadence(self):
        """Send motion and cadence page (Page 5 - optional)."""
        self._send_page(
            5,
            ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page(
                flags=self.stop_indicator,
                bike_cadence_event_time=self.bike_cadence_event_time,
                cumulative_cadence_revolution_count=self.cumulative_cadence_revolution_count
            )
        )

    def start(self):
        """Start the sensor main loop."""
        super().start()
        self.__start_time = time()
        self.__thread = Thread(target=self.main_loop)
        self.__thread.start()

    def main_loop(self):
        """Main loop implementing the transmission pattern.
        """
        background_sequence = [
            self.send_manufacturer_information,
            self.send_product_information,
            self.send_battery_status,
            self.send_cumulative_operating_time,
        ]

        bg_index = 0

        while self.is_started():
            for i in range(64):
                if not self.is_started():
                    return

                req = self.__request
                if req is not None:
                    self.__request = None
                    if req == 0:
                        self.send_default_page()
                    elif req == 1:
                        self.send_cumulative_operating_time()
                    elif req == 2:
                        self.send_manufacturer_information()
                    elif req == 3:
                        self.send_product_information()
                    elif req == 4:
                        self.send_battery_status()
                    elif req == 5:
                        self.send_motion_and_cadence()
                else:
                    self.send_default_page()

                # Change toggle bit
                if (i + 1) % 4 == 0:
                    self.toggle_bit = 1 - self.toggle_bit

                # Update counters
                elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
                self.bike_cadence_event_time = elapsed
                self.cumulative_cadence_revolution_count = (
                    self.cumulative_cadence_revolution_count + 1
                ) & 0xFFFF
                self.cumulative_operating_time = (
                    int(time() - self.__start_time) // 2
                ) & 0xFFFFFF

                sleep(1 / 4.04)

            for _ in range(4):
                if not self.is_started():
                    return

                background_sequence[bg_index]()

                # Change toggle bit
                self.toggle_bit = 1 - self.toggle_bit

                # Update counters
                elapsed = int((time() - self.__start_time) * 1024) & 0xFFFF
                self.bike_cadence_event_time = elapsed
                self.cumulative_cadence_revolution_count = (
                    self.cumulative_cadence_revolution_count + 1
                ) & 0xFFFF
                self.cumulative_operating_time = (
                    int(time() - self.__start_time) // 2
                ) & 0xFFFFFF

                sleep(1 / 4.04)

            bg_index = (bg_index + 1) % len(background_sequence)

    def on_ack_burst(self, payload):
        """Handle request data page requests from the display."""
        if ANT_Request_Data_Page in payload:
            self.__request = payload[ANT_Request_Data_Page].requested_page_number

    def stop(self):
        """Stop the sensor."""
        super().stop()
        if self.__thread is not None:
            self.__thread.join()


class BikeCadenceDisplay(AntPlusSlaveProfile):
    """ANT+ Bike Cadence Display (Device Type 122).

    Receives and decodes bike cadence data from a cadence sensor.
    """
    DEVICE_TYPE = 122
    TRANSMISSION_TYPE = 1
    CHANNEL_PERIOD = 8102
    SEARCH_TIMEOUT = 30

    def __init__(self):
        super().__init__()
        self.bike_cadence_event_time = None
        self.cumulative_cadence_revolution_count = None
        self._cadence_queue = Queue()

    def on_cadence_received(self, cumulative_rev_count, event_time):
        """Called when cadence data is received.
        """
        pass

    def on_broadcast(self, payload):
        """Handle received broadcast messages."""
        if ANT_Plus_Bicycle_Cadence_Header_Hdr in payload:
            for layer_class in (
                ANT_Bicycle_Cadence_Default_Data_Page,
                ANT_Bicycle_Cadence_Manufacturer_Information_Data_Page,
                ANT_Bicycle_Cadence_Product_Information_Data_Page,
                ANT_Bicycle_Cadence_Battery_Status_Data_Page,
                ANT_Bicycle_Cadence_Cumulative_Operating_Time_Data_Page,
                ANT_Bicycle_Cadence_Motion_And_Cadence_Data_Page
            ):
                if layer_class in payload:
                    data = payload[layer_class]
                    self.bike_cadence_event_time = data.bike_cadence_event_time
                    self.cumulative_cadence_revolution_count = data.cumulative_cadence_revolution_count

                    self.on_cadence_received(
                        data.cumulative_cadence_revolution_count,
                        data.bike_cadence_event_time
                    )
                    self._cadence_queue.put(data.cumulative_cadence_revolution_count)
                    break

    @property
    def cadence_revolution_counts(self):
        """Iterator over received cadence revolution counts."""
        while self.is_started() or not self._cadence_queue.empty():
            try:
                yield self._cadence_queue.get(timeout=0.5)
            except Empty:
                continue