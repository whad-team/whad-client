"""ANT+ Display tool interactive shell.
"""
import string
import inspect
from time import sleep
from typing import Union, Optional

from prompt_toolkit import print_formatted_text, HTML

from whad.device import Device
from whad.ant import Slave, Scanner
from whad.ant.stack.app.profiles.antplus import find_slave_profile

from whad.common.monitors import WiresharkMonitor
from whad.exceptions import ExternalToolNotFound

from whad.cli.shell import InteractiveShell, category

INTRO='''
wantplus-display, the WHAD ANT+ Display utility
'''


class AntPlusDisplayShell(InteractiveShell):
    """ANT+ Display interactive shell
    """

    def __init__(self, interface: Device = None, connector=None):
        super().__init__(HTML("<b>wantplus-display></b> "))

        # If interface is None, pick the first matching our needs
        self.__interface = interface
        self.__wireshark = None

        self.__profile = None
        self.__active_channel = None
        self.__detected_devices_cache = []

        # If connector is not provided
        if connector is None:
            # Reset target info and connector.
            self.__connector: Optional[Union[Slave, Scanner]] = None
            self.__device_type = None
        else:
            # If connector provided, consider the device already connected
            self.__connector = connector

        self.intro = INTRO
        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        """
        if self.__active_channel is not None:
            profile = self.__profile.human_readable_name + "("+str(self.__active_channel.device_type)+")"

            self.set_prompt(HTML(
                f"<b>wantplus-display|<ansicyan>{profile}</ansicyan>" + "| @<ansicyan>" + str(self.__active_channel.device_number)+ "</ansicyan> ></b> "
            ), force)
        else:
            self.set_prompt(HTML("<b>wantplus-display></b> "), force)


    def complete_wireshark(self):
        """Autocomplete wireshark command
        """
        completions = {}
        if self.__wireshark is not None:
            completions['off'] = {}
        else:
            completions['on'] = {}
        return completions


    @category("Monitoring")
    def do_wireshark(self, arg):
        """launch wireshark to monitor packets

        <ansicyan><b>wireshark</b> <i>["on" | "off"]</i></ansicyan>

        This command launches a wireshark that will display all the packets sent
        and received in the active connection.
        """
        if len(arg) >=1:
            enabled = arg[0].lower()=="on"
            if enabled:
                if self.__wireshark is None:
                    try:
                        self.__wireshark = WiresharkMonitor()
                        if self.__connector is not None:
                            self.__wireshark.attach(self.__connector)
                            self.__wireshark.start()
                    except ExternalToolNotFound:
                        self.error("Cannot launch Wireshark, please make sure it is installed.")
                else:
                    self.error("Wireshark is already launched, see wireshark off")
            else:
                # Detach monitor if any
                if self.__wireshark is not None:
                    self.__wireshark.detach()
                    self.__wireshark.close()
                    self.__wireshark = None
        else:
            self.error("Missing arguments, see help wireshark.")


    @category("Device discovery")
    def do_scan(self, args):
        """scan surrounding ANT+ devices and show a summary

        <ansicyan><b>scan</b></ansicyan>

        Scan surrounding ANT+ devices and display discovered device types.
        
        <i>
        Currently supported device types:
            - <b>119:</b> Weight Scale
            - <b>120:</b> Heart Rate Monitor
            - <b>121:</b> Combined Speed and Cadence
            - <b>122:</b> Bike Cadence Sensor
            - <b>123:</b> Bike Speed Sensor
            - <b>124:</b> Speed and Distance
        </i>
         
        Scan can be stopped by hitting [CTRL + C]. 
        """
        if self.__wireshark is not None:
            self.__wireshark.stop()
            self.__wireshark.detach()
        self.__connector = Scanner(self.__interface)
        self.__connector.start()
        if self.__wireshark is not None:
            self.__wireshark.attach(self.__connector)
            self.__wireshark.start()

        try:
            print_formatted_text(HTML('<ansigreen>RSSI Lvl   Dev. Num.     Dev. Type    Trans. Type      Profile</ansigreen>'))
            for device in self.__connector.discover_devices():
                print(
                    "[ "+str(device.rssi)+" dBm] " + 
                    str(device.device_number) + 
                    "          " + 
                    str(device.device_type)+
                    "          " + 
                    str(device.transmission_type) + 
                    "                " + 
                    device.profile
                )
                self.__detected_devices_cache.append(device)
                self.__detected_devices_cache = list(set(self.__detected_devices_cache))
        except KeyboardInterrupt:
            print("\rScan terminated by user.")
            if self.__wireshark is not None:
                self.__wireshark.stop()
                self.__wireshark.detach()

            self.__connector.stop()
            self.__connector = None
            #self.__connector.close()

    def complete_connect(self):
        """Autocomplete the 'connect' command with device types.
        """
        completions = {}
        for device in self.__detected_devices_cache:
            completions[str(device.device_number)] = None
        return completions


    @category("Device interaction")
    def do_connect(self, args):
        """connect to an ANT+ device

        <ansicyan><b>connect</b> <i>[device_number]</i></ansicyan>

        Connect to an ANT+ device according to the provided device number.

        Example:
         - <ansicyan>connect 1234</ansicyan>
        """
        if len(args) < 1:
            self.error("Missing device number, see help connect.")
            return

        # Parse device number
        try:
            if args[0].startswith("0x"):
                device_number = int(args[0], 16)
            else:
                device_number = int(args[0])
        except ValueError:
            self.error(f"Invalid device number: {args[0]}")
            return

        if self.__interface is None:
            self.error("No interface specified.")
            return

        # Stop previous connector if any
        if self.__connector is not None:
            if self.__profile is not None:
                self.__profile.stop()
            self.__connector.stop()

        # Detach wireshark if any
        if self.__wireshark is not None:
            self.__wireshark.detach()

        self.__device_type = None
        self.__transmission_type = None
        self.__profile = None
        for device in self.__detected_devices_cache:
            if device_number == device.device_number:
                self.__device_type = device.device_type
                self.__transmission_type = device.transmission_type
                self.__profile = find_slave_profile(self.__device_type)()

        # Create profile and slave connector
        try:
            self.__connector = Slave(self.__interface, profile=self.__profile)
            self.__connector.start()
            self.__device_number = device_number

            # Re-attach wireshark if needed
            if self.__wireshark is not None:
                self.__wireshark.stop()
                self.__wireshark.detach()
                self.__wireshark.attach(self.__connector)
                self.__wireshark.start()


            # Start the profile
            self.__active_channel = self.__connector.search_channel(
                device_number=device_number,
                device_type= self.__device_type,
                transmission_type=self.__transmission_type
            )
            self.__profile.start()
            print(f"Connected to {str(self.__profile)} (device number {hex(device_number)}).")
            print(f"Listening for data... Press CTL-c to stop.")

            self.update_prompt()

        except Exception as e:
            self.error(f"Failed to connect: {e}")
            self.__connector = None
            self.__profile = None
            self.__device_type = None


    @category("Device interaction")
    def do_disconnect(self, args):
        """disconnect from current ANT+ device

        <ansicyan><b>disconnect</b></ansicyan>

        Disconnect from the current ANT+ device.
        """
        if self.__connector is not None:
            if self.__profile is not None:
                self.__profile.stop()
            if self.__active_channel is not None:
                self.__active_channel.close()
            self.__connector.stop()
            self.__connector = None
            self.__profile = None
            self.__active_channel = None
            self.__device_type = None

            self.update_prompt()
            print("Disconnected.")
        else:
            self.error("Not connected.")


    def get_profile_content(self):
        """
        Return a tuple containing attributes and interactions for the current profile.
        """
        attributes = []
        interactions = []

        for attribute in dir(self.__profile):
            if attribute.startswith("_"):
                continue
            if all([i in string.ascii_uppercase + "_" for i in attribute]):
                continue
            if attribute in ("data_page_descriptors", "application", "cumulative_count_attr", "cumulative_operating_time", "event_time_attr", "stop_indicator"):
                continue
            if inspect.isgeneratorfunction(getattr(self.__profile, attribute)):
                continue
            if callable(getattr(self.__profile, attribute)):
                interactions.append(attribute)
            else:
                attributes.append(attribute)

        return (attributes, interactions)

    @category("Device interaction")
    def do_profile(self, args):
        """Show profile attributes and available data pages.

        <ansicyan><b>profile</b></ansicyan>

        Show all profile attributes.
        """
        if (
            self.__connector is not None and
            self.__profile is not None
        ):

            attributes, interactions = self.get_profile_content()
            print_formatted_text(HTML("<green><b>Attributes </b></green>"))
            for attribute in attributes:
                print_formatted_text(HTML(" <b>" + attribute+" </b>"))
                print_formatted_text(HTML(" | <ansicyan>value: </ansicyan>" + str(getattr(self.__profile, attribute))))
            print()

            print_formatted_text(HTML("<green><b>Data pages </b></green>"))
            for data_page_number, data_page in self.__profile.data_page_descriptors.items():
                print_formatted_text(HTML(" <b>" + str(data_page_number) +" </b>: " + str(data_page.layer_class().name)))
                for field in data_page.layer_class().fields_desc:
                    print_formatted_text(HTML(" | <ansicyan>"+field.name +"</ansicyan>"))

            print()

        else:
            self.error("Not connected.")



    def complete_get(self):
        """Autocomplete the 'get' command with attributes.
        """
        completions = {}
        attributes, _ = self.get_profile_content()
        for attribute in attributes:
            completions[attribute] = None
        return completions

    @category("Device interaction")
    def do_get(self, args):
        """Get attribute value from profile if a device is connected.

        <ansicyan><b>get</b> <i>attribute_name</i></ansicyan>

        Get attribute value from profile if a device is connected.

        """
        if (
            self.__connector is not None and
            self.__profile is not None
        ):

            attributes, _ = self.get_profile_content()
            selected_attribute = args[0]

            if selected_attribute in attributes:
                getattr(self.__profile, selected_attribute)
                print_formatted_text(HTML(" <b>" + selected_attribute+" </b>"))
                print_formatted_text(HTML(" | <ansicyan>value: </ansicyan>" + str(getattr(self.__profile, selected_attribute))))
            else:
                self.error("Unknown attribute.")
        else:
            self.error("Not connected.")


    def complete_monitor(self):
        """Autocomplete the 'monitor' command with attributes.
        """
        completions = {}
        attributes, _ = self.get_profile_content()
        for attribute in attributes:
            completions[attribute] = None
        return completions

    @category("Device interaction")
    def do_monitor(self, args):
        """Monitor attribute value from profile if a device is connected.

        <ansicyan><b>monitor</b> <i>attribute_name</i></ansicyan>

        Monitor attribute value from profile if a device is connected.
        """
        # Check that we have at least one parameter set.
        if len(args) == 0:
            self.error("Missing attribute name, see help monitor.")
            return

        # Process parameter.
        if (
            self.__connector is not None and
            self.__profile is not None
        ):

            attributes, _ = self.get_profile_content()
            selected_attribute = args[0]

            if selected_attribute in attributes:
                last_value = None
                print_formatted_text(HTML(" <b>" + selected_attribute+" </b>"))
                try:
                    while True:
                        value = getattr(self.__profile, selected_attribute)
                        if value != last_value:
                            last_value = value
                            print_formatted_text(HTML(" | <ansicyan>updated value: </ansicyan>" + str(value)))
                        else:
                            sleep(0.1)
                except KeyboardInterrupt:
                    return
            else:
                self.error("Unknown attribute.")
        else:
            self.error("Not connected.")

    def complete_request(self):
        """Autocomplete the 'request' command with data pages.
        """
        completions = {}
        if self.__profile is not None:
            for data_page_number, data_page in self.__profile.data_page_descriptors.items():
                completions[str(data_page_number)] = None
                completions[str(data_page.layer_class.__name__)] = None
        return completions

    @category("Device interaction")
    def do_request(self, args):
        """Request a specific data-page information if the device is connected and update the associated attributes.

        <ansicyan><b>request</b> <i>attribute_name</i></ansicyan>
        
        Request a specific data-page information if the device is connected and update the associated attributes.
        """
        # If no parameters provided, display an error and do not process.
        if len(args) == 0:
            self.error("Missing attribute name, see help request.")
            return

        if (
            self.__connector is not None and
            self.__profile is not None
        ):
            requested_page_number = None
            try:
                requested_page_number = int(args[0])
            except ValueError:
                for data_page_number, data_page in self.__profile.data_page_descriptors.items():
                    if data_page.layer_class.__name__ == args[0]:
                        requested_page_number = data_page_number
                        break
            if requested_page_number is None:
                self.error("Invalid page number.")
            else:
                print_formatted_text(HTML(" <b>Requesting " + str(requested_page_number) +" </b>..."))
                response = self.__profile.request_data_page(requested_page_number=requested_page_number)
                if response is None:
                    self.error("No response, timeout.")
                else:
                    self.success("Received response from sensor !")
                    response.show()
        else:
            self.error("Not connected.")


    def get_device_type(self):
        """Return the current device type.
        """
        return self.__device_type


    def get_profile(self):
        """Return the current profile.
        """
        return self.__profile

    def do_quit(self, args):
        """Exit <b>wantplus_display</b> CLI tool.
        
        <ansicyan><b>exit</b></ansicyan>
        
        Exit <b>wantplus_display</b> CLI tool.
        """
        if self.__connector is not None:
            self.__connector.stop()
        if self.__interface is not None:
            self.__interface.close()
        self.stop()

    def do_exit(self, arg):
        """Exit <b>wantplus-display</b> CLI tool (alias for quit).
        
        <ansicyan><b>quit</b></ansicyan>
        
        Exit <b>wantplus-display</b> CLI tool.
        """
        return self.do_quit(arg)

