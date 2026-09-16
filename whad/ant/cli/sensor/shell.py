"""
ANT+ Sensor tool interactive shell.
"""

import inspect
import string

from time import sleep

from prompt_toolkit import print_formatted_text, HTML

from whad.ant import Master
from whad.device import WhadDevice
from whad.cli.shell import InteractiveShell, category

from whad.common.monitors import WiresharkMonitor
from whad.exceptions import ExternalToolNotFound

from whad.ant.stack.app.profiles.antplus import find_master_profile


INTRO = '''
wantplus-sensor, the WHAD ANT+ Sensor utility
'''


class AntPlusSensorShell(InteractiveShell):
    """
    ANT+ Sensor interactive shell.
    """

    def __init__(
        self,
        interface: WhadDevice = None,
        device_type=None,
        device_number=1234,
        transmission_type=1,
        connector=None
    ):
        super().__init__(HTML("<b>wantplus-sensor></b>"))

        self.__interface = interface
        self.__connector = connector
        self.__wireshark = None

        self.__profile = None
        self.__active_channel = None

        self.__device_type = device_type
        self.__device_number = device_number
        self.__transmission_type = transmission_type

        self.intro = INTRO
        self.update_prompt()

    def update_prompt(self, force=False):
        """
        Update prompt to reflect current state.
        """

        if (
            self.__active_channel is not None
            and self.__profile is not None
        ):
            profile = (
                self.__profile.human_readable_name
                + "("
                + str(self.__active_channel.device_type)
                + ")"
            )

            self.set_prompt(
                HTML(
                    f"<b>wantplus-sensor|"
                    f"<ansicyan>{profile}</ansicyan>"
                    f"| @<ansicyan>"
                    f"{self.__active_channel.device_number}"
                    f"</ansicyan> ></b> "
                ),
                force
            )

        else:
            self.set_prompt(
                HTML("<b>wantplus-sensor></b> "),
                force
            )

    def complete_wireshark(self):
        completions = {}

        if self.__wireshark is not None:
            completions["off"] = {}
        else:
            completions["on"] = {}

        return completions

    @category("Monitoring")
    def do_wireshark(self, args):
        """
        Launch Wireshark to monitor packets.
        """

        if len(args) < 1:
            self.error("Missing arguments, see help wireshark.")
            return

        enabled = args[0].lower() == "on"

        if enabled:
            if self.__wireshark is not None:
                self.error(
                    "Wireshark is already launched, see wireshark off"
                )
                return

            try:
                self.__wireshark = WiresharkMonitor()

                if self.__connector is not None:
                    self.__wireshark.attach(self.__connector)
                    self.__wireshark.start()

            except ExternalToolNotFound:
                self.error(
                    "Cannot launch Wireshark, please make sure it is installed."
                )

        else:
            if self.__wireshark is not None:
                self.__wireshark.detach()
                self.__wireshark.close()
                self.__wireshark = None


    def set_profile(self, device_type):
        """
        Create the master profile for a device type.
        """

        profile_class = find_master_profile(device_type)

        if profile_class is None:
            raise ValueError(
                f"No ANT+ master profile for device type {device_type}"
            )

        self.__device_type = device_type
        self.__profile = profile_class()

        self.update_prompt()

    @category("Device interaction")
    def do_start(self, args):
        """
        Start the ANT+ sensor.
        """

        if self.__interface is None:
            self.error("No interface specified.")
            return

        if self.__connector is not None:
            self.error("Sensor already started.")
            return

        if self.__device_type is None:
            self.error("No device type specified.")
            return

        try:
            if self.__profile is None:
                self.set_profile(self.__device_type)

            self.__connector = Master(self.__interface)

            self.__active_channel = self.__connector.create_channel(
                self.__device_number,
                self.__device_type,
                self.__transmission_type,
                channel_period=self.__profile.CHANNEL_PERIOD
            )

            self.__active_channel.app.set_profile(
                self.__profile
            )

            self.__connector.start()
            self.__profile.start()

            if self.__wireshark is not None:
                self.__wireshark.attach(self.__connector)
                self.__wireshark.start()

            self.update_prompt()

            print(
                f"Started {self.__profile.human_readable_name} "
                f"(device number {self.__device_number}, "
                f"device type {self.__device_type})."
            )

        except Exception as e:
            self.error(f"Failed to start sensor: {e}")

            self.__active_channel = None
            self.__connector = None

 
    @category("Device interaction")
    def do_stop(self, args):
        """
        Stop the ANT+ sensor.
        """

        if self.__connector is None:
            self.error("Sensor is not started.")
            return

        try:
            if self.__profile is not None:
                self.__profile.stop()

            if self.__active_channel is not None:
                self.__active_channel.close()

            self.__connector.stop()

        finally:
            if self.__wireshark is not None:
                self.__wireshark.detach()

            self.__active_channel = None
            self.__connector = None

            self.update_prompt()

            print("Sensor stopped.")

    def get_profile_content(self):
        """
        Return attributes and interactions of the current profile.
        """

        attributes = []
        interactions = []

        if self.__profile is None:
            return attributes, interactions

        ignored = (
            "data_page_descriptors",
            "application",
            "cumulative_count_attr",
            "cumulative_operating_time_attr",
            "event_time_attr",
            "stop_indicator",

            # Profile configuration
            "DEVICE_TYPE",
            "TRANSMISSION_TYPE",
            "CHANNEL_PERIOD",
            "SEARCH_TIMEOUT",
            "DEFAULT_RF_CHANNEL",
            "NETWORK_KEY",
            "CHANNEL_DIRECTION",

            "default_page_index",
            "header_class",
            "has_page_number_in_header",
            "update_rate",
        )

        for attribute in dir(self.__profile):
            if attribute.startswith("_"):
                continue

            if all(
                c in string.ascii_uppercase + "_"
                for c in attribute
            ):
                continue

            if attribute in ignored:
                continue

            value = getattr(self.__profile, attribute)

            if inspect.isgeneratorfunction(value):
                continue

            if callable(value):
                interactions.append(attribute)
            else:
                attributes.append(attribute)

        return attributes, interactions

    @category("Device interaction")
    def do_profile(self, args):
        """
        Show profile attributes and data pages.
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        attributes, interactions = self.get_profile_content()

        print_formatted_text(
            HTML("<green><b>Attributes</b></green>")
        )

        for attribute in attributes:
            value = getattr(self.__profile, attribute)

            print_formatted_text(
                HTML(
                    f" <b>{attribute}</b>"
                )
            )

            print_formatted_text(
                HTML(
                    f" | <ansicyan>value: </ansicyan>{value}"
                )
            )

        print()

        print_formatted_text(
            HTML("<green><b>Data pages</b></green>")
        )

        descriptors = self.__profile.data_page_descriptors

        if isinstance(descriptors, dict):
            descriptors = descriptors.items()
        else:
            descriptors = [
                (desc.page_number, desc)
                for desc in descriptors
            ]

        for page_number, descriptor in descriptors:
            print_formatted_text(
                HTML(
                    f" <b>{page_number}</b>: "
                    f"{descriptor.layer_class().name}"
                )
            )

            for field in descriptor.layer_class.fields_desc:
                print_formatted_text(
                    HTML(
                        f" | <ansicyan>{field.name}</ansicyan>"
                    )
                )

        print()

    def complete_get(self):
        completions = {}

        attributes, _ = self.get_profile_content()

        for attribute in attributes:
            completions[attribute] = None

        return completions

    @category("Device interaction")
    def do_get(self, args):
        """
        Get an attribute value.
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        if len(args) < 1:
            self.error("Usage: get <attribute>")
            return

        attributes, _ = self.get_profile_content()

        if args[0] not in attributes:
            self.error("Unknown attribute.")
            return

        value = getattr(self.__profile, args[0])

        print_formatted_text(
            HTML(
                f" <b>{args[0]}</b>"
            )
        )

        print_formatted_text(
            HTML(
                f" | <ansicyan>value: </ansicyan>{value}"
            )
        )

    def complete_set(self):
        completions = {}

        attributes, _ = self.get_profile_content()

        for attribute in attributes:
            completions[attribute] = None

        return completions

    @category("Device interaction")
    def do_set(self, args):
        """
        Set the value of a profile attribute.

        Usage:
            set <attribute> <value>
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        if len(args) < 2:
            self.error(
                "Usage: set <attribute> <value>"
            )
            return

        attribute = args[0]

        attributes, _ = self.get_profile_content()

        if attribute not in attributes:
            self.error("Unknown attribute.")
            return

        raw_value = args[1]
        old_value = getattr(self.__profile, attribute)

        try:
            if isinstance(old_value, bool):
                value = raw_value.lower() in (
                    "1",
                    "true",
                    "yes",
                    "on"
                )

            elif isinstance(old_value, int):
                value = int(raw_value, 0)

            elif isinstance(old_value, float):
                value = float(raw_value)

            elif old_value is None:
                try:
                    value = int(raw_value, 0)
                except ValueError:
                    try:
                        value = float(raw_value)
                    except ValueError:
                        value = raw_value

            else:
                value = raw_value

        except ValueError:
            self.error(
                f"Invalid value '{raw_value}' "
                f"for {attribute}."
            )
            return

        setattr(self.__profile, attribute, value)

        self.success(
            f"{attribute} = "
            f"{getattr(self.__profile, attribute)}"
        )

    def complete_monitor(self):
        completions = {}

        attributes, _ = self.get_profile_content()

        for attribute in attributes:
            completions[attribute] = None

        return completions

    @category("Device interaction")
    def do_monitor(self, args):
        """
        Monitor an attribute.
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        if len(args) < 1:
            self.error("Usage: monitor <attribute>")
            return

        attributes, _ = self.get_profile_content()

        if args[0] not in attributes:
            self.error("Unknown attribute.")
            return

        attribute = args[0]
        last_value = object()

        try:
            while True:
                value = getattr(self.__profile, attribute)

                if value != last_value:
                    last_value = value

                    print_formatted_text(
                        HTML(
                            f" <b>{attribute}</b>"
                            f" | <ansicyan>updated value: "
                            f"</ansicyan>{value}"
                        )
                    )

                sleep(0.1)

        except KeyboardInterrupt:
            return

    @category("Device interaction")
    def do_reset(self, args):
        """
        Reset profile values.
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        self.__profile.reset()

        self.success("Sensor profile reset.")

    def complete_send(self):
        completions = {}

        if self.__profile is not None:
            descriptors = self.__profile.data_page_descriptors

            if isinstance(descriptors, dict):
                for page_number, descriptor in descriptors.items():
                    completions[str(page_number)] = None
                    completions[
                        descriptor.layer_class.__name__
                    ] = None
            else:
                for descriptor in descriptors:
                    completions[
                        str(descriptor.page_number)
                    ] = None

                    completions[
                        descriptor.layer_class.__name__
                    ] = None

        return completions

    @category("Device interaction")
    def do_send(self, args):
        """
        Send a specific data page.
        """

        if self.__profile is None:
            self.error("No profile selected.")
            return

        if self.__connector is None:
            self.error("Sensor is not started.")
            return

        if len(args) < 1:
            self.error("Usage: send <page>")
            return

        requested_page = args[0]
        descriptor = None

        descriptors = self.__profile.data_page_descriptors

        if isinstance(descriptors, dict):
            try:
                descriptor = descriptors[int(requested_page)]
            except (ValueError, KeyError):
                for desc in descriptors.values():
                    if desc.layer_class.__name__ == requested_page:
                        descriptor = desc
                        break

        else:
            try:
                page_number = int(requested_page)

                for desc in descriptors:
                    if desc.page_number == page_number:
                        descriptor = desc
                        break

            except ValueError:
                for desc in descriptors:
                    if desc.layer_class.__name__ == requested_page:
                        descriptor = desc
                        break

        if descriptor is None:
            self.error("Invalid data page.")
            return

        self.__profile.send_page(descriptor)

        self.success(
            f"Sent page {descriptor.page_number}."
        )

    def get_profile(self):
        return self.__profile

    def get_device_type(self):
        return self.__device_type