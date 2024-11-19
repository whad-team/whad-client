"""wble-peripheral interactive shell.
"""

from binascii import unhexlify, Error as BinasciiError

# pylint: disable-next=wildcard-import,unused-wildcard-import
from scapy.layers.bluetooth4LE import *

from prompt_toolkit import print_formatted_text, HTML
from hexdump import hexdump

from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.utils.validators import InvalidUUIDException
from whad.exceptions import ExternalToolNotFound
from whad.device import WhadDevice, WhadDeviceConnector
from whad.ble import Peripheral, GenericProfile, AdvDataFieldList, \
    AdvCompleteLocalName, AdvShortenedLocalName, AdvFlagsField
from whad.ble.profile.service import PrimaryService
from whad.ble.profile.characteristic import Characteristic, CharacteristicProperties, \
    ClientCharacteristicConfig, CharacteristicValue
from whad.ble.profile.attribute import UUID
from whad.ble.stack.constants import BT_MANUFACTURERS
from whad.ble.stack.gatt.constants import CHARACS_UUID, SERVICES_UUID
from whad.ble.stack.att.exceptions import AttError, AttributeNotFoundError, \
    InsufficientAuthenticationError, InsufficientAuthorizationError, \
    InsufficientEncryptionKeySize, ReadNotPermittedError, \
    WriteNotPermittedError
from whad.common.monitors import WiresharkMonitor

from whad.cli.shell import InteractiveShell, category

INTRO='''
wble-periph, the WHAD Bluetooth Low Energy peripheral utility
'''

BDADDR_REGEXP = "^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$"

ADRECORDS = {
}

def validate_uuid(uuid: str) -> str:
    """Ensure a user-provided UUID is valid.

    :param uuid: UUID to validate
    :type uuid: str
    :rtype: str
    :return: Validated UUID
    """
    # Parse provided UUID
    if uuid.lower().startswith("0x"):
        uuid = str(UUID(int(uuid, 16)))
    else:
        uuid = str(UUID(uuid))

    # Return the normalized UUID
    return uuid


class MonitoringProfile(GenericProfile):
    """Peripheral monitoring profile.
    """

    def on_characteristic_read(self, service, characteristic, offset=0, length=0):
        """Characteristic read hook.

        This hook is called whenever a characteristic is about to be read by a GATT client.
        If this method returns a byte array, this byte array will be sent back to the
        GATT client. If this method returns None, then the read operation will return an
        error (not allowed to read characteristic value).
        

        :param BlePrimaryService service: Service owning the characteristic
        :param BleCharacteristic characteristic: Characteristic object
        :param int offset: Read offset (default: 0)
        :param int length: Max read length
        :return: Value to return to the GATT client
        """
        print_formatted_text(HTML((
            f"<ansigreen>Reading</ansigreen> characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        if len(characteristic.value) > 0:
            print_formatted_text(HTML(
                f" <i>{hexdump(characteristic.value, result='return')}</i>"
            ))
        else:
            print_formatted_text(HTML(" <i>Empty value</i>"))

    def on_connect(self, conn_handle):
        print_formatted_text(HTML(f"<ansired>New connection</ansired> handle:{conn_handle:d}"))

    def on_disconnect(self, conn_handle):
        print_formatted_text(HTML(f"<ansired>Disconnection</ansired> handle:{conn_handle:d}"))

    def on_characteristic_written(self, service, characteristic, offset=0, value=b'',
                                  without_response=False):
        """Characteristic written hook

        This hook is called whenever a charactertistic has been written by a GATT
        client.
        """
        print_formatted_text(HTML((
            f"<ansimagenta>Wrote</ansimagenta> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))
        print_formatted_text(HTML(f" <i>{hexdump(value, result='return')}</i>"))


    def on_characteristic_subscribed(self, service, characteristic, notification=False,
                                     indication=False):
        # Check if we have a hook to call
        print_formatted_text(HTML((
            f"<ansicyan>Subscribed</ansicyan> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))

    def on_characteristic_unsubscribed(self, service, characteristic):
        print_formatted_text(HTML((
            f"<ansicyan>Unsubscribed</ansicyan> to characteristic "
            f"<ansicyan>{characteristic.uuid}</ansicyan> of service "
            f"<ansicyan>{service.uuid}</ansicyan>"
        )))


class BlePeriphShell(InteractiveShell):
    """Bluetooth Low Energy interactive shell
    """

    MODE_NORMAL = 0
    MODE_SERVICE_EDIT = 1
    MODE_STARTED = 2

    def __init__(self, interface: WhadDevice = None, dev_profile=None):
        super().__init__(HTML("<b>wble-periph></b> "))

        self.__current_mode = self.MODE_NORMAL

        # Device parameters
        self.__complete_name = "WhadDev"
        self.__shortened_name = None
        self.__manuf_data = []
        self.__manuf_comp = None

        # If interface is None, pick the first matching our needs
        self.__interface = interface

        # Profile
        if dev_profile is not None:
            # Set profile
            self.__profile = MonitoringProfile(from_json=dev_profile)
        else:
            self.__profile = MonitoringProfile()

        self.__selected_service = None
        self.__connector: WhadDeviceConnector = None
        self.__wireshark = None
        self.__central_bd = None
        self.intro = INTRO

        # Update prompt
        self.update_prompt()

    def update_prompt(self, force=False):
        """Update prompt to reflect current state
        """
        # Are we in service edit mode ?
        if self.__current_mode == self.MODE_SERVICE_EDIT:
            self.set_prompt(HTML(
                f"<b>wble-periph|<ansicyan>service({self.__selected_service})</ansicyan>></b> "),
                force)
        elif self.__current_mode == self.MODE_NORMAL:
            if not self.__central_bd:
                self.set_prompt(HTML("<b>wble-periph></b> "), force)
            else:
                self.set_prompt(
                    HTML(f"<b>wble-periph|<ansicyan>{self.__central_bd}</ansicyan>></b> "),
                    force)
        elif self.__current_mode == self.MODE_STARTED:
            self.set_prompt(
                HTML("<b>wble-periph<ansimagenta>[running]</ansimagenta>></b>"))


    def switch_role(self, new_role):
        """Switch from current role (if any) to another role.
        """
        if self.__connector is not None:
            self.__connector.stop()
            if self.__wireshark is not None:
                self.__wireshark.detach()
        self.__connector = new_role(self.__interface)
        if self.__wireshark is not None:
            self.__wireshark.attach(self.__connector)
            self.__wireshark.start()

    def show_att_error(self, error: AttError):
        """Parse ATT error and show exception.
        """
        if isinstance(error, InvalidHandleValueException):
            self.error("ATT Error: wrong value handle")
        elif isinstance(error, ReadNotPermittedError):
            self.error("ATT error: read operation not allowed")
        elif isinstance(error, WriteNotPermittedError):
            self.error("ATT error: write operation not allowed")
        elif isinstance(error, InsufficientAuthenticationError):
            self.error("ATT error: insufficient authentication")
        elif isinstance(error, InsufficientAuthorizationError):
            self.error("ATT error: insufficient authorization")
        elif isinstance(error, AttributeNotFoundError):
            self.error("ATT error: attribute not found")
        elif isinstance(error, InsufficientEncryptionKeySize):
            self.error("ATT error: insufficient encryption")

    ##################################################
    # GATT Service management
    ##################################################

    def has_service(self, uuid: str):
        """Check if a service is already registered
        """
        return self.__profile.get_service_by_uuid(UUID(uuid)) is not None

    def get_service(self, uuid: str):
        """Return service characteristics
        """
        service_obj = self.__profile.get_service_by_uuid(UUID(uuid))
        if service_obj is not None:
            return service_obj

        # Cannot find UUID
        raise IndexError

    def register_service(self, uuid: str):
        """Register a service

        @param  str     uuid    Service UUID
        @retval bool    True if service has been successfully registered, False otherwise
        """
        service_obj = self.__profile.get_service_by_uuid(UUID(uuid))
        if service_obj is None:
            self.__profile.add_service(PrimaryService(uuid=UUID(uuid)))
            return True

        return False

    def unregister_service(self, uuid: str):
        """Unregister a service
        """
        service_obj = self.__profile.get_service_by_uuid(UUID(uuid))
        if service_obj is not None:
            self.__profile.remove_service(service_obj)
            return True

        # Fail
        return False

    def enum_services(self):
        """Enumerate services
        """
        for service in self.__profile.services():
            yield (str(service.uuid), service)

    def select_service(self, uuid):
        """Select service and switch to edit mode.
        """
        self.__selected_service = uuid
        self.__current_mode = self.MODE_SERVICE_EDIT
        self.update_prompt()

    def complete_service(self):
        """auto-completion for 'service' command
        """
        services = [str(s.uuid) for s in list(self.__profile.services())]
        completions = {}
        for action in ["add", "edit", "remove"]:
            completions[action] = {}
            for service in services:
                completions[action][service]={}
        return completions

    @category("GATT profile")
    def do_service(self, args):
        """Manage peripheral's GATT services

        <ansicyan><b>service</b> [<i>ACTION</i> <i>[PARAMS, ...]</i>]</ansicyan>

        This command manages the registered services, with the following <i>ACTION</i>s:

        - <b>add</b>: add a service to the peripheral's GATT profile
        - <b>edit</b>: select a service for edition
        - <b>remove</b>: remove a service from the peripheral's GATT profile

        To add a service: <b>service</b> <i>add</i> <i>UUID</i>

        To edit a specific service: <b>service</b> <i>edit</i>

        To remove a service: <b>service</b> <i>remove</i> <i>UUID</i>

        By default, this command lists the registered services.
        """
        if self.__current_mode != self.MODE_NORMAL:
            if self.__current_mode == self.MODE_SERVICE_EDIT:
                self.error("Already editing services.")
            else:
                self.error("Cannot edit services while peripheral is running.")
            return

        if len(args) > 0:
            action = args[0].lower()
            if action == "add":
                if len(args) >= 2:
                    try:
                        # Validate UUID
                        service_uuid = validate_uuid(args[1])

                        # If service already exists, error.
                        if self.has_service(service_uuid):
                            self.error(f"Service {service_uuid} already exists !")
                            return

                        # Register service
                        self.register_service(service_uuid)

                        # Auto-select this service
                        self.select_service(service_uuid)

                        # Success
                        self.success(f"Service {service_uuid} successfully added.")
                    except InvalidUUIDException:
                        self.error(f"Invalid UUID: {args[1]}")
                else:
                    self.error("You need to provide a valid UUID.")
            elif action == "remove":
                # Not allowed in edit mode
                if self.__current_mode == self.MODE_SERVICE_EDIT:
                    self.error((
                        "You cannot add or remove service in service edit mode. "
                        "Use <ansicyan>back</ansicyan> to exit edit mode and try again."))
                else:
                    if len(args) >= 2:
                        try:
                            # Validate UUID
                            service_uuid = validate_uuid(args[1])

                            if self.has_service(service_uuid):
                                self.unregister_service(service_uuid)
                                self.success(f"Successfully removed service {service_uuid}.")
                            else:
                                self.error(f"Service {service_uuid} is not a registered service.")
                        except InvalidUUIDException:
                            self.error("Invalid UUID: {args[1]}")
                    else:
                        self.error("You need to provide a valid UUID.")
            elif action == "edit":
                if self.__current_mode == self.MODE_SERVICE_EDIT:
                    self.error("Already in edit mode.")
                    return

                if len(args) >= 2:
                    try:
                        # Validate UUID
                        service_uuid = validate_uuid(args[1])

                        if self.has_service(service_uuid):
                            self.select_service(service_uuid)
                            self.update_prompt()
                            return

                        # Error, not registered
                        self.error(f"Service {service_uuid} is not a registered service.")
                    except InvalidUUIDException:
                        self.error(f"Invalid UUID: {args[1]}")
                else:
                    self.error("You need to provide a valid UUID.")
            else:
                self.error(f"Unknown action <i>{action}</i>.")
        else:
            # Enumerate services and store them in a list
            services = list(self.__profile.services())

            if len(services) > 0:
                for service in services:
                    # Resolve service name if 16-bit UUID
                    service_uuid = str(service.uuid)
                    if service.uuid.type == UUID.TYPE_16:
                        uuid_val = int(service_uuid, 16)
                        service_name = SERVICES_UUID.get(uuid_val)
                    else:
                        service_name = None

                    if service_name is not None:
                        print_formatted_text(HTML((
                            f"<ansicyan><b>Service {service.uuid}</b> ({service_name})</ansicyan>"
                            f" (handles from {service.handle:d} to {service.end_handle:d}):"
                        )))
                    else:
                        print_formatted_text(HTML((
                            f"<ansicyan><b>Service {service.uuid}</b></ansicyan>"
                            f" (handles from {service.handle:d} to {service.end_handle:d}):"
                        )))

                    characteristics = list(service.characteristics())
                    if len(characteristics) > 0:
                        for i, charac in enumerate(characteristics):

                            char_chevron = "├" if i < (len(characteristics) - 1) else "└"
                            handle_chevron = "│" if i < (len(characteristics) - 1) else " "


                            # Retrieve characteristic name if 16-bit UUID
                            charac_uuid = charac.uuid
                            charac_name = None
                            if charac_uuid.type == UUID.TYPE_16:
                                uuid_val = int(str(charac_uuid), 16)
                                charac_name = CHARACS_UUID.get(uuid_val)

                            properties = charac.properties
                            perms = []
                            if properties & CharacteristicProperties.READ != 0:
                                perms.append("read")
                            if properties & CharacteristicProperties.WRITE != 0:
                                perms.append("write")
                            if properties & CharacteristicProperties.INDICATE != 0:
                                perms.append("indicate")
                            if properties & CharacteristicProperties.NOTIFY != 0:
                                perms.append("notify")

                            if charac_name is not None:
                                print_formatted_text(HTML((
                                    f"{char_chevron}─ <ansicyan><b>Characteristic "
                                    f"{charac.uuid}</b> ({charac_name})</ansicyan>"
                                )))
                            else:
                                print_formatted_text(HTML((
                                    f"{char_chevron}─ <ansicyan><b>Characteristic "
                                    f"{charac.uuid}</b></ansicyan>"
                                )))
                            print_formatted_text(HTML((
                                f"{handle_chevron} └─ handle:{charac.handle:d}, "
                                f"value handle: {charac.value_handle:d}, props: {','.join(perms)}"
                            )))

                            for desc in charac.descriptors():
                                print_formatted_text(HTML((
                                    f"{handle_chevron} └─ <b>Descriptor {desc.type_uuid}</b>"
                                    f" (handle: {desc.handle:d})"
                                )))
                    else:
                        print_formatted_text(HTML(" <i>No characteristics defined</i>"))
            else:
                self.error("No service registered yet.")

    ##################################################
    # GATT Characteristic management
    ##################################################

    def has_service_char(self, service_uuid:str, char_uuid:str):
        """Check if a characteristic is already registered for a specific service
        """
        service_obj = self.__profile.get_service_by_uuid(UUID(service_uuid))
        if service_obj is not None:
            charac = service_obj.get_characteristic(UUID(char_uuid))
            return charac is not None

        # Not found
        return False


    def register_char(self, service_uuid: str, char_uuid: str, perms: list):
        """Add a characteristic

        @param  service_uuid    Service UUID
        @param  char_uuid       Characteristic UUID
        @param  perms           List of permissions
        @retval                 True on success, False on failure
        """
        if not self.has_service_char(service_uuid, char_uuid):
            # Get service
            service_obj = self.get_service(service_uuid)

            # Build charac properties
            props = 0
            if "read" in perms:
                props |= CharacteristicProperties.READ
            if "write" in perms:
                props |= CharacteristicProperties.WRITE
            if "writecmd" in perms:
                props |= CharacteristicProperties.WRITE_WITHOUT_RESPONSE
            if "notify" in perms:
                props |= CharacteristicProperties.NOTIFY
            if "indicate" in perms:
                props |= CharacteristicProperties.INDICATE

            # Build characteristic object
            charac_obj = Characteristic(
                uuid=UUID(char_uuid),
                properties=props,
            )

            if "notify" in perms or "indicate" in perms:
                cccd = ClientCharacteristicConfig(
                    characteristic=charac_obj,
                    indicate=("indicate" in perms),
                    notify=("notify" in perms)
                )

                charac_obj.add_descriptor(cccd)

                charac_obj.value = b''

            # Add characteristic to service
            service_obj.add_characteristic(charac_obj)

            # Update service in profile
            self.__profile.update_service(service_obj)

            # Success
            self.success(f"Successfully added characteristic {char_uuid}")
            return True

        # Fail
        return False

    def unregister_char(self, service_uuid: str, char_uuid: str):
        """Remove characteristic from service
        """
        if self.has_service_char(service_uuid, char_uuid):
            # Get service
            service_obj = self.get_service(service_uuid)

            charac = service_obj.get_characteristic(UUID(char_uuid))
            if charac is not None:
                service_obj.remove_characteristic(charac)
                self.__profile.update_service(service_obj)
                return True

        # Fail
        return False

    def char_parse_perms(self, permissions):
        """Parse permissions
        """
        allowed_keywords = [
            "read",
            "write",
            "writecmd",
            "notify",
            "indicate"
        ]

        out_perms = []
        for perm in permissions:
            if perm.lower() in allowed_keywords:
                out_perms.append(perm.lower())
        return out_perms


    def complete_char(self):
        """Auto-complete char command
        """
        completions = {}
        if self.__selected_service is not None:
            service = self.__profile.get_service_by_uuid(UUID(self.__selected_service))
            if service is not None:
                chars = list(service.characteristics())
                for action in ["add", "remove"]:
                    completions[action] = {}
                    for char in chars:
                        completions[action][str(char.uuid)] = {}
        return completions

    @category("GATT profile")
    def do_char(self, args):
        """Manage peripheral's GATT characteristics

        <ansicyan><b>char</b> [<i>ACTION</i> <i>[PARAMS]</i>]</ansicyan>

        This command manages the registered characteristics of the currently
        selected service. The following <i>ACTION</i>s are available:

        - <b>add</b>: add a characteristic to the current service
        - <b>remove</b>: remove a characteristic from the current service

        charac add 2a00 read write notify
        """
        # Characteristics must be modified only in edit mode
        if self.__current_mode == self.MODE_SERVICE_EDIT:
            if len(args)>0:
                action = args[0]
                if action == "add":
                    if len(args)>=2:
                        try:
                            # Retrieve characteristic UUID
                            char_uuid = validate_uuid(args[1])

                            # Parse permissions
                            if len(args) >= 3:
                                perms = self.char_parse_perms(args[2:])
                            else:
                                perms = ["read"]

                            if not self.has_service_char(self.__selected_service, char_uuid):
                                self.register_char(self.__selected_service, char_uuid, perms)
                            else:
                                self.error((f"Characteristic {char_uuid} already exist in "
                                           f"service {self.__selected_service}"))
                        except InvalidUUIDException:
                            self.error("Invalid UUID for characteristic.")
                    else:
                        print_formatted_text(HTML(
                            "<b>Usage:</b> <ansicyan>add</ansicyan> <i>UUID</i> [<i>PERM,</i> ...]"
                        ))
                elif action == "remove":
                    if len(args)>=2:
                        try:
                            # Retrieve characteristic UUID
                            char_uuid = validate_uuid(args[1])

                            # Remove characteristic
                            if self.has_service_char(self.__selected_service, char_uuid):
                                self.unregister_char(self.__selected_service, char_uuid)
                                self.success(f"Successfully removed characteristic {char_uuid}")
                            else:
                                self.error(f"Characteristic {char_uuid} does not exist.")
                        except InvalidUUIDException:
                            self.error("Invalid UUID for characteristic.")
                    else:
                        print_formatted_text(HTML(
                            "<b>Usage:</b> <ansicyan>remove</ansicyan> <i>UUID</i>"
                        ))
            else:
                # List characteristics
                print_formatted_text(HTML(
                    f"<ansicyan>Characteristics for service {self.__selected_service}:</ansicyan>"
                ))
                selected_service = self.__profile.get_service_by_uuid(UUID(self.__selected_service))
                if selected_service is not None:
                    characs = list(selected_service.characteristics())
                    if len(characs) > 0:
                        for charac in characs:
                            uuid = charac.uuid
                            if uuid.type == UUID.TYPE_16:
                                uuid_val = int(str(uuid), 16)
                                charac_name = CHARACS_UUID.get(uuid_val)
                            else:
                                charac_name = None

                            properties = charac.properties
                            perms = []
                            if properties & CharacteristicProperties.READ != 0:
                                perms.append("read")
                            if properties & CharacteristicProperties.WRITE != 0:
                                perms.append("write")
                            if properties & CharacteristicProperties.INDICATE != 0:
                                perms.append("indicate")
                            if properties & CharacteristicProperties.NOTIFY != 0:
                                perms.append("notify")

                            access = ",".join([f"<b>{perm}</b>" % perm for perm in perms])
                            if charac_name is not None:
                                print_formatted_text(HTML(
                                    f" {charac.uuid} ({charac_name}): {access}"
                                ))
                            else:
                                print_formatted_text(HTML(
                                    f" {charac.uuid}: ({access})"
                                ))
                    else:
                        print_formatted_text(HTML(" No characteristic registered."))


    def char_set_value(self, handle_uuid, value):
        """Set characteristic value based on its handle or UUID
        """
        if isinstance(handle_uuid, int):
            if self.__current_mode != self.MODE_STARTED:
                self.error("Cannot set a characteristic value by its handle")

            # Search characteristic by its handle
            if self.__profile is not None:
                try:
                    charac = self.__profile.find_object_by_handle(handle_uuid)
                    if isinstance(charac, Characteristic):
                        # Update value
                        charac.value = value
                except IndexError:
                    self.error("Cannot find characteristic with UUID %s" % handle_uuid)
            else:
                self.error("GATT profile has not been set.")
        elif isinstance(handle_uuid, UUID):
            # Are we started ?
            if self.__current_mode == self.MODE_STARTED:
                # Find characteristic handle
                for _, service in self.enum_services():
                    charac_obj = service.get_characteristic(handle_uuid)
                    if charac_obj is not None:
                        charac_obj.value = value
                        return
            else:
                # Find characteristic handle
                for _, service in self.enum_services():
                    charac_obj = service.get_characteristic(handle_uuid)
                    if charac_obj is not None:
                        charac_obj.value = value

    def perform_write(self, args, without_response=False):
        """Perform attribute/handle characteristic
        """
        # parse target arguments
        if len(args) <2:
            self.error(("You must provide at least a characteristic value handle"
                        " or characteristic UUID, and a value to write."))
            return

        handle = None

        # Figure out what the handle is
        if args[0].lower().startswith("0x"):
            try:
                handle = int(args[0].lower(), 16)
            except ValueError:
                self.error("Wrong handle: {args[0]}")
                return
        else:
            try:
                handle = int(args[0])
            except ValueError:
                try:
                    handle = UUID(args[0].replace("-",''))
                except Exception:
                    self.error("Wrong UUID: {args[0]}")
                    return

        # Do we have hex data ?
        if args[1].lower() == "hex":
            # Decode hex data
            hex_data = ''.join(args[2:])
            try:
                char_value = unhexlify(hex_data.replace("\t",''))
            except BinasciiError:
                self.error("Provided hex value contains non-hex characters.")
                return
        else:
            char_value = args[1]

        if not isinstance(char_value, bytes):
            char_value = bytes(char_value,"utf-8")

        # Update characteristic value
        self.char_set_value(handle, char_value)

    @category("GATT profile")
    def do_writecmd(self, args):
        """write data to a GATT attribute without waiting for a response.

        <ansicyan><b>writecmd</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

        Write data to the specified GATT attribute (identified by its handle) or to
        a characteristic value (identified by its UUID, if unique) without waiting
        for a response.

        Data can be provided hex-encoded if prefixed by "hex":

        > writecmd 41 hex 41 42 43

        The command above will write 'ABC' to attribute identified by the handle 41.
        
        Data can also be provided as text:

        > writecmd 41 ABC
        """
        self.perform_write(args, without_response=True)

    @category("GATT profile")
    def do_write(self, args):
        """write data to a a GATT attribute.

        <ansicyan><b>write</b> <i>[UUID | handle] [hex [value] | value ]</i></ansicyan>

        Write data to the specified GATT attribute (identified by its handle) or to
        a characteristic value (identified by its UUID, if unique).

        Data can be provided hex-encoded if prefixed by "hex":

        > write 41 hex 41 42 43

        The command above will write 'ABC' to attribute identified by the handle 41.
        
        Data can also be provided as text:

        > write 41 ABC

        """
        self.perform_write(args, without_response=False)

    @category("GATT profile")
    def do_read(self, args):
        """read a GATT attribute

        <ansicyan><b>read</b> <i>[UUID | handle]</i></ansicyan>

        Read an attribute identified by its handle, or read the value of a characteristic
        identified by its UUID (if unique). 

        Result is displayed as an hexadecimal dump with corresponding ASCII text:

        > read 41
         00000000: 74 68 69 73 20 69 73 20  61 20 74 65 73 74        this is a test
        """
        if len(args) >= 1:
            try:
                charac_uuid = UUID(args[0])
                charac = self.__profile.get_characteristic_by_uuid(charac_uuid)
                if charac is not None:
                    print_formatted_text(HTML(
                        f" <i>{hexdump(charac.value, result='return')}</i>"
                    ))
                else:
                    self.error("Unknown characteristic {charac_uuid}")
            except InvalidUUIDException:
                try:
                    # Decode handle
                    if args[0].lower().startswith("0x"):
                        charac_handle = int(args[0], 16)
                    else:
                        charac_handle = int(args[0], 10)

                    # Retrieve characteristic by handle
                    charac = self.__profile.find_object_by_handle(charac_handle)
                    if isinstance(charac, Characteristic):
                        print_formatted_text(HTML(
                            f" <i>{hexdump(charac.value, result='return')}</i>"
                        ))
                    elif isinstance(charac, CharacteristicValue):
                        print_formatted_text(HTML(
                            f" <i>{hexdump(charac.characteristic.value, result='return')}</i>"
                        ))
                    else:
                        self.error(f"Unknown characteristic with handle {charac_handle:d}")
                except ValueError:
                    self.error(f"Wrong UUID or handle: {args[0]}")


    ##################################################
    # Peripheral emulation
    ##################################################

    @category("Peripheral control")
    def do_start(self, _):
        """Start peripheral.

        <ansicyan><b>start</b></ansicyan>

        Starts the peripheral with its configured services and characteristics.
        """

        # Generate AD data
        adv_data = AdvDataFieldList()
        if self.__complete_name is not None:
            adv_data.add(AdvCompleteLocalName(
                bytes(self.__complete_name, "utf-8")
            ))
        if self.__shortened_name is not None:
            adv_data.add(AdvShortenedLocalName(
                bytes(self.__shortened_name, "utf-8")
            ))
        adv_data.add(AdvFlagsField(
            bredr_support=False,
        ))

        # Switch to emulation mode
        self.__current_mode = self.MODE_STARTED
        self.update_prompt()

        # Instanciate our Peripheral
        self.__connector = Peripheral(
            self.__interface,
            profile=self.__profile,
            adv_data=adv_data
        )
        self.__connector.start()

    @category("Peripheral control")
    def do_stop(self, _):
        """Stop peripheral
        """
        if self.__connector is not None:
            self.__connector.stop()
            self.__connector.close()

        self.__current_mode = self.MODE_NORMAL
        self.update_prompt()


    def complete_wireshark(self):
        """Autocomplete wireshark command
        """
        completions = {}
        if self.__wireshark is not None:
            completions["off"] = {}
        else:
            completions["on"] = {}
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
                    self.error(("Wireshark is already launched, see "
                                "<ansicyan>wireshark off</ansicyan>"))
            else:
                # Detach monitor if any
                if self.__wireshark is not None:
                    self.__wireshark.detach()
                    self.__wireshark.close()
                    self.__wireshark = None
        else:
            self.error("Missing arguments, see <ansicyan>help wireshark</ansicyan>.")

    @category("Advertising data")
    def do_name(self, args):
        """Set device advertising complete local name

        <ansicyan><b>name</b> <i>DEVICE NAME</i></ansicyan>

        This command sets the complete local name for the emulated peripheral.
        """
        if len(args) > 0:
            self.__complete_name = args[0]
            self.success(f"Device name set to \"{self.__complete_name}\"")
        else:
            print_formatted_text(HTML(
                f"<ansicyan>Device complete name:</ansicyan> {self.__complete_name}"
            ))


    @category("Advertising data")
    def do_shortname(self, args):
        """Set device short name

        <ansicyan><b>shortname</b> <i>DEVICE NAME</i></ansicyan>

        This command sets the shortened local name for the emulated peripheral.
        """
        if len(args) > 0:
            self.__shortened_name = args[0]
            self.success(f"Device short name set to \"{self.__shortened_name}\"")
        else:
            print_formatted_text(HTML(
                f"<ansicyan>Device short name:</ansicyan> {self.__shortened_name}"
            ))

    @category("Advertising data")
    def do_manuf(self, args):
        """Set device manufacturer company ID and data.

        <ansicyan><b>shortname</b> [<i>COMPANY_ID</i> <i>HEX DATA</i>]</ansicyan>

        This commands defines the company ID to use in BLE advertising record
        along with manufacturer data if a COMPANY_ID and HEX DATA are provided,
        or simply manufacturer data otherwise.
        """
        if len(args) >= 2:
            comp_id = args[0]
            manuf_data = args[1]
            if comp_id.lower().startswith("0x"):
                self.__manuf_comp = int(comp_id, 16)
            else:
                # First, search for company in our list of known companies (no case compare)
                for cid, comp_name in BT_MANUFACTURERS.items():
                    if comp_name.lower() == comp_id:
                        self.__manuf_comp = cid
                        break

                if self.__manuf_comp is None:
                    try:
                        self.__manuf_comp = int(comp_id)
                    except ValueError:
                        self.error("Bad company ID ({comp_id})")
                        return

            try:
                self.__manuf_data = unhexlify(manuf_data)
                self.success("Manufacturer data set.")
            except Exception:
                self.__manuf_data = []
                self.error("Error while parsing manufacturer data (not valid hex)")
        else:
            if self.__manuf_comp is not None:
                if self.__manuf_comp in BT_MANUFACTURERS:
                    manuf_name = BT_MANUFACTURERS[self.__manuf_comp]
                else:
                    manuf_name = "Unknown"
                print_formatted_text(HTML("<ansicyan>Device Manufacturer data record:</ansicyan>"))
                print_formatted_text(HTML(
                    f" <b>Company ID:</b> 0x{self.__manuf_comp:04x} ({manuf_name})"
                ))
                if self.__manuf_data != []:
                    print_formatted_text(HTML(" <b>Manuf. Data:</b>"))
                    nb_lines = int(len(self.__manuf_data)/16)
                    if nb_lines*16 < len(self.__manuf_data):
                        nb_lines += 1
                    for i in range(nb_lines):
                        manuf_data = " ".join([f"{v:02x}" % v
                                               for v in self.__manuf_data[i*16:(i+1)*16]])
                        print_formatted_text(HTML(f"   <i>{manuf_data}</i>"))

            else:
                self.error("No manufacturer data has been set yet.")

    def do_back(self, _):
        """Return to normal mode.

        <ansicyan><b>back</b></ansicyan>

        This command return to normal mode, i.e. exits any configuration mode
        (service edit mode for instance).
        """
        if self.__current_mode != self.MODE_NORMAL:
            self.__current_mode = self.MODE_NORMAL
            self.__selected_service = None
        self.update_prompt()

    def do_quit(self, _):
        """close ble-peripheral
        """
        if self.__connector is not None:
            self.__connector.close()
        return True

    def do_exit(self, arg):
        """alias for <ansicyan>quit</ansicyan>
        """
        return self.do_quit(arg)
