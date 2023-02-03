import re

from prompt_toolkit import print_formatted_text, HTML
from hexdump import hexdump
from binascii import unhexlify, Error as BinasciiError

from scapy.layers.bluetooth4LE import *

from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.utils.validators import InvalidUUIDException
from whad.exceptions import ExternalToolNotFound
from whad.device import WhadDevice, WhadDeviceConnector
from whad.ble import Peripheral, GenericProfile, AdvDataFieldList, \
    AdvCompleteLocalName, AdvShortenedLocalName, AdvFlagsField
from whad.ble.profile.service import PrimaryService
from whad.ble.profile.characteristic import Characteristic, CharacteristicProperties, \
    ClientCharacteristicConfig
from whad.ble.utils.att import UUID
from whad.ble.stack.constants import BT_MANUFACTURERS
from whad.ble.stack.gatt.constants import CHARACS_UUID, SERVICES_UUID
from whad.ble.stack.att.exceptions import AttError, AttributeNotFoundError, \
    InsufficientAuthenticationError, InsufficientAuthorizationError, \
    InsufficientEncryptionKeySize, ReadNotPermittedError, \
    WriteNotPermittedError
from whad.ble.stack.gatt.exceptions import GattTimeoutException
from whad.common.monitors import WiresharkMonitor

from whad.cli.shell import InteractiveShell

import logging
logging.basicConfig(level=logging.DEBUG)

INTRO='''
ble-periph, the WHAD Bluetooth Low Energy peripheral utility
'''

BDADDR_REGEXP = '^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$'

ADRECORDS = {

}

class BlePeriphShell(InteractiveShell):
    """Bluetooth Low Energy interactive shell
    """

    MODE_NORMAL = 0
    MODE_SERVICE_EDIT = 1
    MODE_STARTED = 2

    def __init__(self, interface: WhadDevice = None):
        super().__init__(HTML('<b>ble-periph></b> '))

        self.__current_mode = self.MODE_NORMAL

        # Device parameters
        self.__complete_name = 'WhadDev'
        self.__shortened_name = None
        self.__manuf_data = []
        self.__manuf_comp = None
        
        # If interface is None, pick the first matching our needs
        self.__interface = interface

        # GATT services
        self.__services = {}
        self.__ordered_services = []

        # GATT characteristics
        self.__characteristics = {}

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
            self.set_prompt(HTML('<b>ble-periph|<ansicyan>service(%s)</ansicyan>></b> ' % (
                self.__selected_service
            )), force)
        elif self.__current_mode == self.MODE_NORMAL:
            if not self.__central_bd:
                self.set_prompt(HTML('<b>ble-periph></b> '), force)
            else:
                self.set_prompt(HTML('<b>ble-periph|<ansicyan>%s</ansicyan>></b> ' % self.__central_bd), force)


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
            self.error('ATT Error: wrong value handle')
        elif isinstance(error, ReadNotPermittedError):
            self.error('ATT error: read operation not allowed')
        elif isinstance(error, WriteNotPermittedError):
            self.error('ATT error: write operation not allowed')
        elif isinstance(error, InsufficientAuthenticationError):
            self.error('ATT error: insufficient authentication')
        elif isinstance(error, InsufficientAuthorizationError):
            self.error('ATT error: insufficient authorization')
        elif isinstance(error, AttributeNotFoundError):
            self.error('ATT error: attribute not found')
        elif isinstance(error, InsufficientEncryptionKeySize):
            self.error('ATT error: insufficient encryption')

    ##################################################
    # GATT Service management
    ##################################################

    def has_service(self, uuid: str):
        """Check if a service is already registered
        """
        return uuid in self.__services

    def get_service(self, uuid: str):
        """Return service characteristics
        """
        if self.has_service(uuid):
            return self.__services[uuid]
        else:
            raise IndexError

    def register_service(self, uuid: str):
        """Register a service

        @param  str     uuid    Service UUID
        @retval bool    True if service has been successfully registered, False otherwise
        """
        if not self.has_service(uuid):
            self.__services[uuid] = []
            self.__ordered_services.append(uuid)
            return True

        return False

    def unregister_service(self, uuid: str):
        """Unregister a service
        """
        if self.has_service(uuid):
            del self.__services[uuid]
            self.__ordered_services.remove(uuid)
            return True

        # Fail
        return False

    def enum_services(self):
        """Enumerate services
        """
        for service_uuid in self.__ordered_services:
            yield (service_uuid, self.__services[service_uuid])

    def select_service(self, uuid):
        """Select service and switch to edit mode.
        """
        self.__selected_service = uuid
        self.__current_mode = self.MODE_SERVICE_EDIT
        self.update_prompt()

    def do_service(self, args):
        """Manage peripheral's GATT services

        <ansicyan><b>services</b> [<i>ACTION</i> <i>[PARAMS, ...]</i>]</ansicyan>

        This command manages the registered services, with the following <i>ACTION</i>s:

        - <b>add</b>: add a service to the peripheral's GATT profile
        - <b>edit</b>: select a service for edition
        - <b>remove</b>: remove a service from the peripheral's GATT profile

        To add a service: <b>service</b> <i>add</i> <i>UUID</i>

        To edit a specific service: <b>service</b> <i>edit</i>

        To remove a service: <b>service</b> <i>remove</i> <i>UUID</i>

        By default, this command lists the registered services.
        """
        if len(args) > 0:
            action = args[0].lower()
            if action == 'add':
                if len(args) >= 2:
                    try:
                        service_uuid = str(UUID(args[1]))

                        # If service already exists, error. 
                        if self.has_service(service_uuid):                        
                            self.error('Service %s already exists !' % service_uuid)
                            return

                        # Register service
                        self.register_service(service_uuid)

                        # Auto-select this service
                        self.select_service(service_uuid)

                        # Success
                        self.success('Service %s successfully added.' % service_uuid)
                    except InvalidUUIDException as uuid_err:
                        self.error('Invalid UUID: %s' % args[1])
                else:
                    self.error('You need to provide a valid UUID.')
            elif action == 'remove':
                # Not allowed in edit mode
                if self.__current_mode == self.MODE_SERVICE_EDIT:
                    self.error('You cannot add or remove service in service edit mode. Use <ansicyan>back</ansicyan> to exit edit mode and try again.')
                else:
                    if len(args) >= 2:
                        try:
                            service_uuid = str(UUID(args[1]))

                            if self.has_service(service_uuid):
                                self.unregister_service(service_uuid)
                                self.success('Successfully removed service %s.' % service_uuid)
                            else:
                                self.error('Service %s is not a registered service.' % service_uuid)
                        except InvalidUUIDException as uuid_err:
                            self.error('Invalid UUID: %s' % args[1])
                    else:
                        self.error('You need to provide a valid UUID.')
            elif action == 'edit':
                if self.__current_mode == self.MODE_SERVICE_EDIT:
                    self.error('Already in edit mode.')
                    return

                if len(args) >= 2:
                    try:
                        service_uuid = str(UUID(args[1]))

                        if self.has_service(service_uuid):
                            self.select_service(service_uuid)
                            self.update_prompt()
                            return
                        else:
                            self.error('Service %s is not a registered service.' % service_uuid)
                    except InvalidUUIDException as uuid_err:
                        self.error('Invalid UUID: %s' % args[1])
                else:
                    self.error('You need to provide a valid UUID.')
            else:
                self.error('Unknown action <i>%s</i>.' % action)
        else:
            if len(self.__services) > 0:
                for service_uuid in self.__ordered_services:
                    serv_uuid = UUID(service_uuid)
                    if serv_uuid.type == UUID.TYPE_16:
                        uuid_val = int(service_uuid, 16)
                        if uuid_val in SERVICES_UUID:
                            service_name = SERVICES_UUID[uuid_val]
                        else:
                            service_name = None
                    else:
                        service_name = None

                    if service_name is not None:
                        print_formatted_text(HTML('<ansicyan><b>Service %s (%s)</b></ansicyan>') % (
                            service_uuid,
                            service_name
                        ))
                    else:
                        print_formatted_text(HTML('<ansicyan><b>Service %s</b></ansicyan>') % service_uuid)

                    service = self.get_service(service_uuid)
                    if len(service) > 0:
                        for charac in service:
                            charac_uuid = UUID(charac['uuid'])
                            charac_name = None
                            if charac_uuid.type == UUID.TYPE_16:
                                uuid_val = int(str(charac_uuid), 16)
                                if uuid_val in CHARACS_UUID:
                                    charac_name = CHARACS_UUID[uuid_val]


                            if charac_name is not None:
                                print_formatted_text(HTML(' %s (%s): %s' % (
                                    charac['uuid'],
                                    charac_name,
                                    ','.join(['<b>%s</b>' % perm for perm in charac['perms']])
                                )))
                            else:
                                print_formatted_text(HTML(' %s: %s)' % (
                                    charac['uuid'],
                                    ','.join(['<b>%s</b>' % perm for perm in charac['perms']])
                                )))

            else:
                self.error('No service registered yet.')

    ##################################################
    # GATT Characteristic management
    ##################################################

    def has_service_char(self, service_uuid:str, char_uuid:str):
        """Check if a characteristic is already registered for a specific service
        """
        if self.has_service(service_uuid):
            # Loop in service characteristics
            for char in self.get_service(service_uuid):
                if char['uuid'] == char_uuid:
                    # Characteristic found
                    return True

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
            service = self.get_service(service_uuid)
            
            # Add a characteristic
            service.append({
                'uuid': char_uuid,
                'perms': perms,
                'value': b''
            })

            # Success
            return True
        
        # Fail
        return False

    def unregister_char(self, service_uuid: str, char_uuid: str):
        """Remove characteristic from service
        """
        if self.has_service_char(service_uuid, char_uuid):
            service = self.get_service(service_uuid)
            char_obj = None
            for char in service:
                if char['uuid'] == char_uuid:
                    char_obj = char
                    break
            if char_obj is not None:
                service.remove(char_obj)

            # Success
            return True
        
        # Fail
        return False

    def char_parse_perms(self, permissions):
        """Parse permissions
        """
        allowed_keywords = [
            'read',
            'write',
            'writecmd',
            'notify',
            'indicate'
        ]

        out_perms = []
        for perm in permissions:
            if perm.lower() in allowed_keywords:
                out_perms.append(perm.lower())
        return out_perms



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
                if action == 'add':
                    if len(args)>=2:
                        try:
                            # Retrieve characteristic UUID
                            char_uuid = str(UUID(args[1]))

                            # Parse permissions
                            if len(args) >= 3:
                                perms = self.char_parse_perms(args[2:])
                            else:
                                perms = ['read']

                            if not self.has_service_char(self.__selected_service, char_uuid):
                                self.register_char(self.__selected_service, char_uuid, perms)
                            else:
                                self.error('Characteristic %s already exist in service %s' % (
                                    char_uuid, self.__selected_service
                                ))
                        except InvalidUUIDException as uuid_err:
                            self.error('Invalid UUID for characteristic.')
                    else:
                        print_formatted_text(HTML(
                            '<b>Usage:</b> <ansicyan>add</ansicyan> <i>UUID</i> [<i>PERM,</i> ...]'
                        ))
                elif action == 'remove':
                    if len(args)>=2:
                        try:
                            # Retrieve characteristic UUID
                            char_uuid = str(UUID(args[1]))

                            # Remove characteristic
                            if self.has_service_char(self.__selected_service, char_uuid):
                                self.unregister_char(self.__selected_service, char_uuid)
                                self.success('Successfully removed characteristic %s' % char_uuid)
                            else:
                                self.error('Characteristic %s does not exist.' % char_uuid)
                        except InvalidUUIDException as uuid_err:
                            self.error('Invalid UUID for characteristic.')
                    else:
                        print_formatted_text(HTML(
                            '<b>Usage:</b> <ansicyan>remove</ansicyan> <i>UUID</i>'
                        ))
            else:
                # List characteristics
                if len(self.__services[self.__selected_service]) > 0:
                    for charac in self.__services[self.__selected_service]:
                        uuid = UUID(charac['uuid'])
                        if uuid.type == UUID.TYPE_16:
                            uuid_val = int(str(uuid), 16)
                            if uuid_val in CHARACS_UUID:
                                charac_name = CHARACS_UUID[uuid_val]
                            else:
                                charac_name = None
                        else:
                            charac_name = None

                        if charac_name is not None:
                            print_formatted_text(HTML(' %s (%s): %s' % (
                                charac['uuid'],
                                charac_name,
                                ','.join(['<b>%s</b>' % perm for perm in charac['perms']])
                            )))

                        else:
                            print_formatted_text(HTML(' %s: %s)' % (
                                charac['uuid'],
                                ','.join(['<b>%s</b>' % perm for perm in charac['perms']])
                            )))
                else:
                    print_formatted_text(HTML(' No characteristic registered.'))
        else:
            self.error('No service selected for modification.')


    def char_set_value(self, handle_uuid, value):
        """Set characteristic value based on its handle or UUID
        """
        if isinstance(handle_uuid, int):
            if self.__current_mode != self.MODE_STARTED:
                self.error('Cannot set a characteristic value by its handle')
            
            # Search characteristic by its handle
            if self.__profile is not None:
                charac = self.__profile.find_object_by_handle(handle_uuid)
                if isinstance(charac, Characteristic):
                    # Update value
                    charac.value = value
            else:
                self.error('GATT profile has not been set.')
        elif isinstance(handle_uuid, UUID):
            # Are we started ?
            if self.__current_mode == self.MODE_STARTED:
                # Find characteristic handle
                for service_uuid, service in self.enum_services():
                    for charac in service:
                        if charac['uuid'] == str(handle_uuid):
                            charac_obj = self.__profile.find_object_by_handle(charac['handle'])
                            charac_obj.value = value
                            return
            else:
                # Find characteristic handle
                for service_uuid, service in self.enum_services():
                    for charac in service:
                        if charac['uuid'] == str(handle_uuid):
                            charac['value'] = value

    def perform_write(self, args, without_response=False):
        """Perform attribute/handle characteristic
        """
        # parse target arguments
        if len(args) <2:
            self.error('You must provide at least a characteristic value handle or characteristic UUID, and a value to write.')
            return
        else:
            handle = None
            offset = None
            uuid = None

        # Figure out what the handle is
        if args[0].lower().startswith('0x'):
            try:
                handle = int(args[0].lower(), 16)
            except ValueError as badval:
                self.error('Wrong handle: %s' % args[0])
                return
        else:
            try:
                handle = int(args[0])
            except ValueError as badval:
                try:
                    handle = UUID(args[0].replace('-',''))
                except:
                    self.error('Wrong UUID: %s' % args[0])
                    return

        # Do we have hex data ?
        if args[1].lower() == 'hex':
            # Decode hex data
            hex_data = ''.join(args[2:])
            try:
                char_value = unhexlify(hex_data.replace('\t',''))
            except BinasciiError as err:
                self.error('Provided hex value contains non-hex characters.')
                return
        else:
            char_value = args[1]

        if not isinstance(char_value, bytes):
            char_value = bytes(char_value,'utf-8')
            
        # Update characteristic value
        self.char_set_value(handle, char_value)

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
        
    ##################################################
    # Peripheral emulation
    ##################################################    

    def do_start(self, args):
        """Start peripheral.

        <ansicyan><b>start</b></ansicyan>

        Starts the peripheral with its configured services and characteristics.
        """
        # Build our profile from registered services and characteristics
        handle = 1
        self.__profile = GenericProfile()
        for service_uuid, service in self.enum_services():
            service_obj = PrimaryService(uuid=UUID(service_uuid), handle=handle)
            handle += 1
            for charac in service:
                # Build charac properties
                props = 0
                if 'read' in charac['perms']:
                    props |= CharacteristicProperties.READ
                if 'write' in charac['perms']:
                    props |= CharacteristicProperties.WRITE
                if 'writecmd' in charac['perms']:
                    props |= CharacteristicProperties.WRITE_WITHOUT_RESPONSE
                if 'notify' in charac['perms']:
                    props |= CharacteristicProperties.NOTIFY
                if 'indicate' in charac['perms']:
                    props |= CharacteristicProperties.INDICATE

                # Build characteristic object
                charac_obj = Characteristic(
                    uuid=UUID(charac['uuid']),
                    properties=props,
                    handle=handle
                )
                charac['handle']=handle
                handle += 2

                if 'notify' in charac['perms'] or 'indicate' in charac['perms']:
                    cccd = ClientCharacteristicConfig(
                        characteristic=charac_obj,
                        handle = handle,
                        indicate=('indicate' in charac['perms']),
                        notify=('notify' in charac['perms']) 
                    )
                    handle += 1

                    charac_obj.add_descriptor(cccd)
                    self.__profile.register_attribute(cccd)


                charac_obj.value = charac['value']
                service_obj.add_characteristic(charac_obj)
                self.__profile.register_attribute(charac_obj)

            service_obj.end_handle = handle-1
            self.__profile.add_service(service_obj)
            self.__profile.register_attribute(service_obj)
        
        # Generate AD data
        adv_data = AdvDataFieldList()
        if self.__complete_name is not None:
            adv_data.add(AdvCompleteLocalName(
                bytes(self.__complete_name, 'utf-8')
            ))
        if self.__shortened_name is not None:
            adv_data.add(AdvShortenedLocalName(
                bytes(self.__shortened_name, 'utf-8')
            ))
        adv_data.add(AdvFlagsField(
            bredr_support=False,
        ))

        # Switch to emulation mode
        self.__current_mode = self.MODE_STARTED

        # Instanciate our Peripheral
        self.__connector = Peripheral(
            self.__interface,
            profile=self.__profile,
            adv_data=adv_data
        )
        self.__connector.start()

    def do_stop(self, arg):
        """Stop peripheral
        """
        if self.__connector is not None:
            self.__connector.stop()
            self.__connector.close()

        self.__current_mode = self.MODE_NORMAL
        self.__profile = None


    def complete_wireshark(self):
        """Autocomplete wireshark command
        """
        completions = {}
        if self.__wireshark is not None:
            completions['off'] = {}
        else:
            completions['on'] = {}
        return completions

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
                    except ExternalToolNotFound as notfound:
                        self.error('Cannot launch Wireshark, please make sure it is installed.')
                else:
                    self.error('Wireshark is already launched, see <ansicyan>wireshark off</ansicyan>')
            else:
                # Detach monitor if any
                if self.__wireshark is not None:
                    self.__wireshark.detach()
                    self.__wireshark.close()
                    self.__wireshark = None
        else:
            self.error('Missing arguments, see <ansicyan>help wireshark</ansicyan>.')


    def do_name(self, args):
        """Set device advertising complete local name

        <ansicyan><b>name</b> <i>DEVICE NAME</i></ansicyan>

        This command sets the complete local name for the emulated peripheral.
        """
        if len(args) > 0:
            self.__complete_name = args[0]
            self.success('Device name set to "%s"' % self.__complete_name)
        else:
            print_formatted_text(HTML('<ansicyan>Device complete name:</ansicyan> %s' % self.__complete_name))


    def do_shortname(self, args):
        """Set device short name

        <ansicyan><b>shortname</b> <i>DEVICE NAME</i></ansicyan>

        This command sets the shortened local name for the emulated peripheral.
        """
        if len(args) > 0:
            self.__shortened_name = args[0]
            self.success('Device short name set to "%s"' % self.__shortened_name)
        else:
            print_formatted_text(HTML('<ansicyan>Device short name:</ansicyan> %s' % self.__shortened_name))

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
            if comp_id.lower().startswith('0x'):
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
                    except ValueError as e:
                        self.error('Bad company ID (%s)' % comp_id)
                        return

            try:
                self.__manuf_data = unhexlify(manuf_data)
                self.success('Manufacturer data set.')
            except Exception as exc:
                self.__manuf_data = []
                self.error('Error while parsing manufacturer data (not valid hex)')
        else:
            if self.__manuf_comp is not None:
                if self.__manuf_comp in BT_MANUFACTURERS:
                    manuf_name = BT_MANUFACTURERS[self.__manuf_comp]
                else:
                    manuf_name = 'Unknown'
                print_formatted_text(HTML('<ansicyan>Device Manufacturer data record:</ansicyan>'))
                print_formatted_text(HTML(' <b>Company ID:</b> 0x%04x (%s)' % (
                    self.__manuf_comp, manuf_name
                )))
                if self.__manuf_data != []:
                    print_formatted_text(HTML(' <b>Manuf. Data:</b>'))
                    nb_lines = int(len(self.__manuf_data)/16)
                    if nb_lines*16 < len(self.__manuf_data):
                        nb_lines += 1
                    for i in range(nb_lines):
                        print_formatted_text(HTML('   <i>%s</i>') % (
                            ' '.join(['%02x' % v for v in self.__manuf_data[i*16:(i+1)*16]])
                        ))

            else:
                self.error('No manufacturer data has been set yet.')




    def do_back(self, arg):
        """Return to normal mode.

        <ansicyan><b>back</b></ansicyan>

        This command return to normal mode, i.e. exits any configuration mode
        (service edit mode for instance).
        """
        if self.__current_mode != self.MODE_NORMAL:
            self.__current_mode = self.MODE_NORMAL
        self.update_prompt()



    def do_quit(self, arg):
        """close ble-peripheral
        """
        if self.__interface is not None:
            self.__interface.close()
        return True

    def do_exit(self, arg):
        """alias for <ansicyan>quit</ansicyan>
        """
        return self.do_quit(arg)
