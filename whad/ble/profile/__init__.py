"""This module provides different classes that represent a BLE device and
allows to interact with it:

* :class:`whad.ble.profile.Profile` is a base class used to register all
  the ATT attributes, including services, characteristics, characteristic values
  and descriptors. It is able to inspect any derived class and build the
  corresponding profile based on properties declared with
  :class:`whad.ble.profile.service.PrimaryService` and
  :class:`whad.ble.profile.characteristic.Characteristic`.

* :class:`whad.ble.profile.read` is a decorator class used to mark a method
  as a callback associated to a GATT read operation for a specific characteristic.
* :class:`whad.ble.profile.write` is a decorator class used to mark a method as a
  callback associated to a GATT write operation to be performed on a specific characteristic.
* :class:`whad.ble.profile.written` is a decorator class used to mark a methiod as
  a callback associated to a performed GATT write operation for a specific characteristic.
* :class:`whad.ble.profile.subscribed` is a decorator class used to mark a method as
  a callback associated to a subscription for notification or indication for a specific
  characteristic
* :class:`whad.ble.profile.unsubscribed` is a decorator class used to mark a method as
  a callback associated to an unsubscription for notification or indication for a specific
  characteristic
"""
import json
import logging
from typing import List, Iterator, Optional, Callable, Any, Union

from whad.ble.profile.attribute import Attribute, UUID
from whad.ble.profile.characteristic import (
    Characteristic, CharacteristicValue, Properties, ClientCharacteristicConfig, Descriptor, CharacteristicDescriptor,
    ReportReference, UserDescription, CharacteristicUserDescriptionDescriptor, ReportReferenceDescriptor
)

from whad.ble.profile.service import PrimaryService, SecondaryService, IncludeService, Service
from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.stack.att.constants import SecurityAccess

logger = logging.getLogger(__name__)

###################################
# Decorators for GenericProfile
###################################

class CharacteristicHook:
    """Characteristic hook decorator.

    This class defines the base hook decorator class and must be inherited.
    """

    def __init__(self, *args):
        if len(args) == 1:
            characteristic = args[0]
            if isinstance(characteristic, Characteristic):
                self.__characteristic = f"{characteristic.service.uuid}:{characteristic.uuid}"
            else:
                raise TypeError
        elif len(args) == 2:
            service = args[0]
            charac = args[1]
            if isinstance(service, str) and isinstance(charac, str):
                self.__characteristic = f"{UUID(service)}:{UUID(charac)}"
            elif isinstance(service, UUID) and isinstance(charac, UUID):
                self.__characteristic = f"{service}:{charac}"

    def __call__(self, method):
        if not hasattr(method, "hooks"):
            method.hooks = []
        if not hasattr(method, "characteristic"):
            method.characteristic = self.__characteristic
        return method

# Decorator name does not start with a capital letter for ease of use
# pylint: disable-next=invalid-name
class read(CharacteristicHook):
    """Read hook decorator

    This decorator is used to declare a callback method for read operations
    on a specific characteristic.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if "read" not in method.hooks:
            method.hooks.append('read')
        return method

# Decorator name does not start with a capital letter for ease of use
# pylint: disable-next=invalid-name
class write(CharacteristicHook):
    """Write hook decorator

    This decorator is used to declare a callback method for write operations
    on a specific characteristic. This callback will be called **before** the
    write operation happens.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if "write" not in method.hooks:
            method.hooks.append('write')
        return method

# Decorator name does not start with a capital letter for ease of use
# pylint: disable-next=invalid-name
class written(CharacteristicHook):
    """Written hook decorator

    This decorator is used to declare a callback method for write operations
    on a specific characteristic. This callback will be called **after** the
    write operation happens.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if "written" not in method.hooks:
            method.hooks.append("written")
        return method

# Decorator name does not start with a capital letter for ease of use
# pylint: disable-next=invalid-name
class subscribed(CharacteristicHook):
    """Subscribe hook decorator

    This decorator is used to declare a callback method for subscribe operations
    on a specific characteristic.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if "sub" not in method.hooks:
            method.hooks.append("sub")
        return method

# Decorator name does not start with a capital letter for ease of use
# pylint: disable-next=invalid-name
class unsubscribed(CharacteristicHook):
    """Unsubscribe hook decorator

    This decorator is used to declare a callback method for unsubscribe operations
    on a specific characteristic.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if "unsub" not in method.hooks:
            method.hooks.append("unsub")
        return method

def is_method_hook(method):
    """Determine if a method is a characteristic operation hook
    """
    if hasattr(method, "hooks") and hasattr(method, "characteristic"):
        return len(method.hooks) > 0
    return False

class Profile:
    """This class implements a GATT profile, i.e. a set of services and characteristics
    exposed by a Bluetooth Low Energy GATT server.
    """

    def __init__(self, start_handle: int = 1, from_json: Optional[str] = None):
        """Parse the device model, instantiate all the services, characteristics
        and descriptors, compute all handle values and registers everything
        inside this instance for further use.

        :param  start_handle:   Start handle value to use (default: 0)
        :type   start_handle:   int
        :param  from_json:      JSON data describing a GATT profile
        :type   from_json:      str
        """
        self.__attr_db = {}
        self.__services = []
        self.__service_by_characteristic_handle = {}

        self.__start_handle = start_handle
        self.__handle = self.__start_handle

        self.__hooks = {}

        # Populate attribute database and model from JSON export if provided
        if from_json is not None:
            from_json: dict = json.loads(from_json)
            # Parse JSON services, characteristics and descriptors to create
            # the corresponding model and attribute database
            if 'services' in from_json:
                # Loop on services
                for service in from_json['services']:
                    # Collect characteristics
                    if UUID(service['type_uuid']) == UUID(0x2800):
                        service_obj = PrimaryService(
                            uuid=UUID(service['uuid']),
                            handle=service['start_handle'],
                            end_handle=service['end_handle'],
                        )
                    elif UUID(service['type_uuid']) == UUID(0x2801):
                        service_obj = SecondaryService(
                            uuid=UUID(service['uuid']),
                            handle=service['start_handle'],
                            end_handle=service['end_handle']
                        )
                    else:
                        # This is not a known service type UUID, continue with
                        # next service
                        continue

                    if 'characteristics' in service:
                        for charac in service['characteristics']:
                            # Load characteristic data (if provided)
                            charac_data = b''
                            if 'data' in charac['value']:
                                charac_data = bytes.fromhex(charac['value']['data'])

                            # Create characteristic model
                            charac_obj = Characteristic(
                                uuid=UUID(charac['value']['uuid']),
                                handle=charac['handle'],
                                value=charac_data,
                                properties=charac['properties'],
                                security=SecurityAccess.int_to_accesses(charac['security'])
                            )

                            # Loop on descriptors for the current characteristic
                            for desc in charac['descriptors']:
                                # Try to convert this descriptor to an instance
                                # of one of our supported descriptors
                                desc_obj = Descriptor.from_uuid(
                                    handle=desc['handle'],
                                    uuid=UUID(desc['uuid']),
                                    value=bytes.fromhex(desc['value']) if 'value' in desc else b'',
                                    characteristic=charac_obj,
                                )

                                # Add descriptor
                                if desc_obj is not None:
                                    charac_obj.add_descriptor(desc_obj)
                                    self.register_attribute(desc_obj)

                            # Register characteristic and its value
                            self.register_attribute(charac_obj)
                            self.register_attribute(charac_obj.value_attr)

                            # Add characteristic to its related service
                            service_obj.add_characteristic(charac_obj)

                    self.register_attribute(service_obj)
                    self.add_service(service_obj)
        else:
            # Introspect this class definition and build model
            services = []
            props = dir(self)
            for prop in props:
                if not prop.startswith('_'):
                    if isinstance(getattr(self, prop), Service):
                        service = getattr(self, prop)
                        services.append((prop, service))

            # Instantiate each service, and for each of them the corresponding
            # characteristics
            for name, service in services:
                if isinstance(service, PrimaryService):
                    logger.info("creating primary service %s", service.uuid)
                    # Create service
                    service_obj = service.build()

                elif isinstance(service, SecondaryService):
                    logger.info("creating secondary service %s", service.uuid)
                    # Create service
                    service_obj = service.build()
                else:
                    continue

                # Overwrite the corresponding instance property with our new
                # service instance.
                self.add_service(service_obj)
                setattr(self, name, service_obj)

            # We then need to update included service start and end handles
            for inc_service in self.included_services():
                # Retrieve the included service UUID
                service_uuid = inc_service.service_uuid

                # Retrieve the corresponding object by UUID
                service_obj = self.get_service_by_uuid(service_uuid)

                # If found, update start and end handles
                if service_obj is not None and service_obj.handle is not None:
                    inc_service.service_start_handle = service_obj.handle
                    inc_service.service_end_handle = service_obj.end_handle


        # Register any hook function declared in profile class
        props = dir(self)
        for prop in props:
            prop_obj = getattr(self, prop)
            # Is this property a callable hook ?
            if callable(prop_obj) and is_method_hook(prop_obj):
                # Associate hook method with each operation
                if prop_obj.characteristic not in self.__hooks:
                    self.__hooks[prop_obj.characteristic] = {}
                for operation in prop_obj.hooks:
                    self.__hooks[prop_obj.characteristic][operation] = prop_obj


    @property
    def db(self):
        return self.__attr_db

    def __alloc_handle(self, number: int = 1):
        """Allocate one or more handle values.

        :param  number: Number of handle values to allocate
        :type   number: int

        :return: Current handle value
        :rtype: int
        """
        current_handle = self.__handle
        self.__handle += number
        return current_handle

    def __repr__(self):
        output = ''
        for service in self.services():
            output += (
                f"Service {service.uuid} (handles from {service.handle:d} to "
                f"{service.end_handle:d}):\n"
            )

            for inc_service in service.included_services():
                output += (
                    f"  Included service {inc_service.service_uuid} "
                    f"(handle:{inc_service.handle:d}, "
                    f"start_handle:{inc_service.service_start_handle:d}, "
                    f"end_handle:{inc_service.service_end_handle:d})\n"
                )
            for charac in service.characteristics():
                properties = charac.properties
                charac_rights = ''
                if properties & Properties.READ != 0:
                    charac_rights += 'R'
                if properties & Properties.WRITE != 0:
                    charac_rights += 'W'
                if properties & Properties.INDICATE != 0:
                    charac_rights += 'I'
                if properties & Properties.NOTIFY != 0:
                    charac_rights += 'N'

                output += (
                    f"  Characteristic {charac.uuid} (handle:{charac.handle:d}, "
                    f"value handle: {charac.value_handle:d}, "
                    f"props: {charac_rights}, {charac.alias})\n"
                )
                for desc in charac.descriptors():
                    output += f"    Descriptor {desc.type_uuid} (handle: {desc.handle:d})\n"
        return output

    def register_attribute(self, attribute: Attribute):
        """Register a GATT attribute

        :param  attribute:  Attribute to register
        :type   attribute:  Attribute
        """
        if isinstance(attribute, Attribute):
            self.__attr_db[attribute.handle] = attribute


    def add_service(self, service: Service, handles_only: bool = False):
        """Add a service to the current device

        :param  service:        Service to add to the device
        :type   service:        Service
        :param  handles_only:   Add only service handles if set to ``True``
        :type   handles_only:   bool
        """
        logger.debug("add service %s", service.uuid)
        if service.handle == 0:
            # Service has not been fully configured, update its handle
            # and the handles of its characteristics and descriptors.
            service.handle = self.__alloc_handle()

        # Append service to the list of our services
        if not handles_only and service not in self.__services:
            self.__services.append(service)

        # Register service as an attribute
        self.register_attribute(service)

        # Register all its characteristics
        for charac in service.characteristics():
            # Register Characteristic and its CharacteristicValue
            self.register_attribute(charac)
            self.register_attribute(charac.value_attr)

            # Register characteristic's descriptors
            for desc in charac.descriptors():
                self.register_attribute(desc)

            # Add characteristic in our lookup table
            self.__service_by_characteristic_handle[charac.handle] = service

        # Update our last handle based on service's end handle
        self.__handle = service.end_handle + 1

    def remove_service(self, service: Service, handles_only: bool = False):
        """Remove service

        :param  service:        Service object or UUID
        :type   service:        Service
        :param  handles_only:   Remove only handles if set to ``True``
        :type   handles_only:   bool
        """
        if isinstance(service, (PrimaryService, SecondaryService)):
            service_obj = self.get_service_by_uuid(service.uuid)
        elif isinstance(service, UUID):
            service_obj = self.get_service_by_uuid(service)
        else:
            service_obj = None

        # Process service object
        if service_obj is not None:
            # Remove service and all its characteristics from the attribute DB
            for charac in service_obj.characteristics():
                # Remove characteristic handle
                if charac.handle in self.__attr_db:
                    del self.__attr_db[charac.handle]

                # Remove characteristic value handle
                if charac.value_handle in self.__attr_db:
                    del self.__attr_db[charac.value_handle]

                # Remove all the attached descriptors
                for desc in charac.descriptors():
                    if desc.handle in self.__attr_db:
                        del self.__attr_db[desc.handle]

            # Remove service object from attribute db
            del self.__attr_db[service_obj.handle]

            # Remove service from our list of services (if required)
            if not handles_only:
                self.__services.remove(service)
        else:
            # Not found, raise IndexError
            raise IndexError()


    def update_service(self, service: Service) -> bool:
        """Update service in profile.

        Keep service in place in the service list,
        but update all the services declared after this one.

        :param  service:    Service object to update.
        :type   service:    Service
        :return: ``True`` if service has been updated, ``False`` otherwise.
        :rtype: bool
        """
        try:
            service_index = self.__services.index(service)

            # Remove all handles used by this service
            self.remove_service(service, handles_only=True)

            # Register all the handles back into our attribute DB
            self.add_service(service, handles_only=True)

            # Update all other services
            handle = service.end_handle
            for remaining_service in self.__services[service_index+1:]:
                remaining_service.handle = handle + 1
                self.update_service(remaining_service)
                handle = remaining_service.end_handle
            self.__handle = handle
            return True
        except IndexError:
            return False

    def find_object_by_handle(self, handle: int) -> Attribute:
        """Find an object by its handle value

        :param  handle: Object handle
        :type   handle: int
        :return: Object if handle is valid, or raise an IndexError exception otherwise
        :rtype: Attribute
        :raises: IndexError
        """
        if handle in self.__attr_db:
            return self.__attr_db[handle]

        # Error.
        raise IndexError

    def find_objects_by_range(self, start: int, end: int) -> List[Attribute]:
        """Find attributes with handles belonging in the [start, end+1] interval.

        :param  start:  Start handle value
        :type   start:  int
        :param  end:    End handle value
        :type   end:    int
        :return:        List of objects with handles between start and end values
        :rtype: list
        :raises: IndexError
        """
        handles = []
        for handle in self.__attr_db:
            if start <= handle <= end:
                handles.append(handle)
        handles.sort()
        return [self.find_object_by_handle(handle) for handle in handles]


    def find_characteristic_by_value_handle(self, value_handle: int) -> Optional[Characteristic]:
        """Find characteristic object by its value handle.

        :param  value_handle:   Characteristic value handle
        :type   value_handle:   int
        :return: Corresponding characteristic object or ``None`` if not found.
        :rtype: Characteristic
        """
        try:
            char_value = self.find_object_by_handle(value_handle)
            if isinstance(char_value, CharacteristicValue) and hasattr(char_value, 'characteristic'):
                return char_value.characteristic

            # Not found.
            return None
        except InvalidHandleValueException:
            return None


    def find_characteristic_end_handle(self, handle: int) -> Optional[int]:
        """Find characteristic end handle based on its handle.

        :param  handle: Characteristic handle
        :type   handle: int
        :rtype: int
        :return: Characteristic value handle
        :raises: InvalidHandleValueException
        """
        try:
            # Find service owning the characteristic
            service = self.find_service_by_characteristic_handle(handle)

            # Build a list of characteristic handles
            service_char_handles=[]
            for characteristic in service.characteristics():
                service_char_handles.append(characteristic.handle)

            # Sort handles
            service_char_handles.sort()
            idx = service_char_handles.index(handle)
            if idx == len(service_char_handles) - 1:
                return service.end_handle

            return service_char_handles[idx+1] - 1

        except InvalidHandleValueException:
            return None


    def find_service_by_characteristic_handle(self, handle: int) -> Service:
        """Find a service object given a characteristic handle that belongs
        to this service.

        :param  handle: Characteristic handle belonging to the searched service
        :type   handle: int
        :rtype: Service
        :return: Service object containing the specified characteristic

        :raises: InvalidHandleValueException
        """
        try:
            if handle in self.__service_by_characteristic_handle:
                return self.__service_by_characteristic_handle[handle]

            # Invalid handle
            raise InvalidHandleValueException
        except IndexError as err:
            raise InvalidHandleValueException from err


    def services(self) -> Iterator[Service]:
        """Enumerate service objects.

        This method is a generator and will yield service objects registered
        into the profile.
        """
        for _, obj in self.__attr_db.items():
            if isinstance(obj, Service):
                yield obj

    def included_services(self) -> Iterator[IncludeService]:
        """Enumerate included services.
        """
        for _, obj in self.__attr_db.items():
            if isinstance(obj, IncludeService):
                yield obj

    def service(self, uuid: Union[str, UUID]) -> Optional[Service]:
        """Retrieve a Service object given its UUID.

        :param uuid:    Service UUID
        :type  uuid:    UUID, str
        :return:        Corresponding Service object if found, ``None`` otherwise.
        :rtype:         Service
        :raise:         InvalidUUIDException
        """
        # If a string is provided as UUID, convert it to the corresponding
        # UUID object. This could raise an InvalidUUIDException.
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        # Search for a service matching the given UUID
        for _, obj in self.__attr_db.items():
            if isinstance(obj, (PrimaryService, SecondaryService)):
                if obj.uuid == uuid:
                    return obj

        # Not found
        return None

    def get_service_by_uuid(self, uuid: Union[str, UUID]) -> Optional[Service]:
        """Retrieve a Service object given its UUID.

        :param uuid:    Service UUID
        :type  uuid:    UUID
        :type  uuid:    str
        :return:        Corresponding Service object if found, `None` otherwise.
        :rtype:         Service, optional
        :raises InvalidUUIDException: Specified UUID is invalid

        .. deprecated:: 1.3.0
            Use the :py:meth:`~whad.ble.profile.service` method to find a service
            based on its UUID (simpler syntax).
        """
        return self.service(uuid)

    def char(self, uuid: Union[str, UUID]) -> Optional[Characteristic]:
        """Get characteristic by its UUID.

        :param      uuid:   Characteristic UUID to look for
        :type       uuid:   :class:`whad.ble.profile.attribute.UUID`
        :type       uuid:   str
        :return:            Characteristic if found, ``None`` otherwise
        :rtype:             :class:`whad.ble.profile.characteristic.Characteristic`, optional
        """
        # If a string is provided as UUID, convert it to the corresponding
        # UUID object. This could raise an InvalidUUIDException.
        if isinstance(uuid, str):
            uuid = UUID(uuid)

        # Search for a characteristic with the given UUID
        for _, obj in self.__attr_db.items():
            if isinstance(obj, Characteristic):
                if obj.uuid == uuid:
                    return obj

        # Not found
        return None

    def get_characteristic_by_uuid(self, uuid: Union[str, UUID]):
        """Get characteristic by its UUID.

        :param      uuid:   Characteristic UUID to look for
        :type       uuid:   :class:`whad.ble.profile.attribute.UUID`
        :type       uuid:   str
        :return:            Characteristic if found, ``None`` otherwise
        :rtype:             :class:`whad.ble.profile.characteristic.Characteristic`
        :raises InvalidUUIDException: Specified UUID is invalid
        """
        return self.char(uuid)

    def attr_by_type_uuid(self, uuid, start: int = 1, end: int = 0xFFFF) -> Iterator[Attribute]:
        """Enumerate attributes that have a specific type UUID.

        :param  uuid:   Type UUID
        :type   uuid:   UUID
        :param  start:  Start handle
        :type   start:  int
        :param  end:    End handle
        :type   end:    int
        """
        for _, obj in self.__attr_db.items():
            if obj.type_uuid == uuid and start <= obj.handle <= end:
                yield obj

    def export_json(self) -> str:
        """Export profile as JSON data, including services, characteristics and descriptors
        definition.

        :return:    JSON data corresponding to this profile
        :rtype:     str
        """
        profile_dict = {}
        profile_dict['services'] = []
        for service in self.services():
            service_dict = {
                'uuid': str(service.uuid),
                'type_uuid': str(service.type_uuid),
                'start_handle': service.handle,
                'end_handle': service.end_handle
            }
            service_dict['characteristics'] = []
            for charac in service.characteristics():
                charac_dict = {
                    'handle': charac.handle,
                    'uuid': str(charac.type_uuid),
                    'properties': charac.properties,
                    'security': SecurityAccess.accesses_to_int(charac.security),
                    'value': {
                        'handle': charac.value_handle,
                        'uuid': str(charac.uuid),
                        'data': Attribute.value.fget(charac.value_attr).hex()
                    }
                }
                charac_dict['descriptors'] = []
                for desc in charac.descriptors():
                    desc_dict = {
                        'handle': desc.handle,
                        'uuid': str(desc.type_uuid),
                        'value': Attribute.value.fget(desc).hex()
                    }
                    charac_dict['descriptors'].append(desc_dict)
                service_dict['characteristics'].append(charac_dict)
            profile_dict['services'].append(service_dict)
        return json.dumps(profile_dict)


    def find_hook(self, service: Service, characteristic: Characteristic,
                  operation: str) -> Optional[Callable[..., Any]]:
        """Find a registered hook for a specific service, characteristic and operation.

        :param  service:        Service object
        :type   service:        Service
        :param  characteristic: Characteristic object
        :type   characteristic: Characteristic
        :param  operation:      GATT operation
        :type   operation:      str

        :return: Hook callback
        :rtype: callable
        """
        hook_key = str(service.uuid) + ':' + str(characteristic.uuid)
        if hook_key in self.__hooks:
            if operation in self.__hooks[hook_key]:
                return self.__hooks[hook_key][operation]
        return None


    ################################################
    # Connection/disconnection hooks
    ################################################

    def on_connect(self, conn_handle: int):
        """Connection hook.

        This hook is only used to notify the connection of a device.

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        logger.debug("[profile] Connection established with handle %d",
                     conn_handle)

    def on_disconnect(self, conn_handle: int):
        """Disconnection hook.

        This hook is only used to notify the disconnection of a device.

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        logger.debug("[profile] Connection terminated for handle %d",
                     conn_handle)


    ################################################
    # Characteristic Read/Write/Subscribe hooks
    ################################################

    def on_characteristic_read(self, service: Service, characteristic: Characteristic,
                               offset: int = 0, length: int = 0):
        """Characteristic read hook.

        This hook is called whenever a characteristic is about to be read by a GATT client.
        If this method returns a byte array, this byte array will be sent back to the
        GATT client. If this method returns None, then the read operation will return an
        error (not allowed to read characteristic value).


        :param  service:        Service owning the characteristic
        :type   service:        Service
        :param  characteristic: Characteristic object
        :type   characteristic: Characteristic
        :param  offset:         Read offset (default: 0)
        :type   offset:         int
        :param  length:         Max read length
        :type   length:         int

        :return:    Value to return to the GATT client
        :rtype:     bytes
        """
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'read')
        if hook is not None:
            return hook(offset, length)

        # If no hook registered, then return the characteristic value
        return characteristic.value[offset:offset + length]

    def on_characteristic_write(self, service: Service, characteristic: Characteristic,
                                offset: int = 0, value: bytes = b'',
                                without_response: bool = False):
        """Characteristic write hook

        This hook is called whenever a charactertistic is about to be written by a GATT
        client.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        :param  offset:             Read offset (default: 0)
        :type   offset:             int
        :param  value:              Value about to be written into the characteristic
        :type   value:              bytes
        :param  without_response:   Set to ``True`` if no response is required
        :type   without_response:   bool
        """
        hook = self.find_hook(service, characteristic, 'write')
        if hook is not None:
            return hook(
                offset,
                value,
                without_response=without_response
            )

        # No action
        return None

    def on_characteristic_written(self, service: Service, characteristic: Characteristic,
                                  offset: int = 0, value: bytes = b'',
                                  without_response: bool = False):
        """Characteristic written hook

        This hook is called whenever a charactertistic has been written by a GATT
        client.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        :param  offset:             Read offset (default: 0)
        :type   offset:             int
        :param  value:              Value about to be written into the characteristic
        :type   value:              bytes
        :param  without_response:   Set to ``True`` if no response is required
        :type   without_response:   bool
        """
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'written')
        if hook is not None:
            # Call our hook
            return hook(
                offset,
                value,
                without_response=without_response
            )

        # No action
        return None

    def on_characteristic_subscribed(self, service: Service, characteristic: Characteristic,
                                     notification: bool = False, indication: bool = False):
        """Characteristic subscribed hook

        This hook is called whenever a characteristic has been subscribed to.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        :param  notification:       Set to ``True`` if subscribed to notification
        :type   notification:       bool
        :param  indication:         Set to ``True`` if subscribed to notification
        :type   indication:         bool
        """
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'sub')
        if hook is not None:
            # Call our hook
            return hook(
                notification=notification,
                indication=indication
            )

        # No action
        return None

    def on_characteristic_unsubscribed(self, service: Service, characteristic: Characteristic):
        """Characteristic unsubscribed hook

        This hook is called whenever a characteristic has been unsubscribed.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        """
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'unsub')
        if hook is not None:
            # Call our hook
            return hook()

        # No action
        return None

    def on_notification(self, service: Service, characteristic: Characteristic, value: bytes):
        """Characteristic notification hook.

        This hook is called when a notification is sent to a characteristic.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        :param  value:              Characteristic value
        :type   value:              bytes
        """
        logger.debug("[profile] GATT notification sent for characteristic %s of service %s with value %s",
                     characteristic.uuid, service.uuid,value)

    def on_indication(self, service: Service, characteristic: Characteristic, value: bytes):
        """Characteristic indication hook.

        This hook is called when a indication is sent to a characteristic.

        :param  service:            Service owning the characteristic
        :type   service:            Service
        :param  characteristic:     Characteristic object
        :type   characteristic:     Characteristic
        :param  value:              Characteristic value
        :type   value:              bytes
        """
        logger.debug("[profile] GATT indication sent for characteristic %s of service %s with value %s",
                     characteristic.uuid, service.uuid,value)

    def on_mtu_changed(self, mtu: int):
        """MTU change callback

        :param  mtu: New MTU value
        :type   mtu: int
        """
        logger.debug("[profile] GATT MTU updated to %d", mtu)

class GenericProfile(Profile):
    """Old name of the `Profile` class, kept for backward compatibility.

    .. versionchanged:: 1.3.0
        :class:`~whad.ble.profile.GenericProfile` has been renamed to :class:`~whad.ble.profile.Profile` to simplify
        code and due to a change in the way standard services are now declared within a GATT profile class.

        In previous versions, including a *Battery Service* into a custom profile required to inherit from both
        :class:`~whad.ble.profile.GenericProfile` and :class:`~whad.ble.profile.services.BatteryService`. A
        *generic profile* was then considered as an empty GATT profile that could be used to create default profiles,
        an idea now put aside because it does not fit in our vision of GATT profiles anymore.
    """

__all__ = [
    # Hooks
    "read",
    "write",
    "written",
    "subscribed",
    "unsubscribed",

    # Classes
    "Characteristic",
    "CharacteristicValue",
    "Descriptor",
    "Service",
    "PrimaryService",
    "SecondaryService",
    "ReportReference",
    "UserDescription",
    "ClientCharacteristicConfig",
    "Profile",

    # Old classes (to be removed later)
    "CharacteristicDescriptor",
    "CharacteristicUserDescriptionDescriptor",
    "ReportReferenceDescriptor",
    "GenericProfile",
]
