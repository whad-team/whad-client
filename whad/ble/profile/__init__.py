"""This module provides different classes that represent a BLE device and
allows to interact with it:

* :class:`whad.ble.profile.GenericProfile` is a base class used to register all the ATT attributes, including
  services, characteristics, characteristic values and descriptors. It is able to
  inspect any derived class and build the corresponding profile based on properties
  declared with :class:`whad.ble.profile.service.PrimaryService` and
  :class:`whad.ble.profile.characteristic.Characteristic`.

"""
import json
from typing import List, Iterator
from whad.ble.stack.smp import Pairing
from whad.ble.profile.attribute import Attribute, UUID
from whad.ble.profile.characteristic import Characteristic as BleCharacteristic,\
    CharacteristicProperties, ClientCharacteristicConfig, \
    CharacteristicValue as BleCharacteristicValue, \
    CharacteristicDescriptor as BleCharacteristicDescriptor, \
    ReportReferenceDescriptor as BleReportReferenceDescriptor, \
    CharacteristicUserDescriptionDescriptor as BleCharacteristicUserDescriptionDescriptor

from whad.ble.profile.service import PrimaryService as BlePrimaryService, \
    SecondaryService as BleSecondaryService, IncludeService as BleIncludeService, \
    Service
from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.stack.att.constants import BleAttProperties, SecurityProperty, \
    SecurityAccess, ReadAccess, WriteAccess, Authentication, Authorization, Encryption

import logging
logger = logging.getLogger(__name__)

###################################
# Decorators for GenericProfile
###################################

class CharacteristicHook(object):

    def __init__(self, *args):
        if len(args) == 1:
            characteristic = args[0]
            if isinstance(characteristic, Characteristic):
                self.__characteristic = str(characteristic.service.uuid)+':'+str(characteristic.uuid)
            else:
                raise TypeError
        elif len(args) == 2:
            service = args[0]
            charac = args[1]
            if isinstance(service, str) and isinstance(charac, str):
                self.__characteristic = str(UUID(service)) + ':' + str(UUID(charac))
            elif isinstance(service, UUID) and isinstance(charac, UUID):
                self.__characteristic = str(service) + ':' + str(charac)

    def __call__(self, method):
        if not hasattr(method, 'hooks'):
            method.hooks = []
        if not hasattr(method, 'characteristic'):
            method.characteristic = self.__characteristic
        return method

class read(CharacteristicHook):
    """Read hook decorator

    This decorator is used to declare a callback method for read operations
    on a specific characteristic.
    """

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if 'read' not in method.hooks:
            method.hooks.append('read')
        return method

class write(CharacteristicHook):

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if 'write' not in method.hooks:
            method.hooks.append('write')
        return method

class written(CharacteristicHook):

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if 'written' not in method.hooks:
            method.hooks.append('written')
        return method

class subscribed(CharacteristicHook):

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if 'sub' not in method.hooks:
            method.hooks.append('sub')
        return method

class unsubscribed(CharacteristicHook):

    def __call__(self, method):
        """Add a specific hook to the method
        """
        super().__call__(method)
        if 'unsub' not in method.hooks:
            method.hooks.append('unsub')
        return method

def is_method_hook(method):
    """Determine if a method is a characteristic operation hook
    """
    if hasattr(method, 'hooks') and hasattr(method, 'characteristic'):
        return (len(method.hooks) > 0)
    return False

################################
# Descriptors model
#
# This section contains all the descriptor models to use while creating
# a profile from Python code. It contains a set of alternative classes
# used by GenericProfile to build the attribute database and populate an
# instance with the corresponding properties and objects.
################################

class CharacteristicDescriptor(object):
    """Generic CharacteristicDescriptor model
    """
    def __init__(self, bleclass=None):
        """Instanciate a characteristic descriptor model

        :param str name: attribute name to access this descriptor
        :param class bleclass: BLE descriptor class to use when instanciating the model
        :param list permissions: descriptor permissions (read/write/notify/indicate)
        """
        self.__handle = 0
        self.__class = bleclass

    @property
    def handle(self):
        return self.__handle

    @handle.setter
    def handle(self, value):
        self.__handle = value

    @property
    def bleclass(self):
        return self.__class


class ReportReferenceDescriptor(CharacteristicDescriptor):
    """Report Reference Descriptor model
    """
    def __init__(self, permissions=None):
        super().__init__(BleReportReferenceDescriptor)

class UserDescriptionDescriptor(CharacteristicDescriptor):
    """User description model
    """
    def __init__(self, description=''):
        super().__init__(BleCharacteristicUserDescriptionDescriptor)


class Characteristic(object):
    """GATT characteristic.
    """
    def __init__(self, name=None, uuid=None, value=b'', permissions=None, notify=False, indicate=False, description=None, security = [], **kwargs):
        """Declares a GATT characteristic.

        Other named arguments are used to declare characteristic's descriptors.

        :param  name:           Characteristic name used in GATT model
        :type   name:           str
        :param  uuid:           Characteristic UUID
        :type   uuid:           :class:`whad.ble.profile.attribute.UUID`
        :param  permissions:    List of permissions for this characteristic (*read*, *write*, *notify*, *indicate*)
        :type   permissions:    list
        :param  notify:         Enable notifications
        :type   notify:         bool
        :param  indicate:       Enable indications
        :type   indicate:       bool
        :param  description:    Textual description for this characteristic
        :type   description:    str
        :param security:        Indicate the security property associated to this characteristic
        :type security:         SecurityAccess
        """
        self.__handle = 0
        self.__name = name
        self.__uuid = uuid
        self.__value = value
        self.__perms = permissions
        self.__notify = notify
        self.__indicate = indicate
        self.__security = SecurityAccess.generate(security)
        self.__service = None
        self.__description = description
        self.__descriptors = []

        # Loop on kwargs to find descriptors
        for arg in kwargs:
            if isinstance(kwargs[arg], CharacteristicDescriptor):
                descriptor = kwargs[arg]
                descriptor.handle = 0
                descriptor.name = arg
                self.add_descriptor(descriptor)

                # Add descriptor to a property to this ServiceModel instance
                if not hasattr(self, arg):
                    setattr(self, arg, descriptor)

    def add_descriptor(self, descriptor):
        """Add descriptor to our descriptor list

        :param  descriptor: Descriptor to add to the characteristic's descriptor list
        :type   descriptor: :class:`whad.ble.profile.characteristic.CharacteristicDescriptor`
        """
        self.__descriptors.append(descriptor)

    def descriptors(self) -> Iterator[CharacteristicDescriptor]:
        """Enumerate descriptors attached to this characteristic

        This method will yield every descriptor attached to the characteristic.
        """
        for descriptor in self.__descriptors:
            yield descriptor

    def get_required_handles(self) -> int:
        """Compute the number of handles this characteristic will consume

        :return: Number of handles
        :rtype: int
        """
        handles = 2
        # A more handle as we may need a ClientCharacteristicConfiguration descriptor
        if self.__notify or self.__indicate:
            handles += 1
        return handles

    def attach(self, service):
        """Attach this characteristic to the corresponding service.

        :param  service:    Service
        :type   service:    :class:̀ whad.ble.profile.service.Service`
        """
        self.__service = service

    @property
    def handle(self) -> int:
        """Characteristic handle
        """
        return self.__handle

    @handle.setter
    def handle(self, value):
        """Set characteristic handle.

        :param  value:  New handle value
        :type   value:  int
        """
        self.__handle = value

    @property
    def end_handle(self) -> int:
        """Characteristic end handle (including characteristic value and descriptors).
        """
        return self.handle + self.get_required_handles()

    @property
    def name(self) -> str:
        """Name
        """
        return self.__name

    @name.setter
    def name(self, value):
        """Set characteristic name.

        :param  value:  New name
        :type   value:  str
        """
        self.__name = value

    @property
    def uuid(self):
        return self.__uuid

    @property
    def value(self) -> UUID:
        """Characteristic UUID
        """
        return self.__value

    @property
    def permissions(self) -> List[str]:
        """Characteristics permissions
        """
        return self.__perms

    @property
    def must_notify(self) -> bool:
        """Check if notification has to be sent on value change.
        """
        return self.__notify

    @property
    def must_indicate(self) -> bool:
        """Check if indication has to be sent on value change.
        """
        return self.__indicate

    @property
    def description(self) -> str:
        """Return characteristic textual description, if any
        """
        return self.__description

    @property
    def service(self) -> Service:
        """Related service.
        """
        return self.__service

    @property
    def security(self) -> SecurityAccess:
        """Returns security access property
        """
        return self.__security

class ServiceModel(object):

    PRIMARY = 1
    SECONDARY = 2

    def __init__(self, uuid=None, start_handle=None, end_handle=None, name=None, service_type=PRIMARY, **kwargs):
        self.__handle = 0
        self.__end_handle = 0
        self.__uuid = uuid
        self.__name = name
        self.__characteristics = []
        self.__included_services = []

        if start_handle is None:
            self.__handle = 0
        else:
            self.__handle = start_handle

        if end_handle is None:
            self.__end_handle = 0
        else:
            self.__end_handle = end_handle

        # Loop on kwargs to find characteristics and included services
        for arg in kwargs:
            if isinstance(kwargs[arg], Characteristic):
                charac = kwargs[arg]
                charac.handle = 0
                charac.name = arg
                self.add_characteristic(charac)
                charac.attach(self)

                # Add characteristic to a property to this ServiceModel instance
                if not hasattr(self, arg):
                    setattr(self, arg, charac)
            elif isinstance(kwargs[arg], SecondaryService):
                # We must include this secondary service in this service
                service = kwargs[arg]
                self.add_included_service(service)

                # Add included service to a property to this ServiceModel instance
                if not hasattr(self, arg):
                    setattr(self, arg, service)


    def add_characteristic(self, characteristic_model):
        """Add a characteristic to the model
        """
        # Add characteristic to the list of our characteristics
        self.__characteristics.append(characteristic_model)

        # Update end handle value (include definition is a single attribute)
        if characteristic_model.handle >= self.__end_handle:
            self.__end_handle = characteristic_model.handle

    def add_included_service(self, service_model):
        """Add an included service to the model
        """
        self.__included_services.append(service_model)

        # Update end handle value
        if service_model.end >= self.__end_handle:
            self.__end_handle = service_model.end

    @property
    def uuid(self):
        return self.__uuid

    @property
    def handle(self):
        return self.__handle

    @property
    def end(self):
        return self.__end_handle

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @handle.setter
    def handle(self, value):
        self.__handle = value

    def characteristics(self):
        for charac in self.__characteristics:
            yield charac

    def included_services(self):
        for inc_service in self.__included_services:
            yield inc_service

class PrimaryService(ServiceModel):
    def __init__(self, uuid=None, start_handle=0, end_handle=0, name=None, **kwargs):
        """Declares a GATT primary service.

        Other named arguments are used to add service's characteristics.

        :param  uuid:           Primary service UUID
        :type   uuid:           :class:`whad.ble.profile.attribute.UUID`
        :param  start_handle:   Service start handle
        :type   start_handle:   int, optional
        :param  end_handle:     Service end handle
        :type   end_handle:     int, optional
        :param  name:           Service name
        :type   name:           str
        """
        super().__init__(uuid, start_handle, end_handle, service_type=ServiceModel.PRIMARY, name=name, **kwargs)


class SecondaryService(ServiceModel):
    def __init__(self, uuid=None, start_handle=0, end_handle=0, name=None, **kwargs):
        """Declares a GATT secondary service.

        Other named arguments are used to add service's characteristics.

        :param  uuid:           Primary service UUID
        :type   uuid:           :class:`whad.ble.profile.attribute.UUID`
        :param  start_handle:   Service start handle
        :type   start_handle:   int, optional
        :param  end_handle:     Service end handle
        :type   end_handle:     int, optional
        :param  name:           Service name
        :type   name:           str
        """
        super().__init__(uuid, start_handle, end_handle, service_type=ServiceModel.SECONDARY, name=name, **kwargs)


class GenericProfile(object):
    """Generic Profile
    """

    def __init__(self, start_handle=0, from_json=None):
        """Parse the device model, instanciate all the services, characteristics
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
            from_json = json.loads(from_json)
            # Parse JSON services, characteristics and descriptors to create
            # the corresponding model and attribute database
            if 'services' in from_json:
                # Loop on services
                for service in from_json['services']:
                    # Collect characteristics
                    service_characs = []
                    service_last_handle = service['start_handle']
                    if UUID(service['type_uuid']) == UUID(0x2800):
                        service_obj = BlePrimaryService(
                            uuid=UUID(service['uuid']),
                            handle=service['start_handle']
                        )
                    elif UUID(service['type_uuid']) == UUID(0x2801):
                        service_obj = BleSecondaryService(
                            uuid=UUID(service['uuid']),
                            handle=service['start_handle']
                        )
                    else:
                        # This is not a known service type UUID, continue with
                        # next service
                        continue

                    if 'characteristics' in service:
                        for charac in service['characteristics']:
                            charac_obj = BleCharacteristic(
                                uuid=UUID(charac['value']['uuid']),
                                handle=charac['handle'],
                                value=b'',
                                properties=charac['properties'],
                                security=SecurityAccess.int_to_accesses(charac['security'])
                            )

                            # Loop on descriptors, only support CCC at the moment
                            for desc in charac['descriptors']:
                                if UUID(desc['uuid']) == UUID(0x2902):
                                    desc_obj = ClientCharacteristicConfig(
                                        charac_obj,
                                        handle=desc['handle'],
                                        notify=charac_obj.must_notify(),
                                        indicate=charac_obj.must_indicate()
                                    )
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
                    if isinstance(getattr(self, prop), ServiceModel):
                        service = getattr(self, prop)
                        service.name = prop
                        services.append(service)


            # Instanciate each service, and for each of them the corresponding
            # characteristics
            for service in services:
                if isinstance(service, PrimaryService):
                    logger.info('creating primary service %s' % service.uuid)
                    # Create service
                    service_obj = BlePrimaryService(
                        uuid=service.uuid,
                        handle=self.__alloc_handle()
                    )

                elif isinstance(service, SecondaryService):
                    logger.info('creating secondary service %s' % service.uuid)
                    # Create service
                    service_obj = BleSecondaryService(
                        uuid=service.uuid,
                        handle=self.__alloc_handle()
                    )
                    self.__attr_db[service_obj.handle] = service_obj
                else:
                    continue

                # Create the corresponding instance property
                setattr(self, service.name, service_obj)

                # Loop on included services and create them if required
                for inc_service in service.included_services():
                    inc_service_obj = BleIncludeService(
                        uuid=inc_service.uuid,
                        handle=self.__alloc_handle(1),
                        start_handle=inc_service.handle,
                        end_handle=inc_service.end
                    )
                    self.__handle = inc_service_obj.end_handle

                    # Register this service include definition
                    self.register_attribute(inc_service_obj)
                    service_obj.add_include_service(inc_service_obj)

                # Loop on underlying characteristics, and create them too.
                for charac in service.characteristics():
                    charac_props = 0
                    if 'read' in charac.permissions:
                        charac_props |= CharacteristicProperties.READ
                    if 'write' in charac.permissions:
                        charac_props |= CharacteristicProperties.WRITE
                    if 'write_without_response' in charac.permissions:
                        charac_props |= CharacteristicProperties.WRITE_WITHOUT_RESPONSE
                    if charac.must_notify:
                        charac_props |= CharacteristicProperties.NOTIFY
                    if charac.must_indicate:
                        charac_props |= CharacteristicProperties.INDICATE
                    charac_obj = BleCharacteristic(
                        uuid=charac.uuid,
                        handle=self.__alloc_handle(1),
                        value=charac.value,
                        properties=charac_props,
                        security=charac.security
                    )
                    logger.info(' creating characteristic %s (handle:%d)' % (
                        charac_obj.uuid, charac_obj.handle
                    ))
                    self.__handle = charac_obj.end_handle

                    # Register this characteristic
                    self.register_attribute(charac_obj)
                    self.register_attribute(charac_obj.value_attr)

                    # If notify or indicate is set to true, we must add a new CCC descriptor
                    if charac.must_notify or charac.must_indicate:
                        ccc_desc = ClientCharacteristicConfig(
                            charac_obj,
                            handle=self.__alloc_handle(),
                            notify=charac.must_notify,
                            indicate=charac.must_indicate
                        )
                        logger.info('  creating cccd (handle:%d)' % (
                            ccc_desc.handle
                        ))
                        charac_obj.add_descriptor(ccc_desc)
                        self.register_attribute(ccc_desc)

                    # If characteristic description has been set, add a descriptor
                    if charac.description is not None:
                        cudd_desc = BleCharacteristicUserDescriptionDescriptor(
                            charac_obj,
                            handle=self.__alloc_handle(),
                            description=charac.description
                        )
                        logger.info('  creating cudd (handle:%d) with text "%s"' % (
                            cudd_desc.handle,
                            charac.description
                        ))
                        charac_obj.add_descriptor(cudd_desc)
                        self.register_attribute(cudd_desc)


                    # Loop on other characteristic descriptors and add them
                    for descriptor in charac.descriptors():
                        desc = descriptor.bleclass(
                            charac_obj,
                            handle=self.__alloc_handle()
                        )
                        logger.info('  creating %s descriptor (handle:%d)' % (
                            type(desc),
                            desc.handle
                        ))
                        charac_obj.add_descriptor(desc)
                        self.register_attribute(desc)

                    # Add our characteristic object to the corresponding service
                    setattr(service_obj, charac.name, charac_obj)
                    service_obj.add_characteristic(charac_obj)

                self.add_service(service_obj)

            # We then need to update included service start and end handles
            for inc_service in self.included_services():
                # Retrieve the included service UUID
                service_uuid = inc_service.service_uuid
                
                # Retrieve the corresponding object by UUID
                service_obj = self.get_service_by_UUID(service_uuid)

                # If found, update start and end handles
                if service_obj is not None:
                    inc_service.service_start_handle = service_obj.handle
                    inc_service.service_end_handle = service_obj.end_handle

        # Register any hook function
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


    def __alloc_handle(self, number=1):
        """Allocate one or more handle values.

        :param  number: Number of handle values to allocate
        :type   number: int

        :return: Current handle value
        :rtype: int
        """
        self.__handle += number
        return self.__handle

    def __repr__(self):
        output = ''
        for service in self.services():
            output += 'Service %s (handles from %d to %d):\n' % (
                service.uuid,
                service.handle,
                service.end_handle
            )

            for inc_service in service.included_services():
                output += '  Included service %s (handle:%d, start_handle:%d, end_handle:%d)\n' % (inc_service.service_uuid, inc_service.handle, inc_service.service_start_handle, inc_service.service_end_handle)
            for charac in service.characteristics():
                properties = charac.properties
                charac_rights = ''
                if properties & CharacteristicProperties.READ != 0:
                    charac_rights += 'R'
                if properties & CharacteristicProperties.WRITE != 0:
                    charac_rights += 'W'
                if properties & CharacteristicProperties.INDICATE != 0:
                    charac_rights += 'I'
                if properties & CharacteristicProperties.NOTIFY != 0:
                    charac_rights += 'N'

                output += '  Characteristic %s (handle:%d, value handle: %d, props: %s)\n' % (
                    charac.uuid,
                    charac.handle,
                    charac.value_handle,
                    charac_rights
                )
                for desc in charac.descriptors():
                    output += '    Descriptor %s (handle: %d)\n' % (
                        desc.type_uuid,
                        desc.handle
                    )
        return output

    def register_attribute(self, attribute):
        """Register a GATT attribute

        :param  attribute:  Attribute to register
        :type   attribute:  :class:`whad.ble.profile.attribute.Attribute`
        """
        if isinstance(attribute, Attribute):
            self.__attr_db[attribute.handle] = attribute


    def add_service(self, service, handles_only=False):
        """Add a service to the current device

        :param  service:        Service to add to the device
        :type   service:        :class:`whad.ble.profile.service.Service`
        :param  handles_only:   Add only service handles if set to ``True``
        :type   handles_only:   bool
        """
        logger.debug('add service %s' % service.uuid)
        if service.handle == 0:
            # Service has not been fully configured, update its handle
            # and the handles of its characteristics and descriptors.
            service.handle = self.__alloc_handle()

        # Append service to the list of our services
        if not handles_only:
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
        self.__handle = service.end_handle


    def remove_service(self, service, handles_only=False):
        """Remove service

        :param  service:        Service object or UUID
        :type   service:        :class:`whad.ble.profile.service.Service`
        :param  handles_only:   Remove only handles if set to ``True``
        :type   handles_only:   bool
        """
        if isinstance(service, BlePrimaryService) or isinstance(service, BleSecondaryService):
            service_obj = self.get_service_by_UUID(service.uuid)
        elif isinstance(service, UUID):
            service_obj = self.get_service_by_UUID(service)
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


    def update_service(self, service) -> bool:
        """Update service in profile.

        Keep service in place in the service list,
        but update all the services declared after this one.

        :param  service:    Service object to update.
        :type   service:    :class:`whad.ble.profile.service.Service`
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
        except IndexError as notfound:
            return False

    def find_object_by_handle(self, handle) -> Attribute:
        """Find an object by its handle value

        :param  handle: Object handle
        :type   handle: int
        :return: Object if handle is valid, or raise an IndexError exception otherwise
        :rtype: :class:`whad.ble.profile.attribute.Attribute`
        :raises: IndexError
        """
        if handle in self.__attr_db:
            return self.__attr_db[handle]
        else:
            raise IndexError

    def find_objects_by_range(self, start, end) -> List[Attribute]:
        """Find attributes with handles belonging in the [start, end+1] interval.

        :param  start:  Start handle value
        :type   start:  int
        :param  end:    End handle value
        :type   end:    int
        :return:        List of objects with handles between start and end values
        :rtype: list
        """
        handles = []
        for handle in self.__attr_db:
            if handle>=start and handle<=end:
                handles.append(handle)
        handles.sort()
        return [self.find_object_by_handle(handle) for handle in handles]


    def find_characteristic_by_value_handle(self, value_handle) -> BleCharacteristic:
        """Find characteristic object by its value handle.

        :param  value_handle:   Characteristic value handle
        :type   value_handle:   int
        :return: Corresponding characteristic object or ``None`` if not found.
        :rtype: :class:`whad.ble.profile.characteristic.Characteristic`
        """
        try:
            char_value = self.find_object_by_handle(value_handle)
            if char_value is not None and hasattr(char_value, 'characteristic'):
                return char_value.characteristic
            else:
                return None
        except InvalidHandleValueException as bad_handle:
            return None


    def find_characteristic_end_handle(self, handle) -> int:
        """Find characteristic end handle based on its handle.

        :param  handle: Characteristic handle
        :type   handle: int
        :rtype: int
        :return: Characteristic value handle
        :raises: :class:`whad.ble.exceptions.InvalidHandleValueException`
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
            else:
                return (service_char_handles[idx+1] - 1)

        except InvalidHandleValueException:
            return None


    def find_service_by_characteristic_handle(self, handle) -> Service:
        """Find a service object given a characteristic handle that belongs
        to this service.

        :param  handle: Characteristic handle belonging to the searched service
        :type   handle: int
        :rtype: :class:`whad.ble.profile.service.Service`
        :return: Service object containing the specified characteristic

        :raises: :class:`whad.ble.exceptions.InvalidHandleValueException`
        """
        try:
            if handle in self.__service_by_characteristic_handle:
                return self.__service_by_characteristic_handle[handle]
            else:
                raise InvalidHandleValueException
        except IndexError:
            raise InvalidHandleValueException


    def services(self) -> Iterator[Service]:
        """Enumerate service objects.

        This method is a generator and will yield service objects registered
        into the profile.
        """
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if isinstance(object, BlePrimaryService) or isinstance(object, BleSecondaryService):
                yield object

    def included_services(self) -> Iterator[BleIncludeService]:
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if isinstance(object, BleIncludeService):
                yield object

    def get_service_by_UUID(self, service_uuid: UUID):
        """Get a service by its UUID.

        :param      service_uuid:   Service UUID to look for
        :type       service_uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:    Service if found, ``None`` otherwise
        :rtype:     :class:`whad.ble.profile.service.Service`
        """
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if isinstance(object, BlePrimaryService) or isinstance(object, BleSecondaryService):
                if object.uuid == service_uuid:
                    return object

        # Not found
        return None

    def get_characteristic_by_UUID(self, charac_uuid: UUID):
        """Get characteristic by its UUID.

        :param      charac_uuid:   Characteristic UUID to look for
        :type       charac_uuid:   :class:`whad.ble.profile.attribute.UUID`
        :return:    Characteristic if found, ``None`` otherwise
        :rtype:     :class:`whad.ble.profile.characteristic.Characteristic`
        """
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if isinstance(object, BleCharacteristic):
                if object.uuid == charac_uuid:
                    return object


    def attr_by_type_uuid(self, uuid, start=1, end=0xFFFF) -> Iterator[Attribute]:
        """Enumerate attributes that have a specific type UUID.

        :param  uuid:   Type UUID
        :type   uuid:   :class:`whad.ble.profile.attribute.UUID`
        :param  start:  Start handle
        :type   start:  int
        :param  end:    End handle
        :type   end:    int
        """
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if object.type_uuid == uuid and object.handle >= start and object.handle <= end:
                yield object

    def export_json(self):
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
                    }
                }
                charac_dict['descriptors'] = []
                for desc in charac.descriptors():
                    desc_dict = {
                        'handle': desc.handle,
                        'uuid': str(desc.type_uuid)
                    }
                    charac_dict['descriptors'].append(desc_dict)
                service_dict['characteristics'].append(charac_dict)
            profile_dict['services'].append(service_dict)
        return json.dumps(profile_dict)


    def find_hook(self, service, characteristic, operation) -> callable:
        """Find a registered hook for a specific service, characteristic and operation.

        :param  service:        Service object
        :type   service:        :class:`whad.ble.profile.service.Service`
        :param  characteristic: Characteristic object
        :type   characteristic: :class:`whad.ble.profile.characteristic.Characteristic`
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

    def on_connect(self, conn_handle):
        """Connection hook.

        This hook is only used to notify the connection of a device.

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        pass

    def on_disconnect(self, conn_handle):
        """Disconnection hook.

        This hook is only used to notify the disconnection of a device.

        :param  conn_handle:    Connection handle
        :type   conn_handle:    int
        """
        pass


    ################################################
    # Characteristic Read/Write/Subscribe hooks
    ################################################

    def on_characteristic_read(self, service, characteristic, offset=0, length=0):
        """Characteristic read hook.

        This hook is called whenever a characteristic is about to be read by a GATT client.
        If this method returns a byte array, this byte array will be sent back to the
        GATT client. If this method returns None, then the read operation will return an
        error (not allowed to read characteristic value).


        :param  service:        Service owning the characteristic
        :type   service:        :class:`whad.ble.profile.service.Service`
        :param  characteristic: Characteristic object
        :type   characteristic: :class:`whad.ble.profile.characteristic.Characteristic`
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

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
        """Characteristic write hook

        This hook is called whenever a charactertistic is about to be written by a GATT
        client.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
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

    def on_characteristic_written(self, service, characteristic, offset=0, value=b'', without_response=False):
        """Characteristic written hook

        This hook is called whenever a charactertistic has been written by a GATT
        client.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
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

    def on_characteristic_subscribed(self, service, characteristic, notification=False, indication=False):
        """Characteristic subscribed hook

        This hook is called whenever a characteristic has been subscribed to.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
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

    def on_characteristic_unsubscribed(self, service, characteristic):
        """Characteristic unsubscribed hook

        This hook is called whenever a characteristic has been unsubscribed.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
        """
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'unsub')
        if hook is not None:
            # Call our hook
            return hook()

    def on_notification(self, service, characteristic, value):
        """Characteristic notification hook.

        This hook is called when a notification is sent to a characteristic.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
        :param  value:              Characteristic value
        :type   value:              bytes
        """
        pass

    def on_indication(self, service, characteristic, value):
        """Characteristic indication hook.

        This hook is called when a indication is sent to a characteristic.

        :param  service:            Service owning the characteristic
        :type   service:            :class:`whad.ble.profile.service.Service`
        :param  characteristic:     Characteristic object
        :type   characteristic:     :class:`whad.ble.profile.characteristic.Characteristic`
        :param  value:              Characteristic value
        :type   value:              bytes
        """
        pass
