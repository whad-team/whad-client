"""Bluetooth Low Energy device model
"""
import json
from whad.ble.profile.attribute import Attribute, UUID
from whad.ble.profile.characteristic import Characteristic as BleCharacteristic,\
    CharacteristicProperties, ClientCharacteristicConfig
from whad.ble.profile.service import PrimaryService as BlePrimaryService, \
    SecondaryService as BleSecondaryService
from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.stack.att.constants import BleAttProperties

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


class Characteristic(object):
    """Characteristic model
    """

    def __init__(self, name=None, uuid=None, value=b'', permissions=None, notify=False, indicate=False):
        self.__handle = 0
        self.__name = name
        self.__uuid = uuid
        self.__value = value
        self.__perms = permissions
        self.__notify = notify
        self.__indicate = indicate
        self.__service = None

    def get_required_handles(self):
        """Compute the number of handles this characteristic will consume
        """    
        handles = 2
        # A more handle as we may need a ClientCharacteristicConfiguration descriptor
        if self.__notify or self.__indicate:
            handles += 1
        return handles

    def attach(self, service):
        """Attach this characteristic to the corresponding service
        """
        self.__service = service

    @property
    def handle(self):
        return self.__handle

    @handle.setter
    def handle(self, value):
        self.__handle = value

    @property
    def end_handle(self):
        return self.handle + self.get_required_handles()
    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    @property
    def uuid(self):
        return self.__uuid

    @property
    def value(self):
        return self.__value

    @property
    def permissions(self):
        return self.__perms

    @property
    def must_notify(self):
        return self.__notify

    @property
    def must_indicate(self):
        return self.__indicate

    @property
    def service(self):
        return self.__service


class ServiceModel(object):

    PRIMARY = 1
    SECONDARY = 2

    def __init__(self, uuid=None, start_handle=None, end_handle=None, name=None, service_type=PRIMARY, **kwargs):
        self.__handle = 0
        self.__end_handle = 0
        self.__uuid = uuid
        self.__name = name
        self.__characteristics = []

        if start_handle is None:
            self.__handle = 0
        else:
            self.__handle = start_handle

        if end_handle is None:
            self.__end_handle = 0
        else:
            self.__end_handle = end_handle

        # Loop on kwargs to find characteristics
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


    def add_characteristic(self, characteristic_model):
        """Add a characteristic to the model
        """
        # Add characteristic to the list of our characteristics
        self.__characteristics.append(characteristic_model)

        # Update end handle value
        if characteristic_model.end_handle >= self.__end_handle:
            self.__end_handle = characteristic_model.end_handle

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

class PrimaryService(ServiceModel):
    def __init__(self, uuid=None, start_handle=0, end_handle=0, name=None, **kwargs):
        super().__init__(uuid, start_handle, end_handle, service_type=ServiceModel.PRIMARY, name=name, **kwargs)


class SecondaryService(ServiceModel):
    def __init__(self, uuid=None, start_handle=0, end_handle=0, name=None, **kwargs):
        super().__init__(uuid, start_handle, end_handle, service_type=ServiceModel.SECONDARY, name=name, **kwargs)


class GenericProfile(object):

    def __init__(self, start_handle=0, from_json=None):
        """Parse the device model, instanciate all the services, characteristics
        and descriptors, compute all handle values and registers everything
        inside this instance for further use.

        :param int start_handle: Start handle value to use (default: 1)
        """
        self.__attr_db = {}
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
                                properties=charac['properties']
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
                    # Create service
                    service_obj = BlePrimaryService(
                        uuid=service.uuid,
                        handle=self.__alloc_handle()
                    )

                elif isinstance(service, SecondaryService):
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
                        properties=charac_props
                    )
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
                        charac_obj.add_descriptor(ccc_desc)
                        self.register_attribute(ccc_desc)

                    # Add our characteristic object to the corresponding service
                    setattr(service_obj, charac.name, charac_obj)
                    service_obj.add_characteristic(charac_obj)

                self.add_service(service_obj)

        # Register any hook function
        props = dir(self)
        for prop in props:
            prop_obj = getattr(self, prop)
            # Is this property a callable hook ?
            if callable(prop_obj) and is_method_hook(prop_obj):
                print('method %s is a hook for %s' % (prop, prop_obj.hooks))
                # Associate hook method with each operation
                if prop_obj.characteristic not in self.__hooks:
                    self.__hooks[prop_obj.characteristic] = {}
                for operation in prop_obj.hooks:
                    self.__hooks[prop_obj.characteristic][operation] = prop_obj


    def __alloc_handle(self, number=1):
        """Allocate one or more handle values.

        :param int number: Number of handle values to allocate
        :return: Current handle value
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

        :param Attribute attribute: Attribute to register
        """
        if isinstance(attribute, Attribute):
            self.__attr_db[attribute.handle] = attribute

    def add_service(self, service):
        """Add a service to the current device

        :param service: Service to add to the device
        """
        # Register service as an attribute
        self.register_attribute(service)

        # Register all its characteristics
        for charac in service.characteristics():
            self.register_attribute(charac)
            self.__service_by_characteristic_handle[charac.handle] = service
        

    def find_object_by_handle(self, handle):
        """Find an object by its handle value

        :param int handle: Object handle
        :return: Object if handle is valid, or raise an IndexError exception otherwise
        :raises: IndexError 
        """
        if handle in self.__attr_db:
            return self.__attr_db[handle]
        else:
            raise IndexError
    
    def find_objects_by_range(self, start, end):
        """Find attributes with handles belonging in the [start, end+1] interval.
        """
        handles = []
        for handle in self.__attr_db:
            if handle>=start and handle<=end:
                handles.append(handle)
        handles.sort()
        return [self.find_object_by_handle(handle) for handle in handles]

    
    def find_characteristic_end_handle(self, handle):
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

    def find_service_by_characteristic_handle(self, handle):
        """Find a service object given a characteristic handle

        :param int handle: Characteristic handle
        """
        try:
            charac = self.find_object_by_handle(handle)
            if charac.handle in self.__service_by_characteristic_handle:
                return self.__service_by_characteristic_handle[charac.handle]
            else:
                raise InvalidHandleValueException
        except IndexError:
            raise InvalidHandleValueException

    def services(self):
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if isinstance(object, BlePrimaryService) or isinstance(object, BleSecondaryService):
                yield object

    def attr_by_type_uuid(self, uuid, start=1, end=0xFFFF):
        for handle in self.__attr_db:
            object = self.__attr_db[handle]
            if object.type_uuid == uuid and object.handle >= start and object.handle <= end:
                yield object

    def export_json(self):
        """Export profile as JSON data, including services, characteristics and descriptors
        definition.

        :return string: JSON data corresponding to this profile
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

    def find_hook(self, service, characteristic, operation):
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
        """
        pass

    def on_disconnect(self, conn_handle):
        """Disconnection hook.

        This hook is only used to notify the disconnection of a device.
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
        

        :param BlePrimaryService service: Service owning the characteristic
        :param BleCharacteristic characteristic: Characteristic object
        :param int offset: Read offset (default: 0)
        :param int length: Max read length
        :return: Value to return to the GATT client
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
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'sub')
        if hook is not None:
            # Call our hook
            return hook(
                notification=notification,
                indication=indication
            )

    def on_characteristic_unsubscribed(self, service, characteristic):
        # Check if we have a hook to call
        hook = self.find_hook(service, characteristic, 'unsub')
        if hook is not None:
            # Call our hook
            return hook()

    def on_notification(self, service, characteristic, value):
        pass

    def on_indication(self, service, characteristic, value):
        pass