"""Bluetooth Low Energy device model
"""
from whad.domain.ble.attribute import Attribute
from whad.domain.ble.characteristic import Characteristic as BleCharacteristic,\
    CharacteristicProperties, ClientCharacteristicConfig
from whad.domain.ble.service import PrimaryService as BlePrimaryService, \
    SecondaryService as BleSecondaryService
from whad.domain.ble.exceptions import InvalidHandleValueException
from whad.domain.ble.stack.att.constants import BleAttProperties

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

    def get_required_handles(self):
        """Compute the number of handles this characteristic will consume
        """    
        handles = 2
        # A more handle as we may need a ClientCharacteristicConfiguration descriptor
        if self.__notify or self.__indicate:
            handles += 1
        return handles

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

    def __init__(self, start_handle=0):
        """Parse the device model, instanciate all the services, characteristics
        and descriptors, compute all handle values and registers everything
        inside this instance for further use.

        :param int start_handle: Start handle value to use (default: 1)
        """
        self.__attr_db = {}
        self.__service_by_characteristic_handle = {}

        self.__start_handle = start_handle
        self.__handle = self.__start_handle

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
        print(characteristic)
        print(characteristic.value)
        return characteristic.value[offset:offset + length]

    def on_characteristic_write(self, service, characteristic, offset=0, value=b'', without_response=False):
        """Characteristic write hook

        This hook is called whenever a charactertistic is about to be written by a GATT
        client. If this method returns None, then the write operation will return an error.
        """
        return value

    def on_characteristic_subscribed(self, service, characteristic, notification=False, indication=False):
        pass

    def on_characteristic_unsubscribed(self, service, characteristic):
        pass