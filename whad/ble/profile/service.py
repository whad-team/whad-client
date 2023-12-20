"""
BLE GATT Service Model
======================
"""
import logging
from struct import pack

from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.profile.attribute import Attribute, UUID, get_uuid_alias
from whad.ble.profile.characteristic import Characteristic

logger = logging.getLogger(__name__)

class Service(Attribute):
    def __init__(self, uuid, type_uuid, handle=0, end_handle=0):
        super().__init__(uuid=type_uuid,handle=handle, value=uuid.to_bytes())
        self.__service_uuid = uuid
        if handle > 0:
            self.__end_handle = end_handle if end_handle > 0 else handle
        else:
            self.__end_handle = 0
        self.__characteristics = []
        self.__included_services = []

    @property
    def uuid(self):
        return self.__service_uuid


    @Attribute.handle.setter
    def handle(self, new_handle):
        """Overwrite `Attribute` handle setter.
        """
        if isinstance(new_handle, int):
            # Update service handle
            Attribute.handle.fset(self, new_handle)

            # Update the underlying characteristics
            char_handle = self.handle
            for characteristic in self.__characteristics:
                characteristic.handle = char_handle + 1
                char_handle = characteristic.end_handle
            
            # Update service end_handle value
            self.__end_handle = char_handle
        else:
            raise InvalidHandleValueException

    @property
    def end_handle(self):
        return self.__end_handle

    @end_handle.setter
    def end_handle(self, value):
        self.__end_handle = value

    @property
    def name(self):
        alias = get_uuid_alias(self.__service_uuid)
        if alias is not None:
            return '%s (0x%s)' % (
                alias,
                str(self.__service_uuid)
            )
        else:
            return str(self.__service_uuid)

    def payload(self):
        """Return service UUID as bytes
        """
        return self.__service_uuid.packed

    def add_characteristic(self, characteristic):
        """Add characteristic, update end handle
        """
        if characteristic.handle == 0:
            # Add characteristic, set characteristic handle and update end handle if required
            characteristic.handle = self.end_handle + 1
            self.__end_handle = characteristic.end_handle
        elif characteristic.handle > self.__end_handle:
            # Add characteristic and update end handle if required
            self.__end_handle = characteristic.end_handle
        self.__characteristics.append(characteristic)

    def remove_characteristic(self, characteristic):
        """Remove a specific characteristic
        """
        if isinstance(characteristic, UUID):
            # Look for characteristic and remove it if found
            for charac in self.__characteristics:
                if charac.uuid == characteristic:
                    self.__characteristics.remove(charac)
                    break
        elif isinstance(characteristic, Characteristic):
            # Look for characteristic object
            if characteristic in self.__characteristics:
                self.__characteristics.remove(characteristic)
        
        # Update characteristic handles
        char_handle = self.handle
        for characteristic in self.__characteristics:
            characteristic.handle = char_handle + 1
            char_handle = characteristic.end_handle
        
        # Update service end_handle value
        self.__end_handle = char_handle

    def characteristics(self):
        for charac in self.__characteristics:
            yield charac

    def get_characteristic(self, uuid):
        """Get characteristic by UUID
        """
        for charac in self.__characteristics:
            if charac.uuid == uuid:
                return charac
        return None
    
    def add_include_service(self, included_service):
        """Add include service definition, update end handle
        """
        if included_service.handle == 0:
            # Add characteristic, set characteristic handle and update end handle if required
            included_service.handle = self.end_handle + 1
            self.__end_handle = included_service.end_handle
        elif included_service.handle > self.__end_handle:
            # Add characteristic and update end handle if required
            self.__end_handle = included_service.end_handle
        self.__included_services.append(included_service)

    def remove_include_service(self, included_service):
        """Remove a specific characteristic
        """
        if isinstance(included_service, UUID):
            # Look for characteristic and remove it if found
            for inc_service in self.__included_services:
                if inc_service.uuid == included_service:
                    self.__included_services.remove(inc_service)
                    break
        elif isinstance(included_service, IncludeService):
            # Look for characteristic object
            if included_service in self.__included_services:
                self.__included_services.remove(included_service)
        
        # Update included services and characteristic handles
        char_handle = self.handle
        for inc_service in self.__included_services:
            inc_service.handle = char_handle + 1
            char_handle = inc_service.handle
        for characteristic in self.__characteristics:
            characteristic.handle = char_handle + 1
            char_handle = characteristic.end_handle
        
        # Update service end_handle value
        self.__end_handle = char_handle        

    def included_services(self):
        for inc_service in self.__included_services:
            yield inc_service


class PrimaryService(Service):

    def __init__(self, uuid, handle=0, end_handle=0):
        super().__init__(uuid, UUID(0x2800),handle=handle, end_handle=end_handle)

class SecondaryService(Service):

    def __init__(self, uuid, handle=None):
        super().__init__(uuid, UUID(0x2801),handle=handle)

class IncludeService(Attribute):
    """IncludeService Attribute class

    This class stores the information related to an included service:

    - the included service UUID (16-bit or 128-bit UUID)
    - the start and end handles of the said included service
    """

    def __init__(self, uuid, handle=0, start_handle=0, end_handle=0):
        """Initialize an included service

        :param  uuid:       Included service UUID
        :type   uuid:       UUID
        :param  handle:     Included service start handle
        :type   handle:     int
        :param  end_handle: Included service end handle
        :type   end_handle: int
        """
        self.__service_uuid = uuid
        self.__start_handle = start_handle
        self.__end_handle = end_handle
        super().__init__(UUID(0x2802), handle=handle, value=self.payload())

    @property
    def end_handle(self):
        """Return this attribute end handle

        This attribute does not belong to a group so its end handle is the same
        than its handle.
        """
        return self.handle

    @end_handle.setter
    def end_handle(self, value):
        self.__end_handle = value

    @property
    def uuid(self):
        """Return the attribute type UUID.
        """
        return self.type_uuid
    
    @property
    def service_uuid(self):
        """Return the included service UUID
        """
        return self.__service_uuid
    
    @property
    def service_start_handle(self):
        """Return the included service start handle
        """
        return self.__start_handle
    
    @service_start_handle.setter
    def service_start_handle(self, value):
        self.__start_handle = value
    
    @property
    def service_end_handle(self):
        """Return the included service end handle
        """
        return self.__end_handle
    
    @service_end_handle.setter
    def service_end_handle(self, value):
        self.__end_handle = value

    @property
    def name(self):
        """Generate the description of the included service definition attribute.
        """
        alias = get_uuid_alias(self.__service_uuid)
        if alias is not None:
            return 'Included service %s (0x%s)' % (
                alias,
                str(self.__service_uuid)
            )
        else:
            return 'Included service ' + str(self.__service_uuid)

    def payload(self):
        """Return service UUID as bytes
        """
        if self.__service_uuid.type == UUID.TYPE_16:
            return pack('<HH', self.__start_handle, self.__end_handle) + self.__service_uuid.packed
        else:
            return pack('<HH', self.__start_handle, self.__end_handle)