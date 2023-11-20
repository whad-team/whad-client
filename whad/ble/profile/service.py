"""
BLE GATT Service Model
======================
"""
import logging

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


class PrimaryService(Service):

    def __init__(self, uuid, handle=0, end_handle=0):
        super().__init__(uuid, UUID(0x2800),handle=handle, end_handle=end_handle)

class SecondaryService(Service):

    def __init__(self, uuid, handle=None):
        super().__init__(uuid, UUID(0x2801),handle=handle)
