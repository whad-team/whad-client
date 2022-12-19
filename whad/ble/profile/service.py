"""Bluetooth Low Energy Service class
"""
from whad.ble.profile.attribute import Attribute, UUID
from whad.ble.stack.gatt.helpers import get_uuid_alias

class Service(Attribute):
    def __init__(self, uuid, type_uuid, handle=0, end_handle=0):
        super().__init__(uuid=type_uuid,handle=handle)
        self.__service_uuid = uuid
        if handle > 0:
            self.__end_handle = end_handle if end_handle > 0 else handle
        self.__characteristics = []

    @property
    def uuid(self):
        return self.__service_uuid

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
        return self.__service_uuid.to_bytes()

    def add_characteristic(self, characteristic):
        """Add characteristic, update end handle
        """
        if self.handle == 0:
            self.handle = characteristic.handle
        if characteristic.end_handle >= self.__end_handle:
            self.__end_handle = characteristic.end_handle
        self.__characteristics.append(characteristic)

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
