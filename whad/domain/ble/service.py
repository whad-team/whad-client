"""Bluetooth Low Energy Service class
"""
from whad.domain.ble.attribute import Attribute, UUID

class Service(Attribute):
    def __init__(self, uuid, handle=None):
        super().__init__(uuid=uuid,handle=handle)
        self.__uuid = uuid
        self.__characteristics = []

    def payload(self):
        return self.__uuid.to_bytes()

    def add_characteristic(self, characteristic):
        self.__characteristics.append(characteristic)

    def characteristics(self):
        for charac in self.__characteristics:
            yield charac

class PrimaryService(Service):

    def __init__(self, uuid, handle=None):
        super().__init__(uuid=UUID(0x2800),handle=handle)

class SecondaryService(Service):

    def __init__(self, uuid, handle=None):
        super().__init__(uuid=UUID(0x2801),handle=handle)
