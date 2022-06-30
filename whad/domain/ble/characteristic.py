"""Bluetooth Low Energy Characteristic Abstraction
"""
from whad.domain.ble.stack.att.constants import BleAttProperties
from whad.domain.ble.attribute import Attribute, UUID
from whad.domain.ble.exceptions import InvalidHandleValueException
from struct import pack

class CharacteristicProperties(object):
    BROADCAST = 0x01
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10
    INDICATE = 0x20
    AUTH_SIGNED_WRITES = 0x40
    EXTENDED_PROPERTIES = 0x80

class CharacteristicDescriptor(Attribute):
    """BLE Characteristic descriptor
    """
    def __init__(self, uuid, handle=None, value=0):
        super().__init__(uuid=uuid,handle=handle,value=value)



class ClientCharacteristicConfig(CharacteristicDescriptor):

    def __init__(self, handle=None, notify=False, indicate=False):
        """Instanciate a Client Characteristic Configuration Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic indicated on change
        """
        value = 0
        if notify:
            value |= 0x0001
        if indicate:
            value |= 0x0002
        super().__init__(uuid=UUID(0x2902), handle=handle, value=value)

    def payload(self):
        return pack('<H', self.value)


class CharacteristicValue(Attribute):
    def __init__(self, uuid, handle=None, value=b''):
        super().__init__(uuid=uuid, handle=handle, value=value)


class Characteristic(Attribute):
    """BLE Characteristic
    """

    def __init__(self, uuid, handle=None, value=b'', properties=BleAttProperties.DEFAULT):
        """Instanciate a BLE characteristic object

        :param uuid: 16-bit or 128-bit UUID
        :param int handle: Handle value
        :param bytes value: Characteristic value
        :param int perms: Permissions
        """
        super().__init__(uuid=UUID(0x2803), handle=handle)
        self.__handle = handle

        if isinstance(handle, int):
            self.__value_handle = handle + 1
            self.__value = CharacteristicValue(uuid, self.__value_handle, value)
        else:
            self.__value_handle = None
            self.__value = CharacteristicValue(uuid, self.__value_handle, value)

        # Permissions
        self.__properties = properties

        # Descriptors
        self.__descriptors = []

    def payload(self):
        return bytes([self.__properties, self.__value_handle]) + self.__value.uuid.to_bytes()

    @property
    def handle(self):
        return self.__handle

    @handle.setter
    def handle(self, new_handle):
        if isinstance(new_handle, int):
            self.__handle = new_handle
            self.__value_handle = self.__handle + 1
        else:
            raise InvalidHandleValueException

    @property
    def value(self):
        return self.__value.value

    @property
    def value_handle(self):
        return self.__value_handle
    
    @value.setter
    def value(self, new_value):
        """Set characteristic value

        :param bytes new_value: Value
        """
        self.__value.value = new_value

    @property
    def properties(self):
        return self.__properties

    @properties.setter
    def properties(self, new_properties):
        self.__properties = new_properties

    ##########################
    # Methods
    ##########################

    def add_descriptor(self, descriptor):
        """Add a descriptor

        :param CharacteristicDescriptor descriptor: Descriptor instance to add to this characteristic.
        """
        if isinstance(descriptor, ClientCharacteristicConfig):
            self.__descriptors.append(descriptor)

    def descriptors(self):
        """Iterate over the registered descriptors (generator)
        """
        for desc in self.__descriptors:
            yield desc

    #########################
    # Callbacks
    #########################

    def on_notify(self):
        """Notification callback
        """
        pass

    def on_indicate(self):
        """Indicate callback
        """
        pass

    def on_read(self):
        """Read callback for characteristic
        """
        return self.__value

    def on_write(self, value):
        """Write callback for characteristic
        """
        self.__value = value


    

    