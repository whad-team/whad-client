"""Bluetooth Low Energy Characteristic Abstraction
"""
from whad.domain.ble.stack.att.constants import BleAttProperties
from whad.domain.ble.attribute import Attribute, UUID
from whad.domain.ble.exceptions import InvalidHandleValueException
from struct import pack, unpack

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
    def __init__(self, characteristic, uuid, handle=None, value=b''):
        super().__init__(uuid=uuid,handle=handle,value=value)
        self.__characteristic = characteristic

    @property
    def characteristic(self):
        return self.__characteristic

class ClientCharacteristicConfig(CharacteristicDescriptor):

    def __init__(self, characteristic, handle=None, notify=False, indicate=False):
        """Instanciate a Client Characteristic Configuration Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic indicated on change
        """
        value = 0
        if notify:
            value |= 0x0001
        if indicate:
            value |= 0x0002
        super().__init__(characteristic, uuid=UUID(0x2902), handle=handle, value=pack('<H', value))

    @property
    def config(self):
        return unpack('<H', super().value)[0]

    @config.setter
    def config(self, val):
        super().value = pack('<H', val)


class CharacteristicValue(Attribute):
    def __init__(self, uuid, handle=None, value=b''):
        super().__init__(uuid=uuid, handle=handle, value=value)

    @property
    def uuid(self):
        return self.type_uuid


class Characteristic(Attribute):
    """BLE Characteristic
    """

    def __init__(self, uuid, handle=None, end_handle=0, value=b'', properties=BleAttProperties.DEFAULT):
        """Instanciate a BLE characteristic object

        :param uuid: 16-bit or 128-bit UUID
        :param int handle: Handle value
        :param bytes value: Characteristic value
        :param int perms: Permissions
        """
        super().__init__(uuid=UUID(0x2803), handle=handle)
        self.__handle = handle
        if end_handle == 0:
            self.__end_handle = handle
        else:
            self.__end_handle = end_handle
        self.__charac_uuid = uuid

        # notification and indication callbacks
        self.__notification_callback = None
        self.__indication_callback = None

        if isinstance(handle, int):
            self.__value_handle = handle + 1
            self.__value = CharacteristicValue(uuid, self.__value_handle, value)
            self.__end_handle = self.__value_handle
        else:
            self.__value_handle = None
            self.__value = CharacteristicValue(uuid, self.__value_handle, value)

        # Permissions
        self.__properties = properties

        # Descriptors
        self.__descriptors = []

    def payload(self):
        return bytes([self.__properties, self.__value_handle]) + self.__value.uuid.to_bytes()

    def set_notification_callback(self, callback):
        self.__notification_callback = callback

    def set_indication_callback(self, callback):
        self.__indication_callback = callback

    @property
    def handle(self):
        return self.__handle

    @handle.setter
    def handle(self, new_handle):
        if isinstance(new_handle, int):
            self.__handle = new_handle
            self.__value_handle = self.__handle + 1
            if self.__end_handle is None:
                self.__end_handle = self.__value_handle
        else:
            raise InvalidHandleValueException

    @property
    def value(self):
        return self.__value.value

    @property
    def value_attr(self):
        return self.__value

    @property
    def value_handle(self):
        return self.__value_handle

    @value_handle.setter
    def value_handle(self, value):
        self.__value_handle = value
    
    @value.setter
    def value(self, new_value):
        """Set characteristic value

        :param bytes new_value: Value
        """
        self.__value.value = new_value

        # Notify or indicate if required
        if self.must_notify() and self.__notification_callback is not None:
            self.__notification_callback(self)
        elif self.must_indicate() and self.__indication_callback is not None:
            self.__indication_callback(self)

    @property
    def properties(self):
        return self.__properties

    @properties.setter
    def properties(self, new_properties):
        self.__properties = new_properties

    @property
    def uuid(self):
        return self.__charac_uuid

    @uuid.setter
    def uuid(self, value):
        self.__charac_uuid = value

    @property
    def end_handle(self):
        return self.__end_handle

    ##########################
    # Methods
    ##########################

    def readable(self):
        return (self.properties & CharacteristicProperties.READ) != 0

    def writeable(self):
        return (self.properties & CharacteristicProperties.WRITE) != 0

    def must_notify(self):
        """Determine if a notification must be sent for this characteristic.

        Notification must be sent when a characteristic has the notification property and
        its ClientCharacteristicConfiguration descriptor has notifications enabled.
        """
        if (self.properties & CharacteristicProperties.NOTIFY) != 0:
            cccd = self.get_client_config()
            if cccd is not None:
                return (cccd.config == 0x0001)
        return False

    def must_indicate(self):
        """Determine if an indication must be sent for this characteristic.

        Indication must be sent when a characteristic has the indication property and
        its ClientCharacteristicConfiguration descriptor has indications enabled.
        """
        if (self.properties & CharacteristicProperties.INDICATE) != 0:
            cccd = self.get_client_config()
            if cccd is not None:
                return (cccd.config == 0x0002)
        return False
            


    def add_descriptor(self, descriptor):
        """Add a descriptor

        :param CharacteristicDescriptor descriptor: Descriptor instance to add to this characteristic.
        """
        if isinstance(descriptor, ClientCharacteristicConfig):
            self.__descriptors.append(descriptor)
            if descriptor.handle > self.__end_handle:
                self.__end_handle = descriptor.handle

    def descriptors(self):
        """Iterate over the registered descriptors (generator)
        """
        for desc in self.__descriptors:
            yield desc

    def get_client_config(self):
        """Find characteristic client configuration descriptor
        """
        for desc in self.__descriptors:
            if isinstance(desc, ClientCharacteristicConfig):
                return desc
        return None


    

    