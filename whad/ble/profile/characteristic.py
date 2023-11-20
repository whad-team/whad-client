"""
BLE GATT Characteristic Model
=============================
"""
from whad.ble.stack.att.constants import BleAttProperties, SecurityAccess
from whad.ble.profile.attribute import Attribute, UUID, get_uuid_alias
from whad.ble.exceptions import InvalidHandleValueException
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
    def __init__(self, characteristic, uuid, handle=0, value=b''):
        super().__init__(uuid=uuid,handle=handle,value=value)
        self.__characteristic = characteristic

    @property
    def characteristic(self):
        return self.__characteristic

    @property
    def uuid(self):
        return self.type_uuid
    
    @property
    def name(self):
        alias = get_uuid_alias(self.type_uuid)
        if alias is not None:
            return '%s (0x%s)' % (
                alias,
                str(self.type_uuid)
            )
        else:
            return str(self.type_uuid)

class ClientCharacteristicConfig(CharacteristicDescriptor):
    """Client Characteristic Configuration Descriptor
    """

    def __init__(self, characteristic, handle=0, notify=False, indicate=False):
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


class ReportReferenceDescriptor(CharacteristicDescriptor):
    """Report Reference Descriptor, used in HID profile
    """

    def __init__(self, characteristic, handle=None, notify=False, indicate=False):
        """Instanciate a Report Reference Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic indicated on change
        """
        super().__init__(
            characteristic,
            uuid=UUID(0x2908),
            handle=handle,
            value=b'\x01\x01'
        )

class CharacteristicUserDescriptionDescriptor(CharacteristicDescriptor):
    """Characteristic description defined by user, contains
    a textual description of the related characteristic.
    """
    def __init__(self, characteristic, handle=None, description=''):
        """Instanciate a Characteristic User Description descriptor

        :param description: Set characteristic text description
        """
        super().__init__(
            characteristic,
            uuid=UUID(0x2901),
            handle=handle,
            value=description.encode('utf-8')
        )


class CharacteristicValue(Attribute):
    def __init__(self, uuid, handle=None, value=b'', characteristic=None):
        super().__init__(uuid=uuid, handle=handle, value=value)
        self.__characteristic = characteristic

    @property
    def characteristic(self):
        return self.__characteristic

    @property
    def uuid(self):
        return self.type_uuid


class Characteristic(Attribute):
    """BLE Characteristic
    """

    def __init__(self, uuid, handle=0, end_handle=0, value=b'', properties=BleAttProperties.DEFAULT, description=None, security=[]):
        """Instanciate a BLE characteristic object

        :param uuid: 16-bit or 128-bit UUID
        :param int handle: Handle value
        :param bytes value: Characteristic value
        :param int perms: Permissions
        """
        super().__init__(uuid=UUID(0x2803), handle=handle,
                         value=pack('<BH', properties & 0xff, handle+1)+uuid.to_bytes())
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
            self.__value = CharacteristicValue(uuid, self.__value_handle, value, self)
            self.__end_handle = self.__value_handle
        else:
            self.__value_handle = None
            self.__value = CharacteristicValue(uuid, self.__value_handle, value, self)

        # Permissions
        self.__properties = properties

        # Security properties
        self.__security = security

        # Descriptors
        self.__descriptors = []

    def payload(self):
        """Return characteristic payload
        """
        #return bytes([self.__properties, self.__value_handle]) + self.__value.uuid.to_bytes()
        return pack('<BH', self.__properties, self.__value_handle) + self.__value.uuid.packed

    def set_notification_callback(self, callback):
        self.__notification_callback = callback

    def set_indication_callback(self, callback):
        self.__indication_callback = callback

    @Attribute.handle.setter
    def handle(self, new_handle):
        if isinstance(new_handle, int):

            # Set attribute handle
            Attribute.handle.fset(self, new_handle)

            self.__value.handle = self.handle + 1
            self.__value_handle = self.handle + 1

            handle = self.__value_handle

            # Update descriptors handle
            for descriptor in self.__descriptors:
                handle += 1
                descriptor.handle = handle

            # Update end handle
            self.__end_handle = handle
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
        self.__value.handle = value

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

    @property
    def name(self):
        alias = get_uuid_alias(self.__charac_uuid)
        if alias is not None:
            return '%s (0x%s)' % (
                alias,
                str(self.__charac_uuid)
            )
        else:
            return str(self.__charac_uuid)

    ##########################
    # Methods
    ##########################

    def readable(self):
        return (self.properties & CharacteristicProperties.READ) != 0

    def writeable(self):
        return (
            ((self.properties & CharacteristicProperties.WRITE) != 0) or
            ((self.properties & CharacteristicProperties.WRITE_WITHOUT_RESPONSE) != 0)
        )

    def can_notify(self) -> bool:
        """Determine if characteristic sends notifications.

        :return: ``True`` if characteristic sends notification, ``False`` otherwise.
        :rtype: bool
        """
        return ((self.properties & CharacteristicProperties.NOTIFY) != 0)

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

    def can_indicate(self) -> bool:
        """Determine if characteristic sends indications.

        :return: ``True`` if characteristic sends indication, ``False`` otherwise.
        :rtype: bool
        """
        return ((self.properties & CharacteristicProperties.INDICATE) != 0)

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
        if isinstance(descriptor, CharacteristicDescriptor):
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

    @property
    def security(self) -> SecurityAccess:
        """Returns security access property
        """
        return self.__security

    def get_security_access(self, access_type):
        """Returns the security access properties linked to an access type.

        :param access_type: access type to check
        :type access_type: SecurityAccess
        """
        for access in self.__security:
            if isinstance(access, access_type):
                return access
        return None

    def check_security_property(self, access_type, property):
        """Returns a boolean indicating if a property is required for a given access type.

        :param access_type: access type to check
        :type access_type: SecurityAccess
        :param property: security property to check
        :type property: SecurityProperty
        """
        access = self.get_security_access(access_type)
        if access is not None:
            return property in access.access
        return False
