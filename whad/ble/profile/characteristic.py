"""
BLE GATT Characteristic Model
=============================
"""
from re import I
from struct import pack, unpack
from typing import Union, Type, Optional, List, Iterator

from whad.ble.stack.att.constants import BleAttProperties, SecurityAccess
from whad.ble.profile.attribute import Attribute, UUID, get_uuid_alias
from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.utils.clues import CluesDb

class desc_type:

    def __init__(self, uuid: UUID):
        self.__uuid = uuid

    def __call__(self, cls):
        Descriptor.register_type(self.__uuid, cls)
        return cls

class Properties:
    """Generic characteristic properties.
    """
    BROADCAST = 0x01
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10
    INDICATE = 0x20
    AUTH_SIGNED_WRITES = 0x40
    EXTENDED_PROPERTIES = 0x80

class CharacteristicProperties(Properties):
    """Old name, defined for compatibility"""

class Descriptor(Attribute):
    """BLE Characteristic descriptor
    """
    desc_types = {}

    def __init__(self, uuid: UUID, handle: int = 0, value: bytes = b'', characteristic: Optional['Characteristic'] = None):
        super().__init__(uuid=uuid,handle=handle,value=value)
        self.__characteristic = characteristic

    @property
    def characteristic(self) -> Optional['Characteristic']:
        """Parent characteristic
        """
        return self.__characteristic

    @characteristic.setter
    def characteristic(self, charac: 'Characteristic'):
        """Set characteristic."""
        self.__characteristic = charac

    @property
    def uuid(self):
        """Descriptor UUID
        """
        return self.type_uuid

    @property
    def name(self):
        """Descriptor name
        """
        # Search Bluetooth known UUIDs
        alias = get_uuid_alias(self.type_uuid)
        if alias is not None:
            return f"{alias} (0x{self.type_uuid})"

        # No alias
        return str(self.type_uuid)

    @staticmethod
    def register_type(uuid: UUID, cls):
        """Register descriptor type (associate a descriptor UUID with the
        corresponding Python class (must inherit from Descriptor)
        """
        uuid_value = uuid.value()
        if uuid_value not in Descriptor.desc_types:
            if issubclass(cls, Descriptor):
                Descriptor.desc_types[uuid_value] = cls

    @staticmethod
    def get_type_uuid(desc_cls) -> Optional[UUID]:
        """Find the type UUID corresponding to a given registered descriptor's
        class.

        :return: Descriptor's type UUID if found, `None` otherwise.
        :rtype: UUID
        """
        for desc_type,desc_cls in Descriptor.desc_types.items():
            if desc_cls == desc_cls:
                return UUID(desc_type)

        # Not found
        return None

    @staticmethod
    def from_uuid(characteristic, handle: int, uuid: UUID, value: bytes):
        """Create an instance of a descriptor based on the provided UUID and
        descriptor value.

        :param uuid: Descriptor UUID
        :type  uuid: UUID
        :param value: Descriptor value
        :type  value: bytes
        :return: Instance of the corresponding descriptor
        :rtype: Descriptor
        """
        uuid_value = uuid.value()
        if uuid_value in Descriptor.desc_types:
            cls = Descriptor.desc_types[uuid_value]
            return cls.from_value(characteristic, handle, value)

        # Cannot find any class matching the provided UUID, return a generic
        # descriptor.
        return Descriptor(uuid, handle, value, characteristic)

    @classmethod
    def _build(cls, instance: Type['Descriptor']):
        """Build a new descriptor based on current template."""
        return cls(
            instance.uuid,
            0,
            instance.value,
            characteristic=instance.characteristic
        )

    def build(self):
        return self.__class__._build(self)

class CharacteristicDescriptor(Descriptor):
    """Old class defining a characteristic descriptor, kept for backward compatibility.

    .. deprecated:: 1.3.0
        Renamed for clarity purpose ('Characteristic' in this class name has been removed
        as this class is already defined in the *characteristic* module), please use
        the new :class:`~whad.ble.profile.characteristic.Descriptor` class instead.
    """

@desc_type(UUID(0x2902))
class ClientCharacteristicConfig(Descriptor):
    """Client Characteristic Configuration Descriptor
    """

    def __init__(self, handle: int = 0, notify: bool = False, indicate: bool = False,
                 characteristic: Optional['Characteristic'] = None):
        """Instantiate a Client Characteristic Configuration Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic
                              indicated on change
        """
        value = 0
        if notify:
            value |= 0x0001
        if indicate:
            value |= 0x0002
        super().__init__(UUID(0x2902), handle=handle, value=pack('<H', value), characteristic=characteristic)

    @property
    def config(self):
        """CCCD configuration
        """
        return unpack('<H', super().value)[0]

    @config.setter
    def config(self, val):
        """Update CCCD configuration
        """
        super().value = pack('<H', val)

    @staticmethod
    def from_value(characteristic, handle, value):
        """Create a ClientCharacteristicConfig instance from the provided
        handle and value, and tie it to a specific characteristic.
        """
        # Create our CCCD object
        v = value[0]
        cccd = ClientCharacteristicConfig(handle,(v & 0x0001) != 0, (v & 0x0002) != 0, characteristic)
        # Set its value
        cccd.value = value

        return cccd

    @classmethod
    def _build(cls, instance: 'ClientCharacteristicConfig'):
        """Build a new descriptor based on current template."""
        return cls(
            0,
            (instance.config & 0x0001) != 0,
            (instance.config & 0x0002) != 0,
            characteristic=instance.characteristic
        )

class ReportReference(Descriptor):
    """Report Reference descriptor, used in HID profile
    """

    def __init__(self, handle: int = 0, characteristic: Optional['Characteristic'] = None):
        """Instantiate a Report Reference Descriptor

        :param bool notify: Set to True to get the corresponding characteristic notified on change
        :param bool indicate: Set to True to get the corresponding characteristic
                              indicated on change
        """
        super().__init__(
            uuid=UUID(0x2908),
            handle=handle,
            value=b'\x01\x01',
            characteristic=characteristic
        )

    @classmethod
    def _build(cls, instance: 'ReportReference'):
        """Build a new descriptor based on current template."""
        return cls(
            0,
            characteristic=instance.characteristic
        )

class ReportReferenceDescriptor(ReportReference):
    """Old report reference descriptor class, kept for backward compatibility.


    .. deprecated:: 1.3.0
        Use the new :class:`~whad.ble.profile.characteristic.ReportReference` class that defines
        an HID ReportReference descriptor.
    """

@desc_type(UUID(0x2901))
class UserDescription(Descriptor):
    """Characteristic user description descriptor.

    This descriptor specifies a textual description of the characteristic it is attached to. This description
    is exposed by the GATT server and can be read by a GATT client.
    """
    def __init__(self, handle: int = 0, description: str = '', characteristic: Optional['Characteristic'] = None):
        """Instantiate a Characteristic User Description descriptor

        :param description: Set characteristic text description
        :type  description: str
        :param characteristic: Characteristic this descriptor is attached to, not required when defining a GATT model.
        :type  characteristic: Characteristic, optional
        """
        self.__description = description
        super().__init__(
            uuid=UUID(0x2901),
            handle=handle,
            value=description.encode('utf-8'),
            characteristic=characteristic
        )

    @property
    def text(self) -> str:
        """User description
        """
        return self.__description

    @property
    def name(self):
        """Descriptor name

        Clean description as it may contain null chars.
        """
        # End string at the first null char encountered
        if '\x00' in self.__description:
            desc = self.__description[:self.__description.index('\x00')]
        else:
            desc = self.__description

        return f"{super().name}, '{desc}'"

    @staticmethod
    def from_value(characteristic, handle, value):
        """Create CUD descriptor from value
        """
        return UserDescription(
             handle, description=value.decode('utf-8'), characteristic=characteristic
        )

    @classmethod
    def _build(cls, instance: 'UserDescription'):
        """Build a new descriptor based on current template."""
        return cls(
            0,
            instance.value.decode('utf-8'),
            characteristic=instance.characteristic
        )

class CharacteristicUserDescriptionDescriptor(UserDescription):
    """Old name of the UserDescription descriptor."""

class CharacteristicValue(Attribute):
    """Characteristic value attribute.
    """

    def __init__(self, uuid, handle: int = 0, value: bytes = b'', characteristic: Optional['Characteristic'] = None):
        super().__init__(uuid=uuid, handle=handle, value=value)
        self.__characteristic = characteristic

    @property
    def characteristic(self):
        """Associated characteristic
        """
        return self.__characteristic

    @property
    def uuid(self):
        """Attribute UUID
        """
        return self.type_uuid

class Characteristic(Attribute):
    """BLE Characteristic
    """

    # Properties
    BROADCAST = 0x01
    READ = 0x02
    WRITE_WITHOUT_RESPONSE = 0x04
    WRITE = 0x08
    NOTIFY = 0x10
    INDICATE = 0x20
    AUTH_SIGNED_WRITES = 0x40
    EXTENDED_PROPERTIES = 0x80

    def __init__(self, uuid: UUID, handle: int = 0, end_handle: int = 0, value: bytes = b'',
                 properties: int = 0, permissions: Optional[List[str]] = None, notify: bool = False,
                 indicate: bool = False, required: bool = False, description: Optional[str] = None, security:
                 Optional[SecurityAccess] = None, descriptors: List[Descriptor] = []):
        """Instantiate a BLE characteristic object

        :param uuid: 16-bit or 128-bit UUID
        :param int handle: Handle value
        :param bytes value: Characteristic value
        :param int perms: Permissions
        """
        # Create our parent attribute (type UUID of 0x2803, and value containing our properties, value handle and UUID)
        super().__init__(uuid=UUID(0x2803), handle=handle,
                         value=pack('<BH', properties & 0xff, handle+1)+uuid.to_bytes())

        # Set end handle: if 0, then it is considered as not set by the caller and set by
        # default to the characteristic's handle value.
        if end_handle == 0:
            self.__end_handle = handle
        else:
            self.__end_handle = end_handle

        # Set characteristic UUID
        self.__charac_uuid = uuid

        # Set characteristic alias
        self.__alias = None

        # Notification and indication callbacks
        self.__notification_callback = None
        self.__indication_callback = None

        # Add a characteristic value attribute
        self.__value_handle = handle + 1
        self.__value = CharacteristicValue(uuid, self.__value_handle, value, self)
        self.__end_handle = self.__value_handle

        # Set characteristic properties
        self.__properties = properties

        # Update properties according to defined permissions, if any (only used when object is considered a template)
        if permissions is not None:
            perms = list(map(lambda x: x.lower().strip(), permissions))
            if 'read' in perms:
                self.__properties |= Characteristic.READ
            if 'write' in perms:
                self.__properties |= Characteristic.WRITE
            if 'write_without_response' in perms:
                self.__properties |= Characteristic.WRITE_WITHOUT_RESPONSE
            if 'notify' in perms:
                self.__properties |= Characteristic.NOTIFY
            if 'indicate' in perms:
                self.__properties |= Characteristic.INDICATE

        # If characteristic is set as supporting notifications, define the correct property.
        if notify:
            self.__properties |= Properties.NOTIFY

        # Same for indications.
        if indicate:
            self.__properties |= Properties.INDICATE

        # By default, this characteristic object is instantiated as a standalone characteristic,
        # this means all the handles depending on this characteristic (value and descriptors) will
        # be computed from the characteristic's definition handle.
        self.__service = None

        # When `required` is set, the characteristic is set as *mandatory*. This flag is only used by a
        # service to determine if this characteristic must be present in its parent service.
        self.required = required

        # Security properties
        self.__security = security if security is not None else []

        # List of descriptors.
        self.__descriptors = []

        # Add descriptors if handle is 0 (object used as a template)
        if handle == 0:
            # If this characteristic's handle is not set, we automatically add a ClientCharacteristicConfig
            # descriptor if its properties say it supports indication and/or notification.
            if (self.can_indicate() or self.can_notify()):
                self.add_descriptor(ClientCharacteristicConfig(
                    characteristic=self
                ))

            # Add a CharacteristicUserDescriptionDescriptor if description is set and handle is 0
            if (description is not None and handle == 0):
                self.add_descriptor(UserDescription(
                    description=description,
                    characteristic=self
                ))

            # Add additional descriptors
            for desc in descriptors:
                if isinstance(desc, Descriptor):
                    # Bind descriptor to this characteristic
                    desc.characteristic = self

                    # Don't add a CCC descriptor if characteristic already has one.
                    if isinstance(desc, ClientCharacteristicConfig) and self.get_descriptor(ClientCharacteristicConfig):
                        continue

                    # Add descriptor to our list of descriptors
                    self.add_descriptor(desc)

    @classmethod
    def _build(cls, instance):
        """Build a new characteristic object based on this model."""
        # Create a new list of descriptors
        descriptors = []
        for desc in instance.descriptors():
            descriptors.append(desc.build())

        # Create a new object based on current template.
        charac = cls(
            instance.uuid,
            handle=0,
            end_handle=0,
            value=instance.value,
            properties=instance.properties,
            security=instance.security,
            descriptors=descriptors
        )
        if instance.alias is not None:
            charac.alias = instance.alias
        return charac

    def build(self):
        """Build a new characteristic from current object."""
        return self.__class__._build(self)

    def payload(self):
        """Return characteristic payload
        """
        return pack('<BH', self.__properties, self.__value_handle) + self.__value.uuid.packed

    def set_notification_callback(self, callback):
        """Save the provided callback as notification callback
        """
        self.__notification_callback = callback

    def set_indication_callback(self, callback):
        """Save the provided callback as indication callback
        """
        self.__indication_callback = callback

    @Attribute.handle.setter
    def handle(self, new_handle):
        """Set new handle value

        Update the characteristic's value handle as well as handles
        of all descriptors attached to this characteristic.
        """
        if isinstance(new_handle, int):

            # Set attribute handle
            Attribute.handle.fset(self, new_handle)

            self.__value.handle = new_handle + 1
            self.__value_handle = new_handle + 1

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

    @value.setter
    def value(self, value):
        """Set characteristic value

        :param bytes new_value: Value
        """
        self.__value.value = value

        # Notify or indicate if required
        if self.must_notify() and self.__notification_callback is not None:
            self.__notification_callback(self)
        elif self.must_indicate() and self.__indication_callback is not None:
            self.__indication_callback(self)

    @property
    def value_attr(self):
        """Associated value attribute
        """
        return self.__value

    @property
    def value_handle(self):
        """Characteristic value handle
        """
        return self.__value_handle

    @value_handle.setter
    def value_handle(self, value):
        """Update characteristic value handle
        """
        self.__value_handle = value
        self.__value.handle = value

    @property
    def properties(self):
        """Characteristic properties
        """
        return self.__properties

    @properties.setter
    def properties(self, new_properties):
        """Set characteristic properties
        """
        self.__properties = new_properties

    @property
    def uuid(self) -> UUID:
        """Characteristic UUID
        """
        return self.__charac_uuid

    @uuid.setter
    def uuid(self, value):
        """Update characteristic UUID
        """
        self.__charac_uuid = value

    @property
    def end_handle(self):
        """Characteristic end handle
        """
        return self.__end_handle

    @property
    def name(self):
        """Characteristic standard name (if any)
        """
        # Search Bluetooth known UUIDs
        alias = get_uuid_alias(self.__charac_uuid)
        if alias is not None:
            return f"{alias} (0x{self.__charac_uuid})"

        # Search in collaborative CLUES database
        alias = CluesDb.get_uuid_alias(self.__charac_uuid)
        if alias is not None:
            if self.__charac_uuid.type == UUID.TYPE_16:
                return f"{alias} (0x{self.__charac_uuid})"
            else:
                return f"{alias} ({self.__charac_uuid})"


        return str(self.__charac_uuid)

    @property
    def service(self):
        """Service this characteristic belongs to."""
        return self.__service

    @service.setter
    def service(self, service):
        """Set characteristic service."""
        self.__service = service

    @property
    def alias(self) -> Optional[str]:
        """Characteristic alias."""
        return self.__alias

    @alias.setter
    def alias(self, alias: str):
        self.__alias = alias

    ##########################
    # Methods
    ##########################

    def attach(self, service):
        """Attach this characteristic to a service.

        :param service: Service referenced
        :type  service: Service
        """
        self.__service = service

    def get_required_handles(self) -> int:
        if self.handle is not None and self.__end_handle is not None:
            return (self.__end_handle - self.handle) + 1
        return 0

    def readable(self):
        """Determine if characteristic can be read
        """
        return (self.properties & Properties.READ) != 0

    def writeable(self):
        """Determine if characteristic can be written to
        """
        return (
            ((self.properties & Properties.WRITE) != 0) or
            ((self.properties & Properties.WRITE_WITHOUT_RESPONSE) != 0)
        )

    def can_notify(self) -> bool:
        """Determine if characteristic sends notifications.

        :return: ``True`` if characteristic sends notification, ``False`` otherwise.
        :rtype: bool
        """
        return (self.properties & Properties.NOTIFY) != 0

    def must_notify(self):
        """Determine if a notification must be sent for this characteristic.

        Notification must be sent when a characteristic has the notification property and
        its ClientCharacteristicConfiguration descriptor has notifications enabled.
        """
        if (self.properties & Properties.NOTIFY) != 0:
            cccd = self.get_client_config()
            if cccd is not None:
                return cccd.config == 0x0001
        return False

    def can_indicate(self) -> bool:
        """Determine if characteristic sends indications.

        :return: ``True`` if characteristic sends indication, ``False`` otherwise.
        :rtype: bool
        """
        return (self.properties & Properties.INDICATE) != 0

    def must_indicate(self):
        """Determine if an indication must be sent for this characteristic.

        Indication must be sent when a characteristic has the indication property and
        its ClientCharacteristicConfiguration descriptor has indications enabled.
        """
        if (self.properties & Properties.INDICATE) != 0:
            cccd = self.get_client_config()
            if cccd is not None:
                return cccd.config == 0x0002
        return False

    def add_descriptor(self, descriptor: Descriptor) -> 'Characteristic':
        """Add a descriptor

        :param descriptor: Descriptor instance to add to this characteristic.
        :type  descriptor: :class:`whad.ble.profile.characteristic.Descriptor`
        """
        # Set descriptor's handle and update end handle
        if descriptor.handle == 0:
            descriptor.handle = self.__end_handle + 1

        # Add this descriptor to our list of descriptors
        self.__descriptors.append(descriptor)

        # Update our end handle
        self.__end_handle = max(descriptor.handle, self.__end_handle)

        return self

    def get_descriptor(self, desc_type: Union[UUID, Type[Descriptor]]) -> Optional[Descriptor]:
        """Retrieve a decriptor based on its type UUID or class.

        :param desc_type: Descriptor type
        :type  desc_type: UUID, :class:`whad.ble.profile.characteristic.Descriptor`
        :return: First matching descriptor belonging to this characteristic
        :rtype: :class:`whad.ble.profile.Descriptor`, optional
        """
        # Validate descriptor type (UUID or class)
        if isinstance(desc_type, UUID):
            # Descriptor's type UUID is provided, use it as-is
            type_uuid = desc_type
        elif issubclass(desc_type, Descriptor):
            # Descriptor class provided, search for corresponding type UUID
            for desc in self.__descriptors:
                if isinstance(desc, desc_type):
                    return desc
            return None

        # If we found a valid type UUID, look for a matching descriptor
        for desc in self.__descriptors:
            if desc.type_uuid == type_uuid:
                return desc

        # Not found
        return None

    def descriptors(self) -> Iterator[Descriptor]:
        """Iterate over the registered descriptors (generator)
        """
        yield from self.__descriptors

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

    def check_security_property(self, access_type, prop):
        """Returns a boolean indicating if a property is required for a given access type.

        :param access_type: access type to check
        :type access_type: SecurityAccess
        :param property: security property to check
        :type property: SecurityProperty
        """
        access = self.get_security_access(access_type)
        if access is not None:
            return prop in access.access
        return False
