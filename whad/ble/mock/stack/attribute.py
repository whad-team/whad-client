"""
Bluetooth Low Energy Tiny Stack - Attributes
"""
from struct import pack
from typing import Optional

from whad.ble.profile.attribute import UUID

class Attribute:
    """Default attribute"""

    def __init__(self, handle: int, uuid: UUID, value: bytes, end_handle : Optional[int] = None,
                 read: bool = True, write: bool = False
                ):
        """Attribute initialization."""
        self.__handle = handle
        self.__end_handle = end_handle or handle
        self.__uuid = uuid
        self.__value = value
        self.__read = read
        self.__write = write

    @property
    def handle(self) -> int:
        """Attribute handle"""
        return self.__handle

    @property
    def end_handle(self) -> int:
        """Attribute end handle (grouping)."""
        return self.__end_handle

    @property
    def uuid(self) -> UUID:
        """Attribute type uuid"""
        return self.__uuid

    @property
    def value(self) -> bytes:
        """Attribute value"""
        return self.__value
    @value.setter
    def value(self, new_value: bytes):
        """Update attribute value"""
        self.__value = new_value

    def readable(self) -> bool:
        """Check if attribute has the read permission."""
        return self.__read

    def writeable(self) -> bool:
        """Check if attribute can be written."""
        return self.__write

    def pack(self) -> bytes:
        return pack("<H", self.handle) + self.value


class PrimaryService(Attribute):
    """GATT Primary Service"""

    def __init__(self, handle: int, end_handle: int, uuid: UUID):
        """Initialize service."""
        super().__init__(handle, UUID(0x2800), uuid.packed, end_handle=end_handle)


class SecondaryService(Attribute):
    """GATT Secondary Service."""

    def __init__(self, handle: int, end_handle: int, uuid: UUID):
        """Initialize secondary service."""
        super().__init__(handle, UUID(0x2801), uuid.packed, end_handle=end_handle)


class IncludeService(Attribute):
    """GATT Included Service."""

    def __init__(self, handle: int, service_handle: int, end_handle: int, uuid: UUID):
        """Initialize included service."""
        service_value = pack("<HH", service_handle, end_handle)
        if uuid.type == UUID.TYPE_16:
            service_value += uuid.packed
        super().__init__(handle, UUID(0x2802), service_value, end_handle=end_handle)


class Characteristic(Attribute):
    """GATT Characteristic."""

    PROP_BROADCAST = 0x01
    PROP_READ = 0x02
    PROP_WRITE_WITHOUT_RESP = 0x04
    PROP_WRITE = 0x08
    PROP_NOTIFY = 0x10
    PROP_INDICATE = 0x20
    PROP_AUTH_SIGN_WRITE = 0x40
    PROP_EXTENDED = 0x80

    def __init__(self, handle: int, uuid: UUID, value_handle: int, properties: int):
        """Characteristic initizalization."""
        self.__properties = properties
        self.__value_handle = value_handle
        charac_def = pack("<BH", properties, value_handle) + uuid.packed
        super().__init__(handle, UUID(0x2803), charac_def)

    @property
    def value_handle(self) -> int:
        """Value handle."""
        return self.__value_handle

    def has_property(self, prop) -> bool:
        """Check if a property is defined for this characteristic."""
        return (prop & self.__properties) > 0

class CharacteristicValue(Attribute):
    """GATT Characteristic value."""

    def __init__(self, handle: int, uuid: UUID, value: bytes, write: bool = True, read: bool = True, 
                 write_without_resp: bool = False):
        """Characteristic value initialization."""
        self.__without_resp = write_without_resp
        # Use `write=True` because characteristic value can be written.
        super().__init__(handle, uuid, value, read=read, write=write or write_without_resp)

    def writeable_without_resp(self) -> bool:
        """Determine if the caracteristic is writeable through a WriteCommand."""
        return self.__without_resp


class ClientCharacteristicConfigurationDescriptor(Attribute):
    """GATT CCCD attribute."""

    def __init__(self, handle: int):
        """Initialize a CCCD. """
        # Descriptor value can be modified.
        super().__init__(handle, UUID(0x2902), pack("<H", 0),
                         write=True)


def find_attr_by_handle(attributes: list, handle: int) -> Attribute:
    """Find attribute from list by handle."""
    for attribute in attributes:
        if attribute.handle == handle:
            return attribute
    raise IndexError()

def find_attr_by_range(attributes: list, start_handle: int, end_handle: int) -> list[Attribute]:
    attrs = []
    for attribute in attributes:
        if attribute.handle >= start_handle and attribute.handle <= end_handle:
            attrs.append(attribute)
    return attrs

def find_attr_by_type(attributes: list[Attribute], attr_type: UUID, start_handle: int = 0, end_handle: int = 0xFFFF) -> list[Attribute]:
    """Find attribute from list by attribute type."""
    attrs = []
    for attribute in attributes:
        if attribute.handle >= start_handle and attribute.handle <= end_handle:
            if attribute.uuid == attr_type:
                attrs.append(attribute)
    return attrs

def find_charac_by_desc_handle(attributes: list[Attribute], handle: int) -> Optional[Characteristic]:
    """Find the characteristic attribute that holds the given descriptor."""
    charac = None
    for attribute in attributes:
        if isinstance(attribute, Characteristic):
            charac = attribute
        if attribute.handle == handle:
            break
    # Return found characteristic
    return charac

