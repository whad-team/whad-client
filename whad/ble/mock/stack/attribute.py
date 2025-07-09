"""
Bluetooth Low Energy Tiny Stack - Attributes
"""
from struct import pack
from typing import Optional

from whad.ble.profile.attribute import UUID

class Attribute:
    """Default attribute"""

    def __init__(self, handle: int, uuid: UUID, value: bytes, end_handle : Optional[int] = None):
        """Attribute initialization."""
        self.__handle = handle
        self.__end_handle = end_handle or handle
        self.__uuid = uuid
        self.__value = value

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
        charac_def = pack("<BH", properties, value_handle) + uuid.packed
        super().__init__(handle, UUID(0x2803), charac_def)


class CharacteristicValue(Attribute):
    """GATT Characteristic value."""

    def __init__(self, handle: int, uuid: UUID, value: bytes):
        """Characteristic value initialization."""
        super().__init__(handle, uuid, value)

class ClientCharacteristicConfigurationDescriptor(Attribute):
    """GATT CCCD attribute."""

    def __init__(self, handle: int):
        """Initialize a CCCD. """
        super().__init__(handle, UUID(0x2902), pack("<H", 0))


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
