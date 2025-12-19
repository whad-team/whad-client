"""Bluetooth Low Energy Central connector testing
"""
import pytest
from typing import Optional
from threading import Event

from whad.ble.mock import CentralMock, EmulatedDevice
from whad.ble import BDAddress, Central
from whad.ble.profile import Characteristic
from whad.ble.profile.attribute import UUID, Attribute
from whad.ble.profile.device import PeripheralCharacteristic, PeripheralDevice, PeripheralService
from whad.ble.stack.att.exceptions import AttributeNotFoundError, InvalidOffsetError, WriteNotPermittedError
from whad.ble.stack.gatt.exceptions import GattTimeoutException

@pytest.fixture
def mock_devices():
    """BLE mock devices
    """
    return [
        EmulatedDevice(BDAddress("00:11:22:33:44:55", random=False),
                    adv_data=b"\x02\x01\x06", scan_data=b"\x07\x08foobar"),
    ]

@pytest.fixture
def central_mock(mock_devices):
    """Create a BLE Central mock.
    """
    return CentralMock(devices=mock_devices, nowait=True)

def test_create(central_mock):
    """Test Central connector creation.
    """
    # Attach a central connector to our central mock
    central = Central(central_mock)
    assert central.can_be_central()

def test_connect_success(central_mock):
    """Initiate a connection to a device (expected to succeed).
    """
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0
    assert isinstance(target, PeripheralDevice)

def test_read_attribute_success(central_mock):
    """Connect to a device and send a PDU.
    """
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Read attribute
    value = target.read(3)
    assert value == b"EmulatedDevice"

def test_read_attribute_error(central_mock):
    """Try to read an attribute with an invalid handle."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Read attribute with invalid handle, must raise InvalidHandleValueError.
    with pytest.raises(AttributeNotFoundError):
        value = target.read(100)
        assert value == None

def test_write_attribute(central_mock):
    """Try to write to an attribute. """
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Read attribute with invalid handle, must raise InvalidHandleValueError.
    target.write(3, b"Pwn3d")
    assert target.read(3) == b"Pwn3d"
    target.write(3, b"EmulatedDevice")

def test_write_attribute_bad_perm(central_mock):
    """Try to write to an attribute. """
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Write read-only attribute, must raise
    with pytest.raises(WriteNotPermittedError):
        target.write(2, b"Foobar")

def test_write_attribute_invalid_handle(central_mock):
    """Try to write to an attribute. """
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Write non-existing attribute, must raise InvalidHandleValueError.
    with pytest.raises(AttributeNotFoundError):
        target.write(100, b"Pwn3d")

def test_write_command(central_mock):
    """Write data into a write without response characteristic."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Write non-existing attribute, must raise InvalidHandleValueError.
    target.write_command(10, b"P0wn3d")

def test_read_blob(central_mock):
    """Read data blob from characteristic."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Read DeviceName characteristic value starting at offset 1.
    assert target.read(3, offset=1) == b"mulatedDevice"

def test_read_blob_bad_offset(central_mock):
    """Read data blob from characteristic."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Read DeviceName characteristic value starting at offset 24 (invalid),
    # InvalidOffsetValueError is expected to be raised
    with pytest.raises(InvalidOffsetError):
        assert target.read(3, offset=24) == b"mulatedDevice"

def test_get_characteristic(central_mock):
    """Search for a specific characteristic based on its UUID."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    print(target)
    charac = target.get_characteristic(UUID("1800"), UUID("2a00"))
    assert charac is not None
    assert type(charac) == PeripheralCharacteristic
    assert charac.handle == 2

def test_get_characteristic_error(central_mock):
    """Search for a non-existing characteristic."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    charac = target.get_characteristic(UUID("1800"), UUID("3300"))
    assert charac is None

def test_find_service_by_uuid(central_mock):
    """Find service by its uuid, with no discovery."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    service = target.find_service_by_uuid(UUID('1800'))
    assert service is not None
    assert service.handle == 1
    assert service.uuid == UUID('1800')

def test_find_service_by_uuid_error(central_mock):
    """Find service by its (invalid) uuid, with no discovery."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    service = target.find_service_by_uuid(UUID('1337'))
    assert service is None

def test_get_service(central_mock):
    """Retrieve a specific service from its UUID with `get_service()`."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_get_service_error(central_mock):
    """Retrieve a service from an invalid UUID with `get_service`"""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('3300'))
    assert service is None

def test_service_uuid(central_mock):
    """Retrieve a specific service from its UUID with the new `service()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_service_str(central_mock):
    """Retrieve a specific service from its UUID as a string with the new `service()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service('1800')
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_service_error(central_mock):
    """Retrieve a specific service from an invalid UUID with the new `service()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('3300'))
    assert service is None

def test_device_get_item_uuid(central_mock):
    """Retrieve a specific service from its UUID using the `PeripheralDevice` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target[UUID('1800')]
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_device_get_item_int(central_mock):
    """Retrieve a specific service from its UUID using the `PeripheralDevice` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target[0x1800]
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_device_get_item_str(central_mock):
    """Retrieve a specific service from its UUID using the `PeripheralDevice` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target['1800']
    assert service is not None
    assert isinstance(service, PeripheralService)

def test_device_get_item_error(central_mock):
    """Retrieve a specific service from an invalid UUID using the `PeripheralDevice` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    with pytest.raises(IndexError):
        _ = target[UUID('3300')]

def test_device_service_in_uuid(central_mock):
    """Check a specific service is present in the attribute database based on its UUID, using the `in` operator."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    assert UUID('1800') in target

def test_find_characteristics(central_mock):
    """Look for a specific characteristic from its UUID."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    characs = target.find_characteristics_by_uuid(UUID('2a00'))
    assert len(characs) == 1
    assert characs[0].uuid == UUID('2a00')
    assert characs[0].handle == 2

def test_find_characteristics_error(central_mock):
    """Look for a specific characteristic from its (invalid) UUID."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    characs = target.find_characteristics_by_uuid(UUID('1337'))
    assert len(characs) == 0

def test_service_get_char(central_mock):
    """Retrieve a specific characteristic from its UUID with `get_characteristic()`."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    assert isinstance(service, PeripheralService)
    char = service.get_characteristic(UUID('2a00'))
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)

def test_service_get_char_error(central_mock):
    """Retrieve a characteristic from an invalid UUID with `get_characteristic()`"""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    char = service.get_characteristic(UUID('3300'))
    assert char is None

def test_service_char_from_uuid(central_mock):
    """Retrieve a specific characteristic from its UUID with the new `char()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    assert isinstance(service, PeripheralService)
    char = service.char(UUID('2a00'))
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)

def test_service_char_from_str(central_mock):
    """Retrieve a specific characteristic from its UUID as string with the new `char()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.get_service(UUID('1800'))
    assert service is not None
    assert isinstance(service, PeripheralService)
    char = service.char('2a00')
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)

def test_service_char_error(central_mock):
    """Retrieve a specific characteristic from an invalid UUID with the new `char()` method."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    char = service.char(UUID('3300'))
    assert char is None

def test_service_get_item_uuid(central_mock):
    """Retrieve a specific characteristic from its UUID using the `PeripheralService` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    char = service[UUID('2a00')]
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)
    assert char.uuid == UUID('2a00')

def test_service_get_item_int(central_mock):
    """Retrieve a specific characteristic from its UUID using the `PeripheralService` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    char = service[0x2a00]
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)
    assert char.uuid == UUID('2a00')

def test_service_get_item_str(central_mock):
    """Retrieve a specific characteristic from its UUID using the `PeripheralService` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    char = service['2a00']
    assert char is not None
    assert isinstance(char, PeripheralCharacteristic)
    assert char.uuid == UUID('2a00')

def test_service_get_item_error(central_mock):
    """Retrieve a specific characteristic from an invalid UUID using the `PeripheralService` dict-like behavior."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    with pytest.raises(IndexError):
        _ = service[UUID('3300')]

@pytest.mark.parametrize("uuid, service", [
    ('2a00', None),
    (UUID('2a00'), None),
    ('2a00', '1800'),
    (UUID('2a00'), '1800'),
    ('2a00', UUID('1800')),
    (UUID('2a00'), UUID('1800')),
])
def test_char(central_mock, uuid, service):
    """Retrieve a specific characteristic from only its UUID as string."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    charac = target.char(uuid, service=service)
    assert charac is not None
    assert charac.uuid == UUID(0x2a00)

def test_service_char_in_uuid(central_mock):
    """Check a specific characteristic is present in the attribute database based on its UUID, using the `in` operator."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    service = target.service(UUID('1800'))
    assert service is not None
    assert UUID('2a00') in service

def test_find_attribute(central_mock):
    """Search for an attribute given its handle."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    attr = target.find_object_by_handle(2)
    assert attr is not None
    assert type(attr) == PeripheralCharacteristic
    assert attr.handle == 2

def test_find_attribute_error(central_mock):
    """Search for an attribute given an invalid handle."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    with pytest.raises(IndexError):
        target.find_object_by_handle(1000)

def test_notification(central_mock):
    """Register for notification and checks notifications are correctly handled."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    # Retrieve a specific characteristic
    char = target.get_characteristic(
        UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
        UUID("6d02b602-1b51-4ef9-b753-1399e05debfd")
    )
    assert char is not None

    notif_sync = Event()
    characteristic: Optional[Characteristic] = None
    value = None
    indicated = False

    # Defines a callback that set `notifs` to True
    def _notif_cb(charac, char_value, indication=False):
        nonlocal value, characteristic, indicated
        notif_sync.set()
        value = char_value
        characteristic = charac
        indicated = indication

    char.subscribe(notification=True, callback=_notif_cb)
    notif_sync.wait()
    assert indicated == False
    assert value == b"Notified"
    assert characteristic is not None and characteristic.uuid == char.uuid

def test_notification_error(central_mock):
    """Register for notification on erroneous characteristic and checks
    no notification is sent."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Discover services and characteristics
    target.discover()

    # Search for a specific characteristic
    char = target.get_characteristic(
        UUID(0x1800),
        UUID(0x2a00)
    )
    assert char is not None

    # Prepare an async event to detect timeouts
    notif_sync = Event()
    characteristic: Optional[Characteristic] = None
    value = None
    indicated = False

    # Defines a callback that saves parameters
    def _notif_cb(charac, char_value, indication=False):
        nonlocal value, characteristic, indicated
        notif_sync.set()
        value = char_value
        characteristic = charac
        indicated = indication

    char.subscribe(notification=True, callback=_notif_cb)
    assert not notif_sync.wait(timeout=1.0)

def test_indication(central_mock):
    """Register for indication and checks indications are correctly handled."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    target.discover()
    # Read DeviceName characteristic value starting at offset 24 (invalid),
    # InvalidOffsetValueError is expected to be raised
    char = target.get_characteristic(
        UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
        UUID("6d02b602-1b51-4ef9-b753-1399e05debfd")
    )
    assert char is not None

    indic_sync = Event()
    characteristic: Optional[Characteristic] = None
    value = None
    indicated = False

    def _indic_cb(charac, char_value, indication=False):
        nonlocal value, characteristic, indicated
        indic_sync.set()
        value = char_value
        characteristic = charac
        indicated = indication

    char.subscribe(indication=True, callback=_indic_cb)
    indic_sync.wait()
    assert indicated == True
    assert value == b"Indicated"
    assert characteristic is not None and characteristic.uuid == char.uuid

def test_indication_error(central_mock):
    """Register for indication and checks confirmation is correctly handled."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Discover services and characteristics
    target.discover()

    # Search for a specific characteristic
    char = target.get_characteristic(
        UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
        UUID("6d02b601-1b51-4ef9-b753-1399e05debfd")
    )
    assert char is not None

    # Prepare an async event to detect timeouts
    indic_sync = Event()
    characteristic: Optional[Characteristic] = None
    value = None
    indicated = False

    # Defines a callback that saves parameters
    def _indic_cb(charac, char_value, indication=False):
        nonlocal value, characteristic, indicated
        indic_sync.set()
        value = char_value
        characteristic = charac
        indicated = indication

    char.subscribe(notification=True, callback=_indic_cb)
    assert not indic_sync.wait(timeout=1.0)


def test_discover(central_mock):
    """Try to read an attribute with an invalid handle."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Discovery services and characteristics
    try:
        target.discover()
        print(target)
        print(target.db)
        assert target.get_service(UUID(0x1800)) is not None
        assert target.get_service(UUID(0x180f)) is not None
        assert target.get_service(UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"))
        assert target.get_characteristic(UUID(0x1800), UUID(0x2a00)) is not None
        assert target.get_characteristic(UUID(0x180f), UUID(0x2a19)) is not None
        assert target.get_characteristic(UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
                                         UUID("6d02b601-1b51-4ef9-b753-1399e05debfd")) is not None
        assert target.get_characteristic(UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
                                         UUID("6d02b602-1b51-4ef9-b753-1399e05debfd")) is not None
    except GattTimeoutException:
        assert False

def test_discover_with_values(central_mock):
    """Discover the remote device GATT attributes and read characteristic's
    values whenever it's possible."""
    # Connect to emulate device
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0

    # Discovery services and characteristics
    try:
        target.discover(include_values=True)
        char1 = target.get_characteristic(UUID("1800"), UUID("2a00"))
        char2 = target.get_characteristic(UUID("180f"), UUID("2a19"))
        assert char1 is not None
        assert char2 is not None
        assert Attribute.value.fget(char1.value_attr) == b'EmulatedDevice'
        assert Attribute.value.fget(char2.value_attr) == b'\x00\x00'
    except GattTimeoutException:
        assert False

