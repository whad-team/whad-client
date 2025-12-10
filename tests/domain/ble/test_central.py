"""Bluetooth Low Energy Central connector testing
"""
import pytest
from typing import Optional
from threading import Event

from whad.ble.mock import CentralMock, EmulatedDevice
from whad.ble import BDAddress, Central
from whad.ble.profile import Characteristic
from whad.ble.profile.attribute import UUID
from whad.ble.profile.device import PeripheralDevice
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

