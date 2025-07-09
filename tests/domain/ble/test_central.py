"""Bluetooth Low Energy Central connector testing
"""
import pytest

from whad.ble.mock import CentralMock, EmulatedDevice
from whad.ble import BDAddress, Central
from whad.ble.profile.attribute import UUID
from whad.ble.profile.device import PeripheralDevice
from whad.ble.stack.att.exceptions import InvalidHandleValueError
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
    with pytest.raises(InvalidHandleValueError):
        value = target.read(100)
        assert value == None

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
