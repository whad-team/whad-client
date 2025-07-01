"""Bluetooth Low Energy Central connector testing
"""
import pytest

from whad.ble.mock import CentralMock, EmulatedDevice
from whad.ble import BDAddress, Central
from whad.ble.profile.device import PeripheralDevice

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

def test_central_create(central_mock):
    """Test Central connector creation.
    """
    # Attach a central connector to our central mock
    central = Central(central_mock)
    assert central.can_be_central()

def test_central_connect_success(central_mock):
    """Initiate a connection to a device (expected to succeed).
    """
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    assert target is not None
    assert target.conn_handle != 0
    assert isinstance(target, PeripheralDevice)

def test_central_send_pdu(central_mock):
    """Connect to a device and send a PDU.
    """
    # Connect to emulate device
    print("Connect to device...")
    central = Central(central_mock)
    target = central.connect("00:11:22:33:44:55")
    print("Connected !")
    assert target is not None
    assert target.conn_handle != 0

    # Send PDU
    target.read(1)
    assert True