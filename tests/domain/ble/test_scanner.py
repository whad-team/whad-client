"""Test Bluetooth Low Energy Scanner class.
"""
import pytest

from whad.ble.mock import DeviceScan, EmulatedDevice
from whad.ble import BDAddress, Scanner

@pytest.fixture
def mock_devices():
    """BLE mock devices
    """
    return [
        EmulatedDevice(BDAddress("00:11:22:33:44:55", random=False),
                    adv_data=b"\x02\x01\x06", scan_data=b"\x07\x08foobar"),
    ]

@pytest.fixture
def scan_mock(mock_devices):
    """Create a BLE DeviceScan mock.
    """
    return DeviceScan(devices=mock_devices, sniffing=False, nowait=True)

@pytest.fixture
def sniff_mock(mock_devices):
    """Create a BLE DeviceScan mock.
    """
    return DeviceScan(devices=mock_devices, sniffing=True, nowait=True)

def test_scanner_no_sniffing(scan_mock):
    """Test scanner instantiation with hardware supporting only scanning.
    """
    scanner = Scanner(scan_mock)
    assert scanner.can_scan()
    assert not scanner.can_sniff_advertisements()

def test_scanner_scan_devices(scan_mock):
    """Test scanner scan-based device discovery
    """
    scanner = Scanner(scan_mock)
    scanner.start()
    devices = []
    for device in scanner.discover_devices(timeout=2.0):
        devices.append(device.address)
        break
    assert "00:11:22:33:44:55" in devices

def test_scanner_sniffing(sniff_mock):
    """Test scanner instantiation with hardware only supporting sniffing
    """
    scanner = Scanner(sniff_mock)
    assert not scanner.can_scan()
    assert scanner.can_sniff_advertisements()

def test_scanner_sniff_adv(sniff_mock):
    """Test BLE scanner sniff-based device discovery procedure.
    """
    scanner = Scanner(sniff_mock)
    scanner.start()
    devices = []
    for device in scanner.discover_devices(timeout=2.0):
        devices.append(device.address)
        break
    assert "00:11:22:33:44:55" in devices
