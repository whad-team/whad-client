"""Unit tests for WHAD's mock device class MockDevice
"""
import pytest

from packaging.version import InvalidVersion

from whad.device.mock.base import MockDevice
from whad.hub.discovery import DeviceType, Domain, Capability
from whad.hub.ble import Commands

@pytest.fixture
def default_capabilities():
    return {
        Domain.BtLE : (
            (Capability.Sniff | Capability.Inject | Capability.SimulateRole),
            [
                Commands.ConnectTo,
                Commands.ScanMode,
                Commands.SendPDU,
                Commands.AdvMode,
                Commands.CentralMode,
                Commands.PeripheralMode,
                Commands.SetAdvData,
                Commands.SetBdAddress,
                Commands.Disconnect,
                Commands.SniffConnReq
            ]
        )
    }

@pytest.fixture
def capabilities_no_commands():
    return {
        Domain.BtLE : (
            (Capability.Sniff | Capability.Inject | Capability.SimulateRole)
        )
    }

@pytest.fixture
def capabilities_wrong_domain():
    return {
        "oops" : (
            (Capability.Sniff | Capability.Inject | Capability.SimulateRole),
            [
                Commands.ConnectTo,
                Commands.ScanMode,
                Commands.SendPDU,
                Commands.AdvMode,
                Commands.CentralMode,
                Commands.PeripheralMode,
                Commands.SetAdvData,
                Commands.SetBdAddress,
                Commands.Disconnect,
                Commands.SniffConnReq
            ]
        )
    }

def test_mock_device_creation(default_capabilities):
    """Create a mock device with basic parameters.
    """
    mock = MockDevice("whad-team", "https://whad.io", proto_minver=2,
                      version="1.3.7", dev_type=DeviceType.VirtualDevice,
                      dev_id=b"TestMockDevice01", capabilities=default_capabilities,
                      max_speed=9600, index=0)
    mock.discover()
    assert isinstance(mock, MockDevice)
    assert mock.info.fw_author == "whad-team"
    assert mock.info.fw_url == "https://whad.io"
    assert Domain.BtLE in mock.info.domains
    assert mock.info.version_str == "1.3.7"
    assert mock.info.max_speed == 9600
    assert mock.info.device_id == "TestMockDevice01"

def test_mock_device_bad_version(default_capabilities):
    """Try to create a mock device with bad version string.
    """
    with pytest.raises(InvalidVersion):
        mock = MockDevice("whad-team", "https://whad.io", proto_minver=2,
                        version="trololo", dev_type=DeviceType.VirtualDevice,
                        dev_id=b"TestMockDevice02", capabilities=default_capabilities,
                        index=0)
        mock.discover()

def test_mock_device_wrong_domain(capabilities_wrong_domain):
    """Try to create a mock device with bad domain string.
    """
    with pytest.raises(TypeError):
        mock = MockDevice("whad-team", "https://whad.io", proto_minver=2,
                      version="trololo", dev_type=DeviceType.VirtualDevice,
                      dev_id=b"TestMockDevice01", capabilities=capabilities_wrong_domain,
                      index=0)
        mock.discover()

def test_mock_device_no_commands(capabilities_no_commands):
    """Try to create a mock device with bad version string.
    """
    with pytest.raises(TypeError):
        mock = MockDevice("whad-team", "https://whad.io", proto_minver=2,
                        version="a.12.0", dev_type=DeviceType.VirtualDevice,
                        dev_id=b"TestMockDevice01", capabilities=capabilities_no_commands,
                        index=0)
        mock.discover()
