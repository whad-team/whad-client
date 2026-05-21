"""Bluetooth Low Energy parameters configuration testing
"""

import pytest
from whad.ble import BLE, PHY
from whad.ble.mock import BasicMock
from whad.hub.exceptions import UnsupportedVersionException

@pytest.fixture
def adapter_mock():
    """BLE adapter mock"""
    return BLE(BasicMock())

@pytest.fixture
def adapter_mock_v1():
    """BLE adapter mock"""
    return BLE(BasicMock(proto_version=2))

def test_set_phy_v1_v2(adapter_mock_v1):
    """Test PHY configuration."""
    with pytest.raises(UnsupportedVersionException):
        adapter_mock_v1.set_phy(PHY.LE_2M, PHY.LE_2M)

def test_set_tx_power_level_v1_v2(adapter_mock_v1):
    """Test TX power configuration."""
    with pytest.raises(UnsupportedVersionException):
        adapter_mock_v1.set_tx_power(-4)

def test_set_phy_v3(adapter_mock):
    """Test PHY configuration."""
    assert adapter_mock.set_phy(PHY.LE_2M, PHY.LE_2M)
    assert adapter_mock.device.rx_phy == PHY.LE_2M
    assert adapter_mock.device.tx_phy == PHY.LE_2M

def test_set_tx_power_level_v3(adapter_mock):
    """Test TX power configuration."""
    assert adapter_mock.set_tx_power(-4)
    assert adapter_mock.device.tx_power_level == -4
