"""Enhanced ShockBurst scanning features unit tests.
"""
from whad.esb.stack.llm.constants import ESBRole
from whad.esb.esbaddr import ESBAddress
from whad.esb.scanning import CommunicatingDevice, CommunicatingDevicesDB


def test_device_creation():
    """Test CommunicatingDevice creation"""
    address = ESBAddress("00:11:22:33:44")
    device = CommunicatingDevice(-40, str(address), ESBRole.PTX, None, 11)
    assert device.role == ESBRole.PTX
    assert 11 in device.channels
    assert device.address == str(address)
    assert device.rssi == -40


def test_device_update():
    """Test modifying CommunicatingDevice parameters"""
    address = ESBAddress("00:11:22:33:44")
    device = CommunicatingDevice(-40, str(address), ESBRole.PTX, None, 11)
    device.update_channel(26)
    assert 26 in device.channels
    device.update_rssi(-1)
    assert device.rssi == -1
    device.set_applicative_layer('test_app_layer')
    assert 'test_app_layer' in repr(device)


def test_device_repr():
    """Test CommunicatingDevice representation"""
    address = ESBAddress("00:11:22:33:44")
    device = CommunicatingDevice(-40, str(address), ESBRole.PTX, 'test_app_layer', 11)
    device_repr = repr(device)
    assert device_repr == "[ -40 dBm] [PTX] 00:11:22:33:44 channels=[11] / last_channel=  11 test_app_layer"
    address = ESBAddress("55:44:33:22:11")
    device = CommunicatingDevice(30, str(address), ESBRole.PRX, 'test_app_layer', 11)
    device.update_channel(26)
    device_repr = repr(device)
    assert device_repr == "[  30 dBm] [PRX] 55:44:33:22:11 channels=[11, 26] / last_channel=  26 test_app_layer"


def test_device_db_creation():
    """Test CommunicatingDevicesDB creation"""
    db = CommunicatingDevicesDB()
    assert db.find_device("00:11:22:33:44", ESBRole.PTX) is None


def test_device_db_register():
    """Test CommunicatingDevicesDB register procedure"""
    db = CommunicatingDevicesDB()
    address = ESBAddress("00:11:22:33:44")
    device = CommunicatingDevice(-40, str(address), ESBRole.PTX, 'test_app_layer', 11)
    db.register_device(device)
    found_device = db.find_device(str(address), ESBRole.PTX)
    assert found_device is not None
    assert found_device == device


def test_device_db_device_update():
    """Test CommunicatingDevicesDB device update sub-routine."""
    db = CommunicatingDevicesDB()
    address = ESBAddress("00:11:22:33:44")
    device = CommunicatingDevice(-40, str(address), ESBRole.PTX, None, 11)
    db.update_device(device, -50, 6, 'dummy_app_layer')
    assert device.rssi == -50
    assert 6 in device.channels
    assert 'dummy_app_layer' in repr(device)
