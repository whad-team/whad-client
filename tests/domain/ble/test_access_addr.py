"""Test access address
"""
import pytest
from whad.ble.sniffing import AccessAddress, InvalidAccessAddressException

def test_creation():
    """Test creating an AccessAddress object
    """
    aa = AccessAddress(0x8E89BED6, 5678, -20)
    assert int(aa) == 0x8E89BED6
    assert aa.last_timestamp == 5678
    assert aa.last_rssi == -20

def test_update():
    """Test AccessAddress object modification
    """
    aa = AccessAddress(0x8E89BED6, 5678, -20)
    aa.update(timestamp=9999, rssi=-60)
    assert aa.last_timestamp == 9999
    assert aa.last_rssi == -60

def test_bad_aa():
    """Test bad access address raises an exception
    """
    with pytest.raises(InvalidAccessAddressException):
        aa = AccessAddress(0x123456)

def test_eq():
    """Test int comparison
    """
    aa = AccessAddress(0x8E89BED6)
    bb = AccessAddress(0x8E89BED6)
    assert aa == bb

def test_count():
    """Test access address counter
    """
    aa = AccessAddress(0x8E89BED6)
    aa.update()
    aa.update()
    assert aa.count == 3
