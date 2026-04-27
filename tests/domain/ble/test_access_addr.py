"""Test access address
"""
import pytest
from whad.ble.exceptions import InvalidHandleValueException
from whad.ble.sniffing import AccessAddress, InvalidAccessAddressException
from whad.ble.utils.phy import is_access_address_valid

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

def test_aa_less_two_transitions():
    with pytest.raises(InvalidAccessAddressException):
        _ = AccessAddress(0x00aaaaaa)

def test_aa_two_transitions():
    assert is_access_address_valid(0xd81278c2)

def test_aa_seven_ones():
    with pytest.raises(InvalidAccessAddressException):
        _ = AccessAddress(0xd87f78c2)

def test_aa_seven_zeroes():
    with pytest.raises(InvalidAccessAddressException):
        _ = AccessAddress(0xd80008c2)

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
