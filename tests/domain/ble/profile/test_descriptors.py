"""Test WHAD BLE GATT profile descriptors.
"""
import pytest
from whad.ble.profile import CharacteristicDescriptor

class DummyClass:
    """Dummy class for descriptors.
    """
    pass

@pytest.fixture
def gen_descriptor():
    """Generate a generic descriptor (fixture)
    """

    return CharacteristicDescriptor(DummyClass)
    

def test_charac_desc(gen_descriptor):
    """Test generic descriptor
    """

    assert(gen_descriptor.handle == 0)
    assert(gen_descriptor.bleclass == DummyClass)

def test_charac_desc_update(gen_descriptor):
    """Test generic descriptor update
    """
    gen_descriptor.handle = 42
    assert(gen_descriptor.handle == 42)