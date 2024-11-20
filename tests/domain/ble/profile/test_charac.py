"""Test WHAD BLE GATT characteristic model.
"""

import pytest
from whad.ble.profile import Characteristic, UUID, ReportReferenceDescriptor, PrimaryService

def test_charac_simple_new():
    """Test characteristic instanciation without descriptors.
    """
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                            permissions=["read", "write"], notify=False, indicate=False,
                            Security=None)
    assert(charac.name == "TestCharac")
    assert(charac.uuid == UUID(0x1234))
    assert(charac.value == b"foobar")
    assert(charac.permissions == ["read", "write"])
    assert(charac.must_notify == False)
    assert(charac.must_indicate == False)
    assert(charac.security == [])

def test_charac_desc_new():
    """Test characteristic instanciation with descriptors
    """
    dummy_desc = ReportReferenceDescriptor()
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                            permissions=["read", "write"], notify=False, indicate=False,
                            Security=None, dummy_desc=dummy_desc)
    desc_list = list(charac.descriptors())
    assert(dummy_desc in desc_list)
    assert(desc_list[0] == dummy_desc)
    

def test_charac_required_handles():
    """Test if characteristic correctly computes the required handles.
    """
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                            permissions=["read", "write"], notify=False, indicate=False,
                            Security=None)
    assert(charac.get_required_handles() == 2)

    charac_ = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                            permissions=["read", "write"], notify=False, indicate=True,
                            Security=None)
    assert(charac_.get_required_handles() == 3)

def test_charac_description():
    """Test characteristic description.
    """
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        Security=None, description="Foobar")
    assert(charac.description == "Foobar")

def test_charac_service_attach():
    """Test characteristic service setter.
    """
    service = PrimaryService(uuid=UUID(0x1800))
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        Security=None)
    charac.attach(service)
    assert(charac.service == service)
    assert(charac.service.uuid == service.uuid)

def test_charac_handles():
    """Test characteristic handle manipulation.
    """
    charac = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        Security=None)
    assert(charac.handle == 0)
    charac.handle = 1
    assert(charac.handle == 1)
    assert(charac.end_handle == 2)
