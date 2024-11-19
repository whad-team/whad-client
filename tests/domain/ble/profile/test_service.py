"""Test WHAD BLE GATT Service models.
"""

from whad.ble.profile import ServiceModel, SecondaryService, Characteristic, UUID


def test_service_simple_new():
    """Create a simple BLE GATT service model
    """
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234))
    assert(service.name == "DummyService")
    assert(service.uuid == UUID(0x1234))
    assert(service.handle == 0)
    assert(len(list(service.characteristics())) == 0)

def test_service_charac():
    """Create a BLE GATT service model with characteristic.
    """
    dummy_char = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        Security=None, description="Foobar")
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234),
                           dummy_char=dummy_char)
    assert(len(list(service.characteristics())) == 1)
    assert(list(service.characteristics())[0] == dummy_char)
    assert(hasattr(service, "dummy_char"))

def test_service_handle_update():
    """Test service handle update
    """
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234))
    service.handle = 1
    assert(service.handle == 1)

def test_service_include():
    """Create a BLE GATT service with an included service
    """
    inc_service = SecondaryService(uuid=UUID(0x5678))
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234),
                        inc_service=inc_service)
    assert(len(list(service.included_services())) == 1)
    assert(list(service.included_services())[0] == inc_service)

def test_service_char_add():
    """Create service and add characteristic
    """
    dummy_char = Characteristic(name="TestCharac", uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        Security=None, description="Foobar")
    dummy_char.handle = 7
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234))
    service.add_characteristic(dummy_char)
    assert(dummy_char in list(service.characteristics()))
    assert(service.end == 8)

def test_service_include_add():
    """Create service and add secondary service.
    """
    inc_service = SecondaryService(uuid=UUID(0x5678), start_handle=10, end_handle=10)
    service = ServiceModel(name="DummyService", uuid=UUID(0x1234))
    service.add_included_service(inc_service)
    assert(inc_service in list(service.included_services()))
    assert(service.end == 10)



    