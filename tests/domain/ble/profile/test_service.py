"""Test WHAD BLE GATT Service models.
"""

from whad.ble.profile.service import Service, PrimaryService, SecondaryService, IncludeService
from whad.ble.profile.characteristic import Characteristic, UUID, CharacteristicUserDescriptionDescriptor


def test_service_simple_new():
    """Create a simple BLE GATT service model
    """
    service = Service(uuid=UUID(0x1234), type_uuid=UUID(0x4567))
    assert(service.uuid == UUID(0x1234))
    assert(service.type_uuid == UUID(0x4567))
    assert(service.handle == 0)
    assert(len(list(service.characteristics())) == 0)

def test_service_charac():
    """Create a BLE GATT service model with characteristic.
    """
    dummy_char = Characteristic(uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        security=None)
    service = PrimaryService(uuid=UUID(0x1234), dummy_char=dummy_char)
    assert(len(list(service.characteristics())) == 1)
    assert(service.get_characteristic(UUID(0x1234)) is not None)
    assert(hasattr(service, "dummy_char"))

def test_service_handle_update():
    """Test service handle update
    """
    service = Service(uuid=UUID(0x1234), type_uuid=UUID(0x4567))
    service.handle = 1
    assert(service.handle == 1)

def test_service_include():
    """Create a BLE GATT service with an included service
    """
    inc_service = SecondaryService(UUID(0x5678))
    service = PrimaryService(uuid=UUID(0x1234), inc_service=inc_service)
    assert(len(list(service.included_services())) == 1)
    assert(list(service.included_services())[0].service_uuid == inc_service.uuid)

def test_service_char_add():
    """Create service and add characteristic
    """
    dummy_char = Characteristic(uuid=UUID(0x1234), value=b"foobar",
                        permissions=["read", "write"], notify=False, indicate=False,
                        security=None, description="foo")
    dummy_char.handle = 7
    service = PrimaryService(uuid=UUID(0x1234))
    service.add_characteristic(dummy_char)
    assert service.get_characteristic(UUID(0x1234)) is not None
    assert(service.end_handle == 9)

def test_service_include_add():
    """Create service and add secondary service.
    """
    inc_service = IncludeService(uuid=UUID(0x5678), handle=10)
    service = PrimaryService(uuid=UUID(0x1234))
    service.add_included_service(inc_service)
    assert(len(list(service.included_services())) == 1)
    assert(list(service.included_services())[0].service_uuid == UUID(0x5678))
    assert(service.end_handle == 10)

