"""Test WHAD BLE GATT generic profile.
"""
import pytest
import json
from whad.ble.profile import GenericProfile, UUID, read, write
from whad.ble.profile.service import PrimaryService
from whad.ble.profile.characteristic import CharacteristicValue, Characteristic

class BasicProfile(GenericProfile):
    """A custom profile
    """

    foo = PrimaryService(
        UUID(0x1234),
        bar=Characteristic(
            uuid=UUID(0x5678),
            permissions=["read", "write"],
            value=b"DummyValue",
            notify=False,
            indicate=False
        )
    )

@pytest.fixture
def basic_profile():
    obj = BasicProfile()
    return obj

@pytest.fixture
def complex_profile():
    class ComplexProfile(GenericProfile):
        """A complex GATT profile
        """
        device_info = PrimaryService(
            uuid=UUID(0x1800),
            device_name=Characteristic(
                uuid=UUID(0x2a00),
                permissions=["read", "write", "notify"],
                notify=True,
                description="Device name",
                value=b"DummyDevice"
            )
        )

        vendor = PrimaryService(
            uuid=UUID("fc0d6e0a-bfa8-4cf7-bd37-215d1f96efab"),
            vendor_char0 = Characteristic(
                uuid=UUID("280c807b-cd3c-4b5e-b8f8-29920b00b673"),
                permissions=["read", "notify"],
                notify=True,
                value=b"0"
            ),
            vendor_char1 = Characteristic(
                uuid=UUID("c15b1f6e-d215-4683-99b6-9bb921f30e10"),
                permissions=["write"],
                value=b""
            )
        )

        @read(device_info.device_name)
        def on_device_name_read(self, *args):
            return b"Foobar"

        @write(vendor.vendor_char1)
        def on_vendor_write(self, *args):
            pass


    return ComplexProfile()

def test_basic_profile(basic_profile):
    """Test a BLE GATT simple profile
    """
    assert(hasattr(basic_profile, "foo"))
    assert(hasattr(basic_profile.foo, "bar"))
    assert(basic_profile.foo.handle == 1)
    assert(basic_profile.foo.bar.handle == 2)
    assert(basic_profile.foo.bar.value_handle == 3)

def test_profile_att_charac_by_uuid(basic_profile: GenericProfile):
    """Test accessing characteristic by UUID
    """
    bar = basic_profile.get_characteristic_by_uuid(UUID(0x5678))
    assert(bar is not None)
    assert(bar.handle == 2)
    assert(bar.value == b"DummyValue")

def test_profile_att_service_by_uuid(basic_profile: GenericProfile):
    """Test accessing service by UUID
    """
    foo = basic_profile.get_service_by_uuid(UUID(0x1234))
    assert(isinstance(foo, PrimaryService))
    assert(foo.handle == 1)
    assert(len(list(foo.characteristics())) == 1)

def test_profile_find_obj_by_handle(basic_profile: GenericProfile):
    """Test getting an ATT attribute by its handle
    """
    # get characteristic value
    char_value = basic_profile.find_object_by_handle(3)
    service = basic_profile.find_object_by_handle(1)
    assert(char_value is not None)
    assert(isinstance(char_value, CharacteristicValue))
    assert(service is not None)
    assert(isinstance(service, PrimaryService))

def test_profile_find_objs_by_range(basic_profile: GenericProfile):
    """Test getting multiple ATT attributes by range
    """
    # get attributes
    attrs = basic_profile.find_objects_by_range(1, 2)
    assert(basic_profile.foo in attrs)
    assert(basic_profile.foo.bar in attrs)
    assert(len(attrs) == 2)

def test_profile_find_charac_by_handle(basic_profile: GenericProfile):
    """Test finding a characteristic from its value handle
    """
    charac = basic_profile.find_characteristic_by_value_handle(3)
    assert(charac is not None)
    assert(charac.handle == 2)
    assert(charac.uuid == UUID(0x5678))

def test_profile_find_charac_end_handle(basic_profile: GenericProfile, complex_profile:GenericProfile):
    """Test characteristic end handle from charac handle
    """
    print(complex_profile.db)
    # Test for basic profile
    end_handle = basic_profile.find_characteristic_end_handle(2)
    assert(end_handle == 3)

    # Test for complex profile
    end_handle = complex_profile.find_characteristic_end_handle(10)
    assert(end_handle == 11)

def test_profile_find_service_by_charac_handle(complex_profile:GenericProfile):
    """Test finding service from one of its characteristic handle.
    """
    service = complex_profile.find_service_by_characteristic_handle(10)
    assert(service.uuid == UUID("fc0d6e0a-bfa8-4cf7-bd37-215d1f96efab"))

def test_profile_hooks(complex_profile:GenericProfile):
    """Test characteristics hooking feature
    """
    hook = complex_profile.find_hook(complex_profile.device_info, complex_profile.device_info.device_name,
                                     "read")
    # Check we found our hook
    assert(hook is not None)
    # Ensure we retrieve the correct function
    assert(hook == complex_profile.on_device_name_read)
    hook_ = complex_profile.find_hook(complex_profile.vendor, complex_profile.vendor.vendor_char0,
                                     "write")
    assert(hook_ is None)

def test_profile_add_remove_service(basic_profile: GenericProfile):
    """Test adding and removing a service
    """
    service = PrimaryService(uuid=UUID(0xabcd), handle=0)
    basic_profile.add_service(service)
    assert(basic_profile.get_service_by_uuid(UUID(0xabcd)) == service)
    basic_profile.remove_service(service)
    assert(basic_profile.get_service_by_uuid(UUID(0xabcd)) is None)

def test_profile_json_export(basic_profile: GenericProfile):
    """Test JSON export
    """
    expected_profile = json.loads("""{
        "services": [
            {
                "uuid": "1234",
                "type_uuid": "2800",
                "start_handle": 1,
                "end_handle": 3,
                "characteristics": [
                    {
                        "handle": 2,
                        "uuid": "2803",
                        "properties": 10,
                        "security": 0,
                        "value": {
                            "data": "44756d6d7956616c7565",
                            "handle": 3,
                            "uuid": "5678"
                        },
                        "descriptors": []
                    }
                ]
            }
        ]
    }""")
    json_profile = json.loads(basic_profile.export_json())
    assert(json_profile == expected_profile)

def test_profile_json_import():
    """Test GATT profile JSON import
    """
    profile = """{
        "services": [
            {
                "uuid": "1234",
                "type_uuid": "2800",
                "start_handle": 1,
                "end_handle": 3,
                "characteristics": [
                    {
                        "handle": 2,
                        "uuid": "2803",
                        "properties": 10,
                        "security": 0,
                        "value": {
                            "handle": 3,
                            "uuid": "5678"
                        },
                        "descriptors": []
                    }
                ]
            }
        ]
    }"""
    custom_profile = GenericProfile(from_json=profile)
    assert(custom_profile.get_service_by_uuid(UUID(0x1234)) is not None)
    charac: Characteristic = custom_profile.get_characteristic_by_uuid(UUID(0x5678))
    assert(charac is not None)
    assert(charac.handle == 2)
    assert(charac.readable() == True)
    assert(custom_profile.find_service_by_characteristic_handle(charac.handle).uuid == UUID(0x1234))
