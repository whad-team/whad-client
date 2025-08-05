"""Bluetooth Low Energy Peripheral connector unit tests.
"""
import pytest
from scapy.layers.bluetooth import ATT_Error_Response

from whad.ble.mock.peripheral import PeripheralMock
from whad.ble import BDAddress, Peripheral

from whad.ble.profile import PrimaryService, Characteristic, GenericProfile
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvShortenedLocalName
from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.constants import BleAttErrorCode
from whad.ble.stack.gatt.attrlist import GattAttributeDataList
from whad.hub.ble import connect

@pytest.fixture
def profile() -> GenericProfile:
    """Generate our emulated GATT profile, similar to the one used when testing
    our Central connector.
    """
    class EmulatedProfile(GenericProfile):
        """Emulated GATT profile."""

        prim0 = PrimaryService(
            uuid=UUID(0x1800),
            devname=Characteristic(
                uuid=UUID(0x2a00),
                permissions=['read','write'],
                value=b'EmulatedDevice',
            )
        )

        prim1 = PrimaryService(
            uuid=UUID(0x180f),
            batt_level=Characteristic(
                uuid=UUID(0x2a19),
                permissions = [ 'read', 'notify'],
                notify = True,
                value=bytes([100]),
            ),
        )

    return EmulatedProfile

@pytest.fixture
def periph_mock() -> PeripheralMock:
    """Create a default BLE peripheral mock"""
    return PeripheralMock()

@pytest.fixture
def connected_peripheral(profile) -> Peripheral:
    """Create a BLE peripheral mock and connect a central to it."""
    # Create mock device
    periph_mock = PeripheralMock()

    # Create a peripheral connector
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv, profile=profile())

    # Start advertising
    periph.start()

    # Make our Peripheral mock trigger a Connected event
    periph_mock.make_connection(BDAddress("11:22:33:44:55:66"))

    # Make sure the connection has successfully been processed
    # by our connector
    periph.wait_connection(timeout=1.0)

    return periph

def test_create(periph_mock):
    """Test Peripheral connector creation."""
    periph = Peripheral(periph_mock)

    # Peripheral must implement Peripheral mode and be able
    # to send PDU.
    assert periph.can_be_peripheral()
    assert periph.can_send()

def test_advertising(periph_mock):
    """Test peripheral advertising settings."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    _ = Peripheral(periph_mock, adv_data=periph_adv)
    adv_data = AdvDataFieldList.from_bytes(periph_mock.get_adv_data())
    assert adv_data.get(AdvFlagsField) is not None
    assert adv_data.get(AdvShortenedLocalName) is not None
    short_local_name = adv_data.get(AdvShortenedLocalName)
    assert isinstance(short_local_name, AdvShortenedLocalName)
    assert short_local_name.name == b"TestPeriph"

def test_start(periph_mock):
    """Test peripheral mode start."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)
    periph.start()
    assert periph_mock.is_started()

def test_stop(periph_mock):
    """Test peripheral mode stop."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)
    periph.start()
    periph.stop()
    assert periph_mock.is_stopped()

def test_connect(periph_mock):
    """Test peripheral connection."""
    # Create a peripheral connector
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)

    # Start advertising
    periph.start()

    # Make our Peripheral mock trigger a Connected event
    assert periph_mock.make_connection(BDAddress("11:22:33:44:55:66"))

    # Make sure the connection has successfully been processed
    # by our connector
    assert periph.wait_connection(timeout=1.0)

def test_connect_fail(periph_mock):
    """Test failure of a peripheral connection."""
    # Create a peripheral connector
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)

    # Start advertising
    periph.start()

    # Wait for a connection while no connection has been initiated. We expect
    # this method to return False.
    assert not periph.wait_connection(timeout=1.0)

def test_read_by_group_type(connected_peripheral):
    """Test ReadByGroupType request handling."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Emulate a ReadByGroupType procedure started by a connected Central
    # device (Enumerate primary services)
    result = mock.read_by_group_type(UUID(0x2800), 1, 0xffff)
    assert isinstance(result, GattAttributeDataList)
    assert len(result) == 2
    assert result[0].value == UUID(0x1800).packed
    assert result[1].value == UUID(0x180f).packed

def test_read_by_group_type_with_invalid_group(connected_peripheral):
    """Test ReadByGroupType request failure."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device
    # Send a ReadByGroupType request with unknown group UUID
    result = mock.read_by_group_type(UUID(0x2f00), 1, 0xffff)
    assert isinstance(result, ATT_Error_Response)
    assert result.ecode == BleAttErrorCode.UNSUPPORTED_GROUP_TYPE
    assert result.handle == 1

def test_read_by_group_type_with_invalid_handle(connected_peripheral):
    """Test ReadByGroupType request with invalid start handle."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device
    # Send a ReadByGroupType request with invalid start handle
    result = mock.read_by_group_type(UUID(0x2f00), 0, 0xffff)
    assert isinstance(result, ATT_Error_Response)
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_read_by_group_type_with_greater_start_handle(connected_peripheral):
    """Test ReadByGroupType request with invalid start handle."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device
    # Send a ReadByGroupType request with invalid start handle
    result = mock.read_by_group_type(UUID(0x2f00), 12, 10)
    assert isinstance(result, ATT_Error_Response)
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 12

def test_find_information(connected_peripheral):
    """Test a successfull FindInformation request."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_information(1, 3)
    assert isinstance(result, list)
    assert len(result) == 3
    assert (result[0].handle == 1) and (result[0].value == 0x2800) # Primary service 0x1800 with handle 1 and type 0x2800
    assert (result[1].handle == 2) and (result[1].value == 0x2803) # Characteristic 0x2A00 with handle 2 and type 0x2803
    assert (result[2].handle == 3) and (result[2].value == 0x2a00) # Characteristic value for characteristic 0x2A00

def test_find_information_with_invalid_handle(connected_peripheral):
    """Test a FindInformation with an invalid start handle."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_information(0, 3)
    assert isinstance(result, ATT_Error_Response)
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_find_information_with_wrong_start_handle(connected_peripheral):
    """Test a FindInformation procedure with a start handle greater than its end handle."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_information(3, 0)
    assert isinstance(result, ATT_Error_Response)
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 3

