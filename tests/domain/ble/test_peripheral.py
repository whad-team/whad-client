"""Bluetooth Low Energy Peripheral connector unit tests.
"""
import pytest
from typing import Type

from scapy.layers.bluetooth import (
    ATT_Error_Response, ATT_Find_By_Type_Value_Response, ATT_Handle_Value_Indication, ATT_Handle_Value_Notification,
    ATT_Read_By_Type_Response, ATT_Hdr
)

from whad.ble.mock.peripheral import PeripheralMock
from whad.ble import BDAddress, Peripheral

from whad.ble.profile import GenericProfile
from whad.ble.profile.service import PrimaryService
from whad.ble.profile.characteristic import Characteristic
from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvShortenedLocalName
from whad.ble.profile.attribute import UUID
from whad.ble.stack.att.constants import BleAttErrorCode, BleAttOpcode
from whad.ble.stack.gatt.attrlist import GattAttributeDataList, GattAttributeValueItem
from whad.hub.ble import connect

@pytest.fixture
def profile() -> Type[GenericProfile]:
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

        prim2 = PrimaryService(
            uuid=UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"),
            tx=Characteristic(
                uuid=UUID("6d02b601-1b51-4ef9-b753-1399e05debfd"),
                permissions=['write_without_resp'],
                value=b"\x00\x00\x00\x00",
            ),
            rx=Characteristic(
                uuid=UUID("6d02b602-1b51-4ef9-b753-1399e05debfd"),
                permissions=['indicate'],
                indicate=True,
                value=b"\x00\x00\x00\x00",
            )
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

def test_read_by_type(profile, connected_peripheral):
    """ Test ReadByType request. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Retrieve the target characteristic definition
    char_def = profile().find_object_by_handle(2).payload()

    # Send a valid ReadByType request
    result = mock.read_by_type(1, 3, UUID(0x2803))
    assert isinstance(result, ATT_Read_By_Type_Response)
    assert result.len == 7
    assert len(result.handles) == 1
    assert result.handles[0].handle == 2
    assert result.handles[0].value == char_def

def test_read_by_type_invalid_start_handle(connected_peripheral):
    """ Test ReadByType request with invalid start handle (0)."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a ReadByType request wth invalid start handle (0)
    result = mock.read_by_type(0, 3, UUID(0x2803))
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_BY_TYPE_REQUEST
    assert result.handle == 0
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE

def test_read_by_type_higher_start_handle(connected_peripheral):
    """ Test ReadByType request with invalid end handle."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a ReadByType request with start handle greater than end handle
    result = mock.read_by_type(3, 0, UUID(0x2803))
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_BY_TYPE_REQUEST
    assert result.handle == 3
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE

def test_read(connected_peripheral):
    """ Test Read request. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a valid Read request
    result = mock.read_attr(3)
    assert result == b"EmulatedDevice"

def test_read_invalid_handle(connected_peripheral):
    """ Test Read request with invalid handle. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a Read request with an invalid handle (0)
    result = mock.read_attr(0)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_read_not_permitted(connected_peripheral):
    """ Test Read request on attribute with no read permission. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a Read request on an attribute without read permission
    result = mock.read_attr(10)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_REQUEST
    assert result.ecode == BleAttErrorCode.READ_NOT_PERMITTED
    assert result.handle == 10

def test_read_blob(connected_peripheral):
    """ Test ReadBlob request. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a valid ReadBlob request
    result = mock.read_blob(3, 8)
    assert result == b"Device"

def test_read_blob_invalid_handle(connected_peripheral):
    """ Test ReadBlob request with invalid handle. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a ReadBlob request with invalid handle (0)
    result = mock.read_blob(0, 8)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_BLOB_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_read_blob_invalid_offset(connected_peripheral):
    """ Test ReadBlob request with invalid offset. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a ReadBlob request with invalid offset (bigger than attribute's value)
    result = mock.read_blob(3, 40)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_BLOB_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_OFFSET
    assert result.handle == 3

def test_read_blob_not_permitted(connected_peripheral):
    """ Test ReadBlob request with invalid handle. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a ReadBlob request on an attribute that is not readable
    result = mock.read_blob(10, 0)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.READ_BLOB_REQUEST
    assert result.ecode == BleAttErrorCode.READ_NOT_PERMITTED
    assert result.handle == 10

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

def test_find_by_type_value(connected_peripheral):
    """Test a FindByTypeValue procedure with a known Service UUID."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_by_type_value(1, 3, UUID(0x2800), UUID(0x1800).packed)
    assert isinstance(result,ATT_Find_By_Type_Value_Response)
    assert len(result.handles) == 1
    assert result.handles[0].handle == 1
    assert result.handles[0].value == 3

def test_find_by_type_value_invalid_start_handle(connected_peripheral):
    """ Test sending a FindByTypeValue procedure with an invalid start handle (0). """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_by_type_value(0, 3, UUID(0x2800), UUID(0x1800).packed)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_find_by_type_value_higher_start_handle(connected_peripheral):
    """ Test sending a FindByTypeValue procedure with an invalid start handle (greater than end handle). """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_by_type_value(4, 3, UUID(0x2800), UUID(0x1800).packed)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 4

def test_find_by_type_value_no_result(connected_peripheral):
    """ Test sending a FindByTypeValue procedure with an invalid start handle (greater than end handle). """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a FindInformation request with valid start and end handle
    result = mock.find_by_type_value(2, 4, UUID(0x2800), UUID(0x1800).packed)
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.FIND_BY_TYPE_VALUE_REQUEST
    assert result.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND
    assert result.handle == 2

def test_write(connected_peripheral):
    """ Test Write request. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a valid Write request
    result = mock.write_attr(3, b"Foobar")
    assert result
    # Read profile characteristic value
    charval = connected_peripheral.profile.find_object_by_handle(3)
    assert charval.value == b"Foobar"

def test_write_invalid_handle(connected_peripheral):
    """Test write procedure with handle 0 and check we receive an INVALID_HANDLE error"""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a Write request with invalide handle (0)
    result = mock.write_attr(0, b"Foobar")
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.WRITE_REQUEST
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_write_unknown_handle(connected_peripheral):
    """Test write procedure with handle 120 and check we receive an ATTRIBUTE_NOT_FOUND error"""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a Write request with an unknown handle
    result = mock.write_attr(120, b"Foobar")
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.WRITE_REQUEST
    assert result.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND
    assert result.handle == 120

def test_write_cmd(connected_peripheral):
    """ Test WriteCommand request. """
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a valid WriteCommand request
    mock.write_cmd(3, b"Foobar")
    # Read profile characteristic value
    charval = connected_peripheral.profile.find_object_by_handle(3)
    assert charval.value == b"Foobar"

def test_write_cmd_invalid_handle(connected_peripheral):
    """Test WriteCommand procedure with handle 0 and check we receive an INVALID_HANDLE error"""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a WriteCommand request with handle=0
    result = mock.write_cmd(0, b"Foobar")
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.WRITE_COMMAND
    assert result.ecode == BleAttErrorCode.INVALID_HANDLE
    assert result.handle == 0

def test_write_cmd_unknown_handle(connected_peripheral):
    """Test WriteCommand procedure with handle 120 and check we receive an ATTRIBUTE_NOT_FOUND error"""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # Send a valid Write request
    result = mock.write_cmd(120, b"Foobar")
    assert isinstance(result, ATT_Error_Response)
    assert result.request == BleAttOpcode.WRITE_COMMAND
    assert result.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND
    assert result.handle == 120

def test_notification_sub(connected_peripheral):
    """Test notification subscription.
    1. central subscribes to a characteristic with notify permission
    2. peripheral updates this characteristic value and send notification to central
    3. check central got a notification
    """
    # Retrieve mock from current peripheral
    mock: PeripheralMock = connected_peripheral.device

    # Start our dedicated notification check procedure from central
    charac = connected_peripheral.profile.find_object_by_handle(5)
    result = mock.sub_notif(7, charac)

    assert isinstance(result, ATT_Handle_Value_Notification)
    assert result.value == b"FOOBAR"


def test_indication_sub(connected_peripheral):
    """Test indication subscription.
    1. Central subscribes to a characteristic with indicate permission
    2. peripheral updates this characteristic value and send indication to central
    3. central must answers with a confirmation
    """
    # Retrieve mock from current peripheral
    mock: PeripheralMock = connected_peripheral.device

    # Start our dedicated indication check procedure from central
    charac = connected_peripheral.profile.find_object_by_handle(11)
    result = mock.sub_ind(13, charac)

    assert isinstance(result, ATT_Handle_Value_Indication)

def test_remote_profile_discovery(connected_peripheral):
    """Test remote GATT profile discovery."""
    # Retrieve mock from current peripheral
    mock:PeripheralMock = connected_peripheral.device

    # First, discover exposed services.
    services = {}
    services_chars = {}

    attr_id = 1
    while attr_id < 0xffff:
        # Discover primary services by reading attributes with group type 0x2800:
        response = mock.read_by_group_type(UUID(0x2800), attr_id, 0xffff)
        if isinstance(response, ATT_Error_Response) and response.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND:
            # Service discovery done
            break
        elif isinstance(response, GattAttributeDataList):
            for item in response:
                services[item.handle] = (UUID(item.value), item.end)
                attr_id = item.end+1

    # Check primary services
    assert len(services) == 3
    assert services[1] == (UUID(0x1800), 3)
    assert services[4] == (UUID(0x180f), 7)
    assert services[8] == (UUID("6d02b600-1b51-4ef9-b753-1399e05debfd"), 13)

    # Discovery characteristics for each service
    for serv_handle, serv_params  in services.items():
        _, end_handle = serv_params

        # Discover characteristics
        services_chars[serv_handle] = []
        attr_id = serv_handle
        while attr_id <= end_handle:
            # Read characteristic attributes
            response = mock.read_by_type(attr_id, end_handle, UUID(0x2803))
            if isinstance(response, ATT_Error_Response) and response.ecode == BleAttErrorCode.ATTRIBUTE_NOT_FOUND:
                # Characs discovered
                break
            elif isinstance(response, ATT_Read_By_Type_Response):
                for item in response.handles:
                    chardef = GattAttributeValueItem.from_bytes(bytes(item))
                    if chardef is not None:
                        services_chars[serv_handle].append((item.handle,item.value))
                        attr_id = chardef.handle + 1
                    else:
                        # Invalid attribute/value item returned by the peripheral !
                        assert False

    # Make sure our characteristics have successfully been discovered
    assert len(services_chars.keys()) == 3
    assert len(services_chars[1]) == 1
    assert 2 in services_chars[1][0]
    assert len(services_chars[4]) == 1
    assert 5 in services_chars[4][0]
    assert len(services_chars[8]) == 2
    assert 9 in services_chars[8][0]

